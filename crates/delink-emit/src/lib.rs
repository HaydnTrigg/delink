//! ET_REL writer. Emits one relocatable ELF object per compilation unit,
//! plus a single `__shared_data.o` that carries the binary's `.rodata` /
//! `.data` / `.bss` bytes referenced by every other `.o` through named
//! section-start globals.
//!
//! Two architectures are supported and they differ in how addends travel:
//!
//! * **AArch64** uses `SHT_RELA`; the addend is stored in the relocation and
//!   the code bytes are copied through untouched.
//! * **ARM (A32)** uses `SHT_REL`; the addend lives in the relocated field, so
//!   every recovered relocation is written back into a private copy of the
//!   section bytes before they are handed to the writer. The relocation
//!   itself then carries addend `0`.

pub mod dwarf_relocs;

use anyhow::{anyhow, Context, Result};
use delink_arch::Arch;
use delink_core::binary::Binary;
use delink_core::cu::CompilationUnit;
use delink_core::symbols::{
    read_all_dyn_relocs, DynReloc, GlobalSymbols, SYM_BSS_START, SYM_DATA_REL_RO_LOCAL_START,
    SYM_DATA_REL_RO_START, SYM_DATA_START, SYM_RODATA_START,
};
use object::write::{
    Comdat, Object, Relocation, SectionId, StandardSection, Symbol, SymbolId, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, Endianness, Object as _, ObjectSection as _, RelocationFlags,
    SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use std::collections::HashMap;
use std::path::Path;

pub struct EmitOptions<'a> {
    pub cu: &'a CompilationUnit,
    pub symbols: &'a GlobalSymbols,
    /// Emit linkage-scope functions as `STB_WEAK` inside `GRP_COMDAT`
    /// section groups so the linker dedupes duplicate mangled names
    /// across CUs (inline / template instantiations). Off by default
    /// because some analysis tools (objdiff) hide COMDAT-grouped weak
    /// symbols from their UI.
    pub comdat: bool,
    /// Emit per-CU DWARF slices (`.debug_info`/`.debug_abbrev`/`.debug_line`)
    /// with reloc synthesis. Off by default: the slices carry forward the
    /// original DWARF which some parsers stumble on post-slice, and many
    /// workflows (objdiff, relink correctness) don't need it.
    pub dwarf: bool,
    /// When true, emit one `.text.<mangled>` section per function
    /// (standard `-ffunction-sections` output). When false, emit a
    /// single `.text` section per `.o` with functions laid out
    /// back-to-back and symbols at their section offsets — the layout
    /// objdiff and similar tools expect.
    pub per_function_sections: bool,
    /// Emit `static` functions as `STB_GLOBAL` rather than `STB_LOCAL`.
    ///
    /// Needed when the compilation-unit boundaries are reconstructed rather
    /// than read from debug info: a function the original source declared
    /// `static` may land in a different object from one of its callers, and a
    /// local definition cannot satisfy a cross-object reference. Names are
    /// already unique (see `disambiguate_names`), so promoting is safe.
    pub promote_locals: bool,
}

#[derive(Debug, Default)]
pub struct EmitStats {
    pub text_bytes: u64,
    pub local_symbols: usize,
    pub undef_symbols: usize,
    pub relocations: usize,
    pub unresolved_calls: usize,
    pub decode_failures: usize,
    pub instructions: usize,
    pub ranges_coalesced: usize,
    /// AArch64: `adrp` sites seen / paired / left unresolved.
    pub adrp_seen: usize,
    pub adrp_paired: usize,
    pub adrp_unresolved: usize,
    /// ARM: PC-relative literal pool sites seen / relocated / unresolved,
    /// plus pool words that fall outside the emitted function.
    pub pool_loads: usize,
    pub pool_relocated: usize,
    pub pool_unresolved: usize,
    pub pool_out_of_range: usize,
    pub dwarf_bytes: u64,
}

impl EmitStats {
    pub fn accumulate(&mut self, other: &EmitStats) {
        self.text_bytes += other.text_bytes;
        self.local_symbols += other.local_symbols;
        self.undef_symbols += other.undef_symbols;
        self.relocations += other.relocations;
        self.unresolved_calls += other.unresolved_calls;
        self.decode_failures += other.decode_failures;
        self.instructions += other.instructions;
        self.adrp_seen += other.adrp_seen;
        self.adrp_paired += other.adrp_paired;
        self.adrp_unresolved += other.adrp_unresolved;
        self.pool_loads += other.pool_loads;
        self.pool_relocated += other.pool_relocated;
        self.pool_unresolved += other.pool_unresolved;
        self.pool_out_of_range += other.pool_out_of_range;
        self.dwarf_bytes += other.dwarf_bytes;
    }
}

/// One relocation ready for the writer, already normalized across the two
/// addend conventions.
struct PreparedReloc {
    /// Offset from the start of the function's byte slice.
    offset: u64,
    r_type: u32,
    target: String,
    /// Addend to hand `object`. Always `0` on ARM, where the value has
    /// already been encoded into `bytes`.
    addend: i64,
}

struct FunctionCode {
    /// Possibly-patched copy of the function's bytes.
    bytes: Vec<u8>,
    relocs: Vec<PreparedReloc>,
    stats: EmitStats,
}

fn object_architecture(arch: Arch) -> Architecture {
    match arch {
        Arch::Aarch64 => Architecture::Aarch64,
        Arch::Arm => Architecture::Arm,
    }
}

/// Recover relocations for one function and produce the exact bytes to emit.
fn prepare_function(
    arch: Arch,
    fn_addr: u64,
    fn_size: u64,
    text_base: u64,
    text_data: &[u8],
    globals: &GlobalSymbols,
) -> Result<FunctionCode> {
    let start = (fn_addr - text_base) as usize;
    let end = start + fn_size as usize;
    let mut bytes = text_data[start..end].to_vec();
    let mut relocs = Vec::new();
    let mut stats = EmitStats::default();

    match arch {
        Arch::Aarch64 => {
            let rec = delink_aarch64::recover(&bytes, fn_addr, globals)?;
            for r in &rec.relocs {
                relocs.push(PreparedReloc {
                    offset: r.offset,
                    r_type: aarch64_reloc_type(r.kind),
                    target: r.target.clone(),
                    addend: r.addend,
                });
            }
            stats.instructions = rec.diag.instructions;
            stats.decode_failures = rec.diag.decode_failures;
            stats.unresolved_calls = rec.diag.bl_unresolved;
            stats.adrp_seen = rec.diag.adrp_seen;
            stats.adrp_paired = rec.diag.adrp_paired;
            stats.adrp_unresolved = rec.diag.adrp_unresolved;
        }
        Arch::Arm => {
            let image = delink_arm::recover::CodeImage {
                base: text_base,
                bytes: text_data,
            };
            let rec = delink_arm::recover(fn_addr, fn_size, &image, globals)?;
            for r in &rec.relocs {
                // SHT_REL: the addend has to go into the field itself.
                delink_arm::apply_addend(r.kind, &mut bytes, r.offset as usize, r.addend)?;
                relocs.push(PreparedReloc {
                    offset: r.offset,
                    r_type: delink_arm::elf_reloc_type(r.kind),
                    target: r.target.clone(),
                    addend: 0,
                });
            }
            stats.instructions = rec.diag.instructions;
            stats.decode_failures = rec.diag.decode_failures;
            stats.unresolved_calls = rec.diag.bl_unresolved;
            stats.pool_loads = rec.diag.pool_loads;
            stats.pool_relocated = rec.diag.pool_relocated;
            stats.pool_unresolved = rec.diag.pool_unresolved;
            stats.pool_out_of_range = rec.diag.pool_out_of_range;
        }
    }

    Ok(FunctionCode {
        bytes,
        relocs,
        stats,
    })
}

pub fn emit_cu(binary: &Binary<'_>, opts: EmitOptions<'_>, out_path: &Path) -> Result<EmitStats> {
    let cu = opts.cu;
    let globals = opts.symbols;
    let arch = binary.arch;

    if cu.functions.is_empty() {
        return Err(anyhow!(
            "CU '{}' has no functions with concrete addresses",
            cu.name
        ));
    }

    let text_section = binary
        .elf
        .section_by_name(".text")
        .ok_or_else(|| anyhow!("binary has no .text section"))?;
    let text_base = text_section.address();
    let text_data = text_section.data().context("read .text")?;
    let text_end_abs = text_base + text_section.size();

    let live_functions: Vec<_> = cu
        .functions
        .iter()
        .filter(|f| f.size > 0 && f.addr >= text_base && f.addr + f.size <= text_end_abs)
        .collect();

    if live_functions.is_empty() {
        return Err(anyhow!(
            "CU '{}' has no functions with addresses inside .text",
            cu.name
        ));
    }

    let mut obj = Object::new(
        BinaryFormat::Elf,
        object_architecture(arch),
        Endianness::Little,
    );

    // Functions are laid out sorted by original address. In the default
    // single-.text layout, this preserves the relative order of the input
    // so disassembly-and-diff tools see something close to the original.
    let mut live_functions = live_functions;
    live_functions.sort_by_key(|f| f.addr);

    struct FunctionSlot {
        section_id: SectionId,
        /// Byte offset within `section_id` where this function's bytes live.
        section_offset: u64,
        relocs: Vec<PreparedReloc>,
    }
    let mut slots: Vec<FunctionSlot> = Vec::with_capacity(live_functions.len());
    let mut local_syms: HashMap<String, SymbolId> = HashMap::new();
    let mut total_text_bytes: u64 = 0;
    let mut agg = EmitStats::default();

    // Create a single `.text` section up front if we're in shared mode.
    let shared_text: Option<SectionId> = if opts.per_function_sections {
        None
    } else {
        Some(obj.section_id(StandardSection::Text))
    };

    for f in &live_functions {
        // Take the name from the resolver when it knows this address: it owns
        // collision renaming, and every reference to this function elsewhere
        // was emitted with that same name.
        let raw_name = globals
            .functions
            .get(&f.addr)
            .map(|g| g.export_name())
            .unwrap_or_else(|| f.linkage_name.as_deref().unwrap_or(f.name.as_str()));
        let name = if raw_name.is_empty() || raw_name == "<anon>" {
            format!("__delink_sub_{:x}", f.addr)
        } else {
            raw_name.to_string()
        };

        // Recovery has to run before the bytes are handed to the writer: on
        // ARM it rewrites literal-pool words in place.
        let code = prepare_function(arch, f.addr, f.size, text_base, text_data, globals)
            .with_context(|| format!("recover relocations for function at {:#x}", f.addr))?;
        agg.accumulate(&code.stats);

        let (section_id, section_offset) = match shared_text {
            Some(sid) => {
                let off = obj.append_section_data(sid, &code.bytes, 4);
                (sid, off)
            }
            None => {
                let section_name = format!(".text.{}", sanitize_section_suffix(&name));
                let sid = obj.add_section(Vec::new(), section_name.into_bytes(), SectionKind::Text);
                obj.append_section_data(sid, &code.bytes, 4);
                (sid, 0)
            }
        };
        total_text_bytes += f.size;

        let scope = if f.external || opts.promote_locals {
            SymbolScope::Dynamic
        } else {
            SymbolScope::Compilation
        };
        let is_linkage = matches!(scope, SymbolScope::Dynamic);
        let weak = opts.comdat && opts.per_function_sections && is_linkage;
        let symbol_id = obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: section_offset,
            size: f.size,
            kind: SymbolKind::Text,
            scope,
            weak,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        local_syms.insert(name.clone(), symbol_id);

        // COMDAT only makes sense per-function-sections — can't dedupe
        // functions at the section level when they share a section.
        if opts.comdat && opts.per_function_sections && is_linkage {
            obj.add_comdat(Comdat {
                kind: object::ComdatKind::Any,
                symbol: symbol_id,
                sections: vec![section_id],
            });
        }

        slots.push(FunctionSlot {
            section_id,
            section_offset,
            relocs: code.relocs,
        });
    }

    // Pass 2: attach the recovered relocations now that every function has a
    // section and offset.
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();
    let mut relocations = 0usize;

    for slot in &slots {
        for r in &slot.relocs {
            let sym_id = resolve_symbol(&mut obj, &local_syms, &mut undef_cache, &r.target);
            // `r.offset` is the field offset within this function
            // (0..f.size). Translate to the offset within the target ELF
            // section, which differs between layout modes.
            let section_offset = slot.section_offset + r.offset;
            obj.add_relocation(
                slot.section_id,
                Relocation {
                    offset: section_offset,
                    symbol: sym_id,
                    addend: r.addend,
                    flags: RelocationFlags::Elf { r_type: r.r_type },
                },
            )
            .with_context(|| format!("add reloc at {:#x}", section_offset))?;
            relocations += 1;
        }
    }

    if opts.dwarf {
        emit_cu_dwarf(
            &mut obj,
            binary,
            cu,
            globals,
            &mut local_syms,
            &mut undef_cache,
        )?;
    }

    let bytes = obj.write().context("serialize ET_REL")?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out_path, &bytes).with_context(|| format!("write {}", out_path.display()))?;

    let dwarf_bytes = (cu
        .debug_info_range
        .end
        .saturating_sub(cu.debug_info_range.start)
        + cu.debug_abbrev_range
            .end
            .saturating_sub(cu.debug_abbrev_range.start)
        + cu.debug_line_range
            .as_ref()
            .map(|r| r.end - r.start)
            .unwrap_or(0)) as u64;

    agg.text_bytes = total_text_bytes;
    agg.local_symbols = local_syms.len();
    agg.undef_symbols = undef_cache.len();
    agg.relocations = relocations;
    agg.ranges_coalesced = cu.ranges.len().max(1);
    agg.dwarf_bytes = dwarf_bytes;
    Ok(agg)
}

fn emit_cu_dwarf(
    obj: &mut Object,
    binary: &Binary<'_>,
    cu: &CompilationUnit,
    globals: &GlobalSymbols,
    local_syms: &mut HashMap<String, SymbolId>,
    undef_cache: &mut HashMap<String, SymbolId>,
) -> Result<()> {
    if binary.arch != Arch::Aarch64 {
        // The DWARF reloc scanner assumes 8-byte `DW_FORM_addr`; on 32-bit
        // targets the slices are copied through unrelocated instead of
        // emitting relocations that would corrupt them.
        tracing::warn!(
            arch = %binary.arch,
            "DWARF relocation synthesis is AArch64-only; emitting unrelocated slices"
        );
    }
    let synth = binary.arch == Arch::Aarch64;

    let (debug_info_section, debug_info_slice) =
        add_dwarf_slice(obj, binary, ".debug_info", cu.debug_info_range.clone());
    add_dwarf_slice(obj, binary, ".debug_abbrev", cu.debug_abbrev_range.clone());
    let (debug_line_section, debug_line_slice) = if let Some(range) = cu.debug_line_range.clone() {
        add_dwarf_slice(obj, binary, ".debug_line", range)
    } else {
        (None, None)
    };

    if !synth {
        return Ok(());
    }

    if let (Some(info_section), Some(info_slice), Some(abbrev_slice)) = (
        debug_info_section,
        debug_info_slice,
        dwarf_section_slice(binary, ".debug_abbrev", cu.debug_abbrev_range.clone()),
    ) {
        match dwarf_relocs::scan_debug_info(info_slice, abbrev_slice, globals) {
            Ok((recs, _diag)) => {
                for r in recs {
                    attach_dwarf_reloc(obj, info_section, local_syms, undef_cache, &r)?;
                }
            }
            Err(e) => tracing::warn!(cu = %cu.name, error = %e, "debug_info scan failed"),
        }
    }

    if let (Some(line_section), Some(line_slice)) = (debug_line_section, debug_line_slice) {
        match dwarf_relocs::scan_debug_line(line_slice, globals) {
            Ok((recs, _diag)) => {
                for r in recs {
                    attach_dwarf_reloc(obj, line_section, local_syms, undef_cache, &r)?;
                }
            }
            Err(e) => tracing::warn!(cu = %cu.name, error = %e, "debug_line scan failed"),
        }
    }
    Ok(())
}

/// Copy a byte slice of a DWARF section into the output object and return
/// the new section id + a borrow of the slice (for follow-up reloc scans).
fn add_dwarf_slice<'a>(
    obj: &mut Object,
    binary: &'a Binary<'_>,
    section_name: &str,
    range: std::ops::Range<usize>,
) -> (Option<SectionId>, Option<&'a [u8]>) {
    let slice = dwarf_section_slice(binary, section_name, range);
    let Some(slice) = slice else {
        return (None, None);
    };
    let kind = if section_name == ".debug_str" || section_name == ".debug_line_str" {
        SectionKind::DebugString
    } else {
        SectionKind::Debug
    };
    let section_id = obj.add_section(Vec::new(), section_name.as_bytes().to_vec(), kind);
    obj.append_section_data(section_id, slice, 1);
    (Some(section_id), Some(slice))
}

fn dwarf_section_slice<'a>(
    binary: &'a Binary<'_>,
    section_name: &str,
    range: std::ops::Range<usize>,
) -> Option<&'a [u8]> {
    let section = binary.elf.section_by_name(section_name)?;
    let data = section.data().ok()?;
    if range.start >= data.len() || range.end > data.len() || range.start >= range.end {
        return None;
    }
    Some(&data[range])
}

fn attach_dwarf_reloc(
    obj: &mut Object,
    section_id: SectionId,
    local_syms: &mut HashMap<String, SymbolId>,
    undef_cache: &mut HashMap<String, SymbolId>,
    reloc: &dwarf_relocs::DwarfReloc,
) -> Result<()> {
    let (offset, symbol, addend, r_type) = match reloc {
        dwarf_relocs::DwarfReloc::Abs64 {
            offset,
            symbol,
            addend,
        } => (*offset, symbol, *addend, object::elf::R_AARCH64_ABS64),
        dwarf_relocs::DwarfReloc::Abs32 {
            offset,
            symbol,
            addend,
        } => (*offset, symbol, *addend, object::elf::R_AARCH64_ABS32),
    };
    let sym_id = resolve_symbol(obj, local_syms, undef_cache, symbol);
    obj.add_relocation(
        section_id,
        Relocation {
            offset,
            symbol: sym_id,
            addend,
            flags: RelocationFlags::Elf { r_type },
        },
    )
    .map_err(Into::into)
}

/// Sanitize a mangled symbol into something safe as a section-name suffix.
/// ELF permits most chars, but some tools choke on unusual bytes.
fn sanitize_section_suffix(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            c if c.is_ascii_alphanumeric() => out.push(c),
            '_' | '.' | '$' | '@' => out.push(ch),
            _ => out.push('_'),
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

fn resolve_symbol(
    obj: &mut Object,
    local: &HashMap<String, SymbolId>,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = local.get(name) {
        return *id;
    }
    if let Some(id) = undef.get(name) {
        return *id;
    }
    let id = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

fn aarch64_reloc_type(kind: delink_aarch64::RelocKind) -> u32 {
    use delink_aarch64::RelocKind;
    use object::elf::*;
    match kind {
        RelocKind::Call26 => R_AARCH64_CALL26,
        RelocKind::Jump26 => R_AARCH64_JUMP26,
        RelocKind::AdrPrelPgHi21 => R_AARCH64_ADR_PREL_PG_HI21,
        RelocKind::AddAbsLo12Nc => R_AARCH64_ADD_ABS_LO12_NC,
        RelocKind::Ldst8AbsLo12Nc => R_AARCH64_LDST8_ABS_LO12_NC,
        RelocKind::Ldst16AbsLo12Nc => R_AARCH64_LDST16_ABS_LO12_NC,
        RelocKind::Ldst32AbsLo12Nc => R_AARCH64_LDST32_ABS_LO12_NC,
        RelocKind::Ldst64AbsLo12Nc => R_AARCH64_LDST64_ABS_LO12_NC,
        RelocKind::Ldst128AbsLo12Nc => R_AARCH64_LDST128_ABS_LO12_NC,
        RelocKind::AdrGotPage => R_AARCH64_ADR_GOT_PAGE,
        RelocKind::Ld64GotLo12Nc => R_AARCH64_LD64_GOT_LO12_NC,
    }
}

/// Find a CU by matching the tail of its `name` against `needle`.
pub fn find_cu<'a>(units: &'a [CompilationUnit], needle: &str) -> Option<&'a CompilationUnit> {
    units
        .iter()
        .find(|u| u.name.ends_with(needle) || u.name == needle)
}

// ---------------------------------------------------------------------------
// Shared data object
// ---------------------------------------------------------------------------

/// Emit a single ET_REL carrying the binary's shared data sections with
/// named start symbols. Per-CU `.o`s reference these symbols with addends
/// for anonymous string literals / globals we can't attribute to a CU.
#[derive(Debug, Default)]
pub struct SharedDataStats {
    pub rodata_bytes: u64,
    pub data_bytes: u64,
    pub data_rel_ro_bytes: u64,
    pub data_rel_ro_local_bytes: u64,
    pub init_array_bytes: u64,
    pub fini_array_bytes: u64,
    pub bss_bytes: u64,
    pub eh_frame_bytes: u64,
    pub arm_exidx_bytes: u64,
    pub arm_extab_bytes: u64,
    pub dwarf_shared_bytes: u64,
    pub debug_ranges_relocs: usize,
    pub debug_loc_relocs: usize,
    pub translated_relatives: usize,
    pub translated_abs64: usize,
    pub translated_glob_dat: usize,
    pub skipped_relocs: usize,
    pub unresolved_relocs: usize,
    pub fde_relocs: usize,
    pub exidx_relocs: usize,
}

struct DataSectionSlot {
    section_id: SectionId,
    vaddr: u64,
    size: u64,
    needs_relocs: bool,
    /// Mutable copy of the section bytes. On ARM this is where implicit
    /// addends get written before the section is handed to the writer.
    data: Vec<u8>,
}

pub struct SharedDataOptions {
    pub dwarf: bool,
}

pub fn emit_shared_data(
    binary: &Binary<'_>,
    symbols: &GlobalSymbols,
    opts: SharedDataOptions,
    out_path: &Path,
) -> Result<SharedDataStats> {
    let arch = binary.arch;
    let mut obj = Object::new(
        BinaryFormat::Elf,
        object_architecture(arch),
        Endianness::Little,
    );
    let mut stats = SharedDataStats::default();
    let mut slots: Vec<DataSectionSlot> = Vec::new();
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();

    // Sections are collected first (bytes still mutable), the dynamic
    // relocations are translated into them, and only then is the data handed
    // to the writer — ARM needs the addends baked into the bytes.
    struct Pending {
        name: &'static str,
        kind: SectionKind,
        start_symbol: Option<&'static str>,
        needs_relocs: bool,
    }
    const SECTIONS: &[Pending] = &[
        Pending {
            name: ".rodata",
            kind: SectionKind::ReadOnlyData,
            start_symbol: Some(SYM_RODATA_START),
            needs_relocs: false,
        },
        Pending {
            name: ".data",
            kind: SectionKind::Data,
            start_symbol: Some(SYM_DATA_START),
            needs_relocs: true,
        },
        Pending {
            name: ".data.rel.ro",
            kind: SectionKind::ReadOnlyDataWithRel,
            start_symbol: Some(SYM_DATA_REL_RO_START),
            needs_relocs: true,
        },
        Pending {
            name: ".data.rel.ro.local",
            kind: SectionKind::ReadOnlyDataWithRel,
            start_symbol: Some(SYM_DATA_REL_RO_LOCAL_START),
            needs_relocs: true,
        },
        Pending {
            name: ".init_array",
            kind: SectionKind::Data,
            start_symbol: None,
            needs_relocs: true,
        },
        Pending {
            name: ".fini_array",
            kind: SectionKind::Data,
            start_symbol: None,
            needs_relocs: true,
        },
    ];

    for pending in SECTIONS {
        let Some(section) = binary.elf.section_by_name(pending.name) else {
            continue;
        };
        let data = section
            .data()
            .with_context(|| format!("read {}", pending.name))?;
        if data.is_empty() {
            continue;
        }
        let section_id =
            obj.add_section(Vec::new(), pending.name.as_bytes().to_vec(), pending.kind);
        if let Some(sym) = pending.start_symbol {
            add_start_symbol(&mut obj, section_id, sym);
        }
        let len = data.len() as u64;
        slots.push(DataSectionSlot {
            section_id,
            vaddr: section.address(),
            size: section.size(),
            needs_relocs: pending.needs_relocs,
            data: data.to_vec(),
        });
        match pending.name {
            ".rodata" => stats.rodata_bytes = len,
            ".data" => stats.data_bytes = len,
            ".data.rel.ro" => stats.data_rel_ro_bytes = len,
            ".data.rel.ro.local" => stats.data_rel_ro_local_bytes = len,
            ".init_array" => stats.init_array_bytes = len,
            ".fini_array" => stats.fini_array_bytes = len,
            _ => {}
        }
    }

    if let Some(section) = binary.elf.section_by_name(".bss") {
        let size = section.size();
        let section_id =
            obj.add_section(Vec::new(), b".bss".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(section_id).append_bss(size, 16);
        add_start_symbol(&mut obj, section_id, SYM_BSS_START);
        slots.push(DataSectionSlot {
            section_id,
            vaddr: section.address(),
            size,
            needs_relocs: false,
            data: Vec::new(),
        });
        stats.bss_bytes = size;
    }

    // Emit every named global as a defined symbol in the section whose range
    // contains it, so per-CU `.o`s can resolve by name.
    for (addr, var) in &symbols.variables {
        let Some(slot) = slots
            .iter()
            .find(|s| s.vaddr <= *addr && *addr < s.vaddr + s.size)
        else {
            continue;
        };
        let name = var.export_name().to_string();
        if name.is_empty() {
            continue;
        }
        obj.add_symbol(Symbol {
            name: name.into_bytes(),
            value: *addr - slot.vaddr,
            size: 0,
            kind: SymbolKind::Data,
            // This object is the single definition site for every global in
            // the binary, and per-CU objects reach them by name — so even
            // `static` data has to be visible outside this object. Collision
            // renaming in the resolver keeps that from clashing.
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(slot.section_id),
            flags: SymbolFlags::None,
        });
    }

    // Translate dynamic relocations that land in the sections above into
    // per-object absolute relocations.
    let ptr_reloc = match arch {
        Arch::Aarch64 => object::elf::R_AARCH64_ABS64,
        Arch::Arm => object::elf::R_ARM_ABS32,
    };
    let all_relocs = read_all_dyn_relocs(binary)?;
    let mut queued: Vec<(usize, u64, String, i64)> = Vec::new();
    for rel in &all_relocs {
        let Some(slot_idx) = slots.iter().position(|s| {
            s.needs_relocs && s.vaddr <= rel.r_offset && rel.r_offset < s.vaddr + s.size
        }) else {
            stats.skipped_relocs += 1;
            continue;
        };
        let section_offset = rel.r_offset - slots[slot_idx].vaddr;

        let class = classify_dyn_reloc(arch, rel);
        let translated = match class {
            DynClass::Relative => {
                // `*_RELATIVE` names no symbol: the module-local address it
                // installs is the addend (explicit on AArch64, read from the
                // field on ARM).
                resolve_target_name(symbols, rel.r_addend as u64)
            }
            DynClass::Abs | DynClass::GlobDat => Some((rel.sym_name.clone(), rel.r_addend)),
            DynClass::JumpSlot | DynClass::Other => {
                stats.skipped_relocs += 1;
                continue;
            }
        };

        let Some((name, addend)) = translated else {
            stats.unresolved_relocs += 1;
            continue;
        };
        if name.is_empty() {
            stats.unresolved_relocs += 1;
            continue;
        }

        queued.push((slot_idx, section_offset, name, addend));
        match class {
            DynClass::Relative => stats.translated_relatives += 1,
            DynClass::Abs => stats.translated_abs64 += 1,
            DynClass::GlobDat => stats.translated_glob_dat += 1,
            _ => {}
        }
    }

    for (slot_idx, section_offset, name, addend) in queued {
        let sym_id = resolve_or_add_undef(&mut obj, &mut undef_cache, &name);
        let emit_addend = if arch.uses_rela() {
            addend
        } else {
            // SHT_REL: bake the addend into the field. The linked-in value at
            // this offset is the *old* absolute address and must be replaced
            // even when the addend is zero.
            let slot = &mut slots[slot_idx];
            write_i32(&mut slot.data, section_offset as usize, addend)?;
            0
        };
        let section_id = slots[slot_idx].section_id;
        obj.add_relocation(
            section_id,
            Relocation {
                offset: section_offset,
                symbol: sym_id,
                addend: emit_addend,
                flags: RelocationFlags::Elf { r_type: ptr_reloc },
            },
        )
        .with_context(|| format!("add dyn reloc at {:#x}", section_offset))?;
    }

    // Bytes are final now (ARM addends written); hand them to the writer.
    for slot in &slots {
        if slot.data.is_empty() {
            continue;
        }
        obj.append_section_data(slot.section_id, &slot.data, 16);
    }

    if arch == Arch::Aarch64 {
        if let Some(section) = binary.elf.section_by_name(".eh_frame") {
            let data = section.data().context("read .eh_frame")?;
            if !data.is_empty() {
                let section_id =
                    obj.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
                obj.append_section_data(section_id, data, 8);
                stats.eh_frame_bytes = data.len() as u64;
                stats.fde_relocs = translate_eh_frame(
                    &mut obj,
                    section_id,
                    data,
                    section.address(),
                    symbols,
                    &mut undef_cache,
                )?;
            }
        }
    } else {
        let (exidx, extab, relocs) = emit_arm_unwind(&mut obj, binary, symbols, &mut undef_cache)?;
        stats.arm_exidx_bytes = exidx;
        stats.arm_extab_bytes = extab;
        stats.exidx_relocs = relocs;
    }

    if opts.dwarf {
        emit_shared_dwarf(&mut obj, binary, symbols, &mut undef_cache, &mut stats)?;
    }

    let bytes = obj.write().context("serialize shared-data ET_REL")?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out_path, &bytes).with_context(|| format!("write {}", out_path.display()))?;

    Ok(stats)
}

fn write_i32(data: &mut [u8], offset: usize, value: i64) -> Result<()> {
    let field = data
        .get_mut(offset..offset + 4)
        .with_context(|| format!("dynamic reloc offset {offset} past end of section"))?;
    field.copy_from_slice(&(value as i32).to_le_bytes());
    Ok(())
}

pub const SYM_ARM_EXTAB_START: &str = "__delink_arm_extab_start";

/// Copy `.ARM.exidx` / `.ARM.extab` into the shared object and relocate the
/// `PREL31` pointers inside the index so entries keep addressing their
/// function after the split.
///
/// `sh_link` (which normally ties an exidx section to the code it describes)
/// is not settable through `object`'s writer, so the section is emitted with
/// `SHT_ARM_EXIDX` + `SHF_ALLOC` only.
fn emit_arm_unwind(
    obj: &mut Object,
    binary: &Binary<'_>,
    symbols: &GlobalSymbols,
    undef_cache: &mut HashMap<String, SymbolId>,
) -> Result<(u64, u64, usize)> {
    let mut extab_bytes = 0u64;
    let mut extab_vaddr = 0u64;
    if let Some(section) = binary.elf.section_by_name(".ARM.extab") {
        let data = section.data().context("read .ARM.extab")?;
        if !data.is_empty() {
            let sid = obj.add_section(
                Vec::new(),
                b".ARM.extab".to_vec(),
                SectionKind::ReadOnlyData,
            );
            obj.append_section_data(sid, data, 4);
            add_start_symbol(obj, sid, SYM_ARM_EXTAB_START);
            extab_bytes = data.len() as u64;
            extab_vaddr = section.address();
        }
    }

    let Some(section) = binary.elf.section_by_name(".ARM.exidx") else {
        return Ok((0, extab_bytes, 0));
    };
    let data = section.data().context("read .ARM.exidx")?;
    if data.is_empty() {
        return Ok((0, extab_bytes, 0));
    }
    let vaddr = section.address();
    let mut bytes = data.to_vec();
    let mut relocs: Vec<(u64, String, i64)> = Vec::new();

    for (i, entry) in data.chunks_exact(8).enumerate() {
        let entry_off = (i * 8) as u64;
        let word0 = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let word1 = u32::from_le_bytes(entry[4..8].try_into().unwrap());

        // word0: PREL31 offset from this slot to the function it describes.
        let place = vaddr + entry_off;
        let func_addr = place.wrapping_add(sign_extend31(word0) as u64);
        if let Some((name, addend)) = resolve_target_name(symbols, func_addr) {
            relocs.push((entry_off, name, addend));
        }

        // word1 is EXIDX_CANTUNWIND (1), an inline unwind opcode block
        // (bit 31 set), or a PREL31 pointer into `.ARM.extab`.
        if word1 != 1 && word1 & 0x8000_0000 == 0 && extab_bytes > 0 {
            let place = vaddr + entry_off + 4;
            let extab_addr = place.wrapping_add(sign_extend31(word1) as u64);
            let offset_in_extab = extab_addr.wrapping_sub(extab_vaddr);
            if offset_in_extab < extab_bytes {
                relocs.push((
                    entry_off + 4,
                    SYM_ARM_EXTAB_START.to_string(),
                    offset_in_extab as i64,
                ));
            }
        }
    }

    for (offset, _, addend) in &relocs {
        delink_arm::apply_addend(
            delink_arm::RelocKind::Prel31,
            &mut bytes,
            *offset as usize,
            *addend,
        )?;
    }

    let sid = obj.add_section(
        Vec::new(),
        b".ARM.exidx".to_vec(),
        SectionKind::Elf(object::elf::SHT_ARM_EXIDX),
    );
    obj.section_mut(sid).flags = SectionFlags::Elf {
        sh_flags: object::elf::SHF_ALLOC as u64,
    };
    obj.append_section_data(sid, &bytes, 4);

    let count = relocs.len();
    for (offset, name, _) in relocs {
        let sym_id = resolve_or_add_undef(obj, undef_cache, &name);
        obj.add_relocation(
            sid,
            Relocation {
                offset,
                symbol: sym_id,
                addend: 0,
                flags: RelocationFlags::Elf {
                    r_type: object::elf::R_ARM_PREL31,
                },
            },
        )
        .with_context(|| format!("add .ARM.exidx reloc at {offset:#x}"))?;
    }

    Ok((data.len() as u64, extab_bytes, count))
}

fn sign_extend31(v: u32) -> i32 {
    ((v & 0x7fff_ffff) << 1) as i32 >> 1
}

fn emit_shared_dwarf(
    obj: &mut Object,
    binary: &Binary<'_>,
    symbols: &GlobalSymbols,
    undef_cache: &mut HashMap<String, SymbolId>,
    stats: &mut SharedDataStats,
) -> Result<()> {
    // DWARF sections that are shared across all per-CU `.o`s go here. Per-CU
    // `.debug_info`/`.debug_abbrev`/`.debug_line` live in each CU's own `.o`
    // (see emit_cu), and reference these shared sections by raw offset.
    //
    // For address-bearing shared sections (.debug_ranges / .debug_loc) we
    // walk their content and attach per-pair relocations so the linker
    // rewrites absolute VAs to point at the new function layout.
    let mut debug_ranges_info: Option<(SectionId, &[u8])> = None;
    let mut debug_loc_info: Option<(SectionId, &[u8])> = None;

    for dwarf_shared in [
        ".debug_str",
        ".debug_line_str",
        ".debug_str_offsets",
        ".debug_ranges",
        ".debug_rnglists",
        ".debug_loc",
        ".debug_loclists",
        ".debug_addr",
    ] {
        if let Some(section) = binary.elf.section_by_name(dwarf_shared) {
            let data = section.data().unwrap_or(&[]);
            if data.is_empty() {
                continue;
            }
            let kind = if dwarf_shared == ".debug_str" || dwarf_shared == ".debug_line_str" {
                SectionKind::DebugString
            } else {
                SectionKind::Debug
            };
            let sid = obj.add_section(Vec::new(), dwarf_shared.as_bytes().to_vec(), kind);
            obj.append_section_data(sid, data, 1);
            stats.dwarf_shared_bytes += data.len() as u64;

            let start_sym = match dwarf_shared {
                ".debug_str" => Some("__delink_debug_str_start"),
                ".debug_line_str" => Some("__delink_debug_line_str_start"),
                ".debug_ranges" => Some("__delink_debug_ranges_start"),
                ".debug_rnglists" => Some("__delink_debug_rnglists_start"),
                ".debug_loc" => Some("__delink_debug_loc_start"),
                ".debug_loclists" => Some("__delink_debug_loclists_start"),
                _ => None,
            };
            if let Some(sym) = start_sym {
                obj.add_symbol(Symbol {
                    name: sym.as_bytes().to_vec(),
                    value: 0,
                    size: 0,
                    kind: SymbolKind::Data,
                    scope: SymbolScope::Dynamic,
                    weak: false,
                    section: SymbolSection::Section(sid),
                    flags: SymbolFlags::None,
                });
            }

            if dwarf_shared == ".debug_ranges" {
                debug_ranges_info = Some((sid, data));
            } else if dwarf_shared == ".debug_loc" {
                debug_loc_info = Some((sid, data));
            }
        }
    }

    if binary.arch != Arch::Aarch64 {
        // See `emit_cu_dwarf`: the scanners assume 64-bit DWARF addresses.
        return Ok(());
    }

    let ptr_size = binary.class.pointer_size() as u8;
    if let Some((sid, data)) = debug_ranges_info {
        let (recs, diag) = dwarf_relocs::scan_debug_ranges(data, ptr_size, symbols);
        for r in recs {
            attach_dwarf_reloc(obj, sid, &mut HashMap::new(), undef_cache, &r)?;
        }
        stats.debug_ranges_relocs = diag.range_pairs_resolved;
    }
    if let Some((sid, data)) = debug_loc_info {
        let (recs, diag) = dwarf_relocs::scan_debug_loc(data, ptr_size, symbols);
        for r in recs {
            attach_dwarf_reloc(obj, sid, &mut HashMap::new(), undef_cache, &r)?;
        }
        stats.debug_loc_relocs = diag.loc_pairs_resolved;
    }
    Ok(())
}

/// Walk `.eh_frame`, find each FDE's `pc_begin` field (assumed `DW_EH_PE_pcrel
/// | DW_EH_PE_sdata4` — standard on AArch64 ELF), resolve the target function
/// address to a symbol, and emit an `R_AARCH64_PREL32` relocation at that
/// field so the linker rewrites the offset when the function moves.
///
/// Returns the number of relocations emitted.
fn translate_eh_frame(
    obj: &mut Object,
    section_id: SectionId,
    data: &[u8],
    section_vaddr: u64,
    symbols: &GlobalSymbols,
    undef_cache: &mut HashMap<String, SymbolId>,
) -> Result<usize> {
    let mut cursor = 0usize;
    let mut emitted = 0usize;

    while cursor + 4 <= data.len() {
        let length = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        if length == 0 {
            // Terminator.
            break;
        }
        if length == 0xffff_ffff {
            // 64-bit extended length — uncommon on AArch64 ELF, skip.
            tracing::warn!(".eh_frame has 64-bit record at offset {cursor}; skipping");
            break;
        }

        let record_start = cursor;
        let record_header_end = cursor + 4;
        let record_end = record_header_end + length;
        if record_end > data.len() {
            tracing::warn!(
                ".eh_frame truncated at offset {cursor}: record claims {length} bytes, only {} left",
                data.len() - record_header_end
            );
            break;
        }

        // The second u32 is CIE_id (for CIEs) or CIE_pointer (for FDEs).
        // CIE_id == 0 → this is a CIE; anything else → FDE.
        let cie_id = u32::from_le_bytes(
            data[record_header_end..record_header_end + 4]
                .try_into()
                .unwrap(),
        );
        if cie_id != 0 {
            // FDE: pc_begin follows at record_start + 8.
            let pc_begin_field_off = record_start + 8;
            let pc_begin_rel = i32::from_le_bytes(
                data[pc_begin_field_off..pc_begin_field_off + 4]
                    .try_into()
                    .unwrap(),
            ) as i64;
            let field_vaddr = section_vaddr + pc_begin_field_off as u64;
            let target_vaddr = field_vaddr.wrapping_add(pc_begin_rel as u64);

            if let Some((name, addend)) = fde_resolve_target(symbols, target_vaddr) {
                let sym_id = resolve_or_add_undef(obj, undef_cache, &name);
                obj.add_relocation(
                    section_id,
                    Relocation {
                        offset: pc_begin_field_off as u64,
                        symbol: sym_id,
                        addend,
                        flags: RelocationFlags::Elf {
                            r_type: object::elf::R_AARCH64_PREL32,
                        },
                    },
                )
                .with_context(|| format!("add FDE pc_begin reloc at {:#x}", pc_begin_field_off))?;
                emitted += 1;
            } else {
                tracing::trace!(
                    "FDE at {:#x}: pc_begin {:#x} resolves to no known function",
                    record_start,
                    target_vaddr
                );
            }
        }

        cursor = record_end;
    }

    Ok(emitted)
}

fn fde_resolve_target(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    // FDE pc_begin usually points at the first byte of the function. If it
    // didn't (cold-split function segments etc.), fall through to interior
    // lookup.
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr < *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum DynClass {
    Relative,
    /// Pointer-sized absolute: `R_AARCH64_ABS64` / `R_ARM_ABS32`.
    Abs,
    GlobDat,
    JumpSlot,
    Other,
}

fn classify_dyn_reloc(arch: Arch, rel: &DynReloc) -> DynClass {
    use object::elf::*;
    match arch {
        Arch::Aarch64 => match rel.r_type {
            R_AARCH64_RELATIVE => DynClass::Relative,
            R_AARCH64_ABS64 => DynClass::Abs,
            R_AARCH64_GLOB_DAT => DynClass::GlobDat,
            R_AARCH64_JUMP_SLOT => DynClass::JumpSlot,
            _ => DynClass::Other,
        },
        Arch::Arm => match rel.r_type {
            R_ARM_RELATIVE => DynClass::Relative,
            R_ARM_ABS32 | R_ARM_TARGET1 => DynClass::Abs,
            R_ARM_GLOB_DAT => DynClass::GlobDat,
            R_ARM_JUMP_SLOT => DynClass::JumpSlot,
            _ => DynClass::Other,
        },
    }
}

fn resolve_target_name(symbols: &GlobalSymbols, addr: u64) -> Option<(String, i64)> {
    // Prefer function at exact start; then variable; then fall back to section-relative.
    if let Some(f) = symbols.functions.get(&addr) {
        return Some((f.export_name().to_string(), 0));
    }
    if let Some(v) = symbols.variables.get(&addr) {
        return Some((v.export_name().to_string(), 0));
    }
    if let Some((start, f)) = symbols.functions.range(..=addr).next_back() {
        if addr < *start + f.size {
            return Some((f.export_name().to_string(), (addr - *start) as i64));
        }
    }
    // Section-relative fallback via resolve_data.
    let r = symbols.resolve_data(addr)?;
    Some((r.symbol, r.addend))
}

fn resolve_or_add_undef(
    obj: &mut Object,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = undef.get(name) {
        return *id;
    }
    let id = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Unknown,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

fn add_start_symbol(obj: &mut Object, section_id: SectionId, name: &str) {
    obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(section_id),
        flags: SymbolFlags::None,
    });
}

/// Sanitize a DWARF CU name (which often contains backslashes and colons
/// on Windows-compiled inputs) into a filesystem-safe stem.
pub fn sanitize_cu_name(name: &str) -> String {
    // Take only the final path component, strip any extension.
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = match basename.rfind('.') {
        Some(i) => &basename[..i],
        None => basename,
    };
    stem.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Split every CU in `idx` into its own `.o` under `out_dir`, in parallel.
/// Skips CUs with no sized functions; returns per-CU outcomes.
#[derive(Debug)]
pub struct CuOutcome {
    pub cu_name: String,
    pub file: std::path::PathBuf,
    pub result: std::result::Result<EmitStats, String>,
}

#[allow(clippy::too_many_arguments)]
pub fn split_all(
    binary: &Binary<'_>,
    idx: &delink_core::cu::CuIndex,
    symbols: &GlobalSymbols,
    out_dir: &Path,
    comdat: bool,
    dwarf: bool,
    per_function_sections: bool,
    promote_locals: bool,
) -> Result<Vec<CuOutcome>> {
    use rayon::prelude::*;
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let outcomes: Vec<CuOutcome> = idx
        .units
        .par_iter()
        .filter(|cu| cu.functions.iter().any(|f| f.size > 0))
        .map(|cu| {
            // An edited grouping file names its own outputs; otherwise derive
            // a filesystem-safe stem from the CU name.
            let file = match &cu.file_name {
                Some(name) => out_dir.join(name),
                None => out_dir.join(format!("{:04}_{}.o", cu.id, sanitize_cu_name(&cu.name))),
            };
            let result = emit_cu(
                binary,
                EmitOptions {
                    cu,
                    symbols,
                    comdat,
                    dwarf,
                    per_function_sections,
                    promote_locals,
                },
                &file,
            )
            .map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_name: cu.name.clone(),
                file,
                result,
            }
        })
        .collect();

    Ok(outcomes)
}
