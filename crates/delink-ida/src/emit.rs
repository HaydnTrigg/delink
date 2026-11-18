//! Object emitter for the IDA importer.
//!
//! Produces one COFF `.obj` (or ELF `.o`) per group of functions plus a single
//! `__shared_data` object carrying the data/const/bss sections.  For x86 /
//! x86-64 it runs iced-x86 relocation recovery ([`delink_x86`] /
//! [`delink_x86_64`]) for rel32 calls/jumps and RIP-relative references, and
//! uses IDA's fixup table for absolute pointers.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use object::write::{Mangling, Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags, SymbolKind,
    SymbolScope,
};
use rayon::prelude::*;

use std::collections::BTreeMap;

use crate::idapro_json::{IdaproJson, SymbolDef};
use crate::resolver::{IdaSymbols, SYM_BSS_START, SYM_CONST_START, SYM_DATA_START};
use crate::{IdaArch, IdaModel, PeImage, SegClass};

/// Read `len` bytes at `rva` from the original binary, zero-padding any tail not
/// backed by raw section data (e.g. virtual-size padding).
fn read_padded(pe: &PeImage, rva: u64, len: usize) -> Vec<u8> {
    if let Some(b) = pe.data_at_rva(rva, len) {
        return b.to_vec();
    }
    let mut out = vec![0u8; len];
    if let Some(sec) = pe.section_for_rva(rva) {
        let off = (rva - sec.rva) as usize;
        let n = sec.data.len().saturating_sub(off).min(len);
        if n > 0 {
            out[..n].copy_from_slice(&sec.data[off..off + n]);
        }
    }
    out
}

/// REL32 fields are next-instruction-relative; the object writer (and the ELF
/// S+A−P convention) reference the field start, so subtract the 4-byte field
/// width from the recovered addend (same adjustment as the PE/Mach-O emitters).
const REL32_FIELD_BYTES: i64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Coff,
    Elf,
}

impl OutputFormat {
    pub fn binary_format(self) -> BinaryFormat {
        match self {
            OutputFormat::Coff => BinaryFormat::Coff,
            OutputFormat::Elf => BinaryFormat::Elf,
        }
    }
    /// Default output object extension.
    pub fn ext(self) -> &'static str {
        match self {
            OutputFormat::Coff => "obj",
            OutputFormat::Elf => "o",
        }
    }
    /// Pick a sensible default from IDA's reported file type.
    pub fn default_for_filetype(filetype: &str) -> OutputFormat {
        match filetype {
            "ELF" | "MACHO" => OutputFormat::Elf,
            _ => OutputFormat::Coff, // PE / COFF / unknown
        }
    }
}

#[derive(Debug, Default)]
pub struct EmitStats {
    pub text_bytes: u64,
    pub data_bytes: u64,
    pub bss_bytes: u64,
    pub instructions: usize,
    pub local_symbols: usize,
    pub undef_symbols: usize,
    pub relocations: usize,
    pub unresolved_calls: usize,
    pub unresolved_rip: usize,
}

#[derive(Debug, Default)]
pub struct SharedDataStats {
    pub data_bytes: u64,
    pub const_bytes: u64,
    pub bss_bytes: u64,
    pub relocations: usize,
}

#[derive(Debug)]
pub struct CuOutcome {
    pub cu_name: String,
    pub file: std::path::PathBuf,
    pub result: std::result::Result<EmitStats, String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Split driven by an `idapro.json` grouping.  Symbols sharing a key are
/// emitted into one object named exactly by that key.
pub fn split_by_groups(
    model: &IdaModel,
    pe: &PeImage,
    symbols: &IdaSymbols,
    groups: &IdaproJson,
    out_dir: &Path,
    format: OutputFormat,
) -> Result<Vec<CuOutcome>> {
    if model.arch == IdaArch::Other {
        return Err(anyhow!(
            "relocation recovery is only implemented for x86 / x86-64 (procname {:?})",
            model.procname
        ));
    }
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let items = DataItems::build(groups);
    let group_vec: Vec<(&String, &BTreeMap<String, SymbolDef>)> = groups.iter().collect();
    let outcomes = group_vec
        .par_iter()
        .map(|(file_name, syms)| {
            let file = out_dir.join(file_name.as_str());
            let result = emit_object(model, pe, symbols, &items, syms, format, &file)
                .map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_name: (*file_name).clone(),
                file,
                result,
            }
        })
        .collect();
    Ok(outcomes)
}

/// Emit the `__shared_data` object carrying data / const / bss sections.
pub fn emit_shared(
    model: &IdaModel,
    pe: &PeImage,
    symbols: &IdaSymbols,
    out_path: &Path,
    format: OutputFormat,
) -> Result<SharedDataStats> {
    let (arch, endian) = obj_arch(model);
    let mut obj = Object::new(format.binary_format(), arch, endian);
    if format == OutputFormat::Coff && model.arch == IdaArch::X86 {
        obj.set_mangling(Mangling::Coff);
    }
    let mut defined: HashMap<String, SymbolId> = HashMap::new();
    let mut undef: HashMap<String, SymbolId> = HashMap::new();
    let mut stats = SharedDataStats::default();

    // Track which class already emitted a `__delink_ida_*_start` symbol.
    let mut data_start_done = false;
    let mut const_start_done = false;
    let mut bss_start_done = false;

    // Data relocations are staged and emitted in a second pass, after every
    // section's start symbol and named variables exist, so a pointer into a
    // later section (or a not-yet-defined variable) still binds locally.
    struct PendingData {
        sid: SectionId,
        offset: u64,
        name: String,
        addend: i64,
        size: u32,
    }
    let mut pending: Vec<PendingData> = Vec::new();

    for sec in &model.sections {
        let (kind, name, start_sym, bytes_field): (SectionKind, &str, Option<&str>, &mut u64) =
            match sec.class {
                SegClass::Data => (
                    SectionKind::Data,
                    data_name(format),
                    (!data_start_done).then_some(SYM_DATA_START),
                    &mut stats.data_bytes,
                ),
                SegClass::Const => (
                    SectionKind::ReadOnlyData,
                    const_name(format),
                    (!const_start_done).then_some(SYM_CONST_START),
                    &mut stats.const_bytes,
                ),
                SegClass::Bss => (
                    SectionKind::UninitializedData,
                    bss_name(format),
                    (!bss_start_done).then_some(SYM_BSS_START),
                    &mut stats.bss_bytes,
                ),
                _ => continue,
            };

        let sid = obj.add_section(Vec::new(), name.as_bytes().to_vec(), kind);

        if kind == SectionKind::UninitializedData {
            obj.section_mut(sid).append_bss(sec.size(), 16);
        } else {
            // Read the section's bytes from the original binary, then zero
            // resolvable fixup slots and stage their relocations.
            let rva = sec.start.wrapping_sub(model.image_base);
            let mut bytes = read_padded(pe, rva, sec.size() as usize);
            for r in symbols.relocs_in(sec.start..sec.end) {
                if abs_flags(format, model.arch, r.size).is_none() {
                    continue;
                }
                let off = (r.addr - sec.start) as usize;
                let w = r.size as usize;
                if off + w > bytes.len() {
                    continue;
                }
                if let Some((name, addend)) = symbols.resolve_data(r.target) {
                    bytes[off..off + w].fill(0);
                    pending.push(PendingData {
                        sid,
                        offset: off as u64,
                        name,
                        addend,
                        size: r.size,
                    });
                }
            }
            obj.append_section_data(sid, &bytes, 16);
        }

        if let Some(start_sym) = start_sym {
            let id = obj.add_symbol(Symbol {
                name: start_sym.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Data,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(sid),
                flags: SymbolFlags::None,
            });
            defined.insert(start_sym.to_string(), id);
            match sec.class {
                SegClass::Data => data_start_done = true,
                SegClass::Const => const_start_done = true,
                SegClass::Bss => bss_start_done = true,
                _ => {}
            }
        }

        // Named variables that live in this section.
        for (va, var) in symbols.variables.range(sec.start..sec.end) {
            let scope = if var.public {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Compilation
            };
            let id = obj.add_symbol(Symbol {
                name: sanitize_symbol_name(&var.name),
                value: va - sec.start,
                size: 0,
                kind: SymbolKind::Data,
                scope,
                weak: false,
                section: SymbolSection::Section(sid),
                flags: SymbolFlags::None,
            });
            defined.entry(var.name.clone()).or_insert(id);
        }

        *bytes_field += sec.size();
    }

    for p in pending {
        let Some(flags) = abs_flags(format, model.arch, p.size) else {
            continue;
        };
        let sym = match defined.get(&p.name) {
            Some(id) => *id,
            None => resolve_or_add_undef(&mut obj, &mut undef, &p.name, format),
        };
        obj.add_relocation(
            p.sid,
            Relocation {
                offset: p.offset,
                symbol: sym,
                addend: p.addend,
                flags,
            },
        )
        .with_context(|| format!("add data reloc at {:#x}", p.offset))?;
        stats.relocations += 1;
    }

    let bytes = obj.write().context("serialize shared object")?;
    write_file(out_path, &bytes)?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Per-object emit
// ---------------------------------------------------------------------------

/// Every entry of the grouping (code and data), by address. An absolute pointer
/// in data that lands inside one of them is expressed relative to it
/// (`@TFoo@ + 0x4C` rather than IDA's `VMT_TFoo`), the way a compiler addresses
/// the pieces it emits. Code keeps IDA's names (its relocations compare by
/// address).
pub struct DataItems {
    by_start: BTreeMap<u64, (u64, String)>,
}

impl DataItems {
    pub fn build(groups: &IdaproJson) -> Self {
        let mut by_start = BTreeMap::new();
        for syms in groups.values() {
            for (name, d) in syms {
                // Code entries too: data can point inside a routine (a thunk block's
                // interface table) the way it points inside a VMT.
                if d.bytes.is_some() || d.anonymous || d.size == 0 {
                    continue;
                }
                by_start.insert(d.address, (d.address + d.size, name.clone()));
            }
        }
        Self { by_start }
    }

    fn containing(&self, va: u64) -> Option<(String, i64)> {
        let (start, (end, name)) = self.by_start.range(..=va).next_back()?;
        (va < *end).then(|| (name.clone(), (va - start) as i64))
    }

    /// Resolve an absolute pointer: a data entry it lands in first, then the
    /// IDA names.
    pub fn resolve(&self, symbols: &IdaSymbols, va: u64) -> Option<(String, i64)> {
        self.containing(va).or_else(|| symbols.resolve_data(va))
    }
}

fn emit_object(
    model: &IdaModel,
    pe: &PeImage,
    symbols: &IdaSymbols,
    items: &DataItems,
    syms: &BTreeMap<String, SymbolDef>,
    format: OutputFormat,
    out_path: &Path,
) -> Result<EmitStats> {
    let text_name = text_name(format);
    let is_code = |d: &SymbolDef| d.is_code(text_name);

    // Order the group's symbols by address; each carries its own va/size/scope.
    // Explicit-bytes data has no meaningful address, so keep it after the rest.
    let mut entries: Vec<(&String, &SymbolDef)> = syms
        .iter()
        .filter(|(_, d)| d.size > 0 || d.bytes.is_some())
        .collect();
    entries.sort_by_key(|(_, d)| (d.bytes.is_some(), d.address));
    if entries.is_empty() {
        return Err(anyhow!("group has no resolvable symbols"));
    }

    let (arch, endian) = obj_arch(model);
    let mut obj = Object::new(format.binary_format(), arch, endian);
    if format == OutputFormat::Coff && model.arch == IdaArch::X86 {
        obj.set_mangling(Mangling::Coff);
    }
    // Sections are created on first use, code first so a pure-code group keeps
    // its single `.text` section at index 1.
    let mut sections: HashMap<String, SectionId> = HashMap::new();
    if entries.iter().any(|(_, d)| is_code(d)) {
        let sid = obj.add_section(Vec::new(), text_name.as_bytes().to_vec(), SectionKind::Text);
        sections.insert(text_name.to_string(), sid);
    }

    let mut local: HashMap<String, SymbolId> = HashMap::new();
    let mut undef: HashMap<String, SymbolId> = HashMap::new();
    let mut stats = EmitStats::default();

    // Relocations are staged (by target *name*) and emitted in a second pass,
    // after every symbol in the group exists, so an intra-object reference
    // binds to the local definition rather than a stray undef.
    struct Pending {
        sid: SectionId,
        offset: u64,
        sym: String,
        addend: i64,
        flags: RelocationFlags,
    }
    let mut pending: Vec<Pending> = Vec::new();
    let rel32 = rel32_flags(format, model.arch);
    let ptr_size = (model.bits / 8).max(4);

    for (name, def) in entries {
        let scope = if def.scope.is_global() {
            SymbolScope::Dynamic
        } else {
            SymbolScope::Compilation
        };
        let start = def.address;
        let size = def.size;
        let rva = start.wrapping_sub(model.image_base);

        if is_code(def) {
            let sid = sections[text_name];
            let end = start + size;
            let Some(orig) = pe.data_at_rva(rva, size as usize) else {
                tracing::warn!(
                    "function '{name}' at {start:#x} (rva {rva:#x}) not backed by the input binary; skipping"
                );
                continue;
            };
            let mut bytes = orig.to_vec();
            stats.text_bytes += size;

            // 1) iced-x86 recovery â†’ rel32 relocations.
            let recovered = recover(model, &bytes, start, size, symbols)?;
            stats.instructions += recovered.instructions;
            stats.unresolved_calls += recovered.unresolved_calls;
            stats.unresolved_rip += recovered.unresolved_rip;
            for r in &recovered.relocs {
                let off = r.offset as usize;
                if off + 4 <= bytes.len() {
                    bytes[off..off + 4].fill(0);
                }
            }

            // 2) IDA fixup table â†’ absolute relocations within this function.
            let mut abs: Vec<(u64, String, i64, RelocationFlags)> = Vec::new();
            for r in symbols.relocs_in(start..end) {
                let Some(flags) = abs_flags(format, model.arch, r.size) else {
                    continue;
                };
                let off = (r.addr - start) as usize;
                let w = r.size as usize;
                if off + w > bytes.len() {
                    continue;
                }
                if let Some((tname, addend)) = symbols.resolve_data(r.target) {
                    bytes[off..off + w].fill(0);
                    abs.push((off as u64, tname, addend, flags));
                }
            }

            let fn_off = obj.append_section_data(sid, &bytes, 1);
            let sym_id = obj.add_symbol(Symbol {
                name: sanitize_symbol_name(name),
                value: fn_off,
                size,
                kind: SymbolKind::Text,
                scope,
                weak: false,
                section: SymbolSection::Section(sid),
                flags: SymbolFlags::None,
            });
            local.insert(name.clone(), sym_id);

            for (off, tname, addend, flags) in abs {
                pending.push(Pending {
                    sid,
                    offset: fn_off + off,
                    sym: tname,
                    addend,
                    flags,
                });
            }
            for r in &recovered.relocs {
                pending.push(Pending {
                    sid,
                    offset: fn_off + r.offset,
                    sym: r.target.clone(),
                    addend: r.addend - REL32_FIELD_BYTES,
                    flags: rel32,
                });
            }
            continue;
        }

        // Data symbol.
        let section_name = def.section.as_deref().unwrap_or_default();
        let kind = data_section_kind(section_name);
        let sid = *sections
            .entry(section_name.to_string())
            .or_insert_with(|| obj.add_section(Vec::new(), section_name.as_bytes().to_vec(), kind));
        // Byte alignment by default: COFF symbols carry no size, so readers infer it
        // from the next symbol, and padding would count as part of the data.
        let align = def.align.unwrap_or(1).max(1);

        let (value, sym_size) = if kind == SectionKind::UninitializedData {
            stats.bss_bytes += size;
            (obj.append_section_bss(sid, size, align), size)
        } else if let Some(hex) = &def.bytes {
            let mut bytes = decode_hex(hex).with_context(|| format!("bytes of '{name}'"))?;
            let flags = abs_flags(format, model.arch, ptr_size)
                .ok_or_else(|| anyhow!("no absolute relocation of {ptr_size} bytes"))?;
            let mut rels = Vec::new();
            for r in def.relocations.iter().flatten() {
                let off = r.offset as usize;
                if off + ptr_size as usize > bytes.len() {
                    return Err(anyhow!("relocation at {off:#x} past the end of '{name}'"));
                }
                bytes[off..off + ptr_size as usize].fill(0);
                rels.push((r.offset, r.symbol.clone(), r.addend));
            }
            let off = obj.append_section_data(sid, &bytes, align);
            for (o, s, a) in rels {
                pending.push(Pending {
                    sid,
                    offset: off + o,
                    sym: s,
                    addend: a,
                    flags,
                });
            }
            stats.data_bytes += bytes.len() as u64;
            (off, bytes.len() as u64)
        } else {
            let mut bytes = read_padded(pe, rva, size as usize);
            let mut rels = Vec::new();
            for r in symbols.relocs_in(start..start + size) {
                let Some(flags) = abs_flags(format, model.arch, r.size) else {
                    continue;
                };
                let off = (r.addr - start) as usize;
                let w = r.size as usize;
                if off + w > bytes.len() {
                    continue;
                }
                if let Some((tname, addend)) = items.resolve(symbols, r.target) {
                    bytes[off..off + w].fill(0);
                    rels.push((off as u64, tname, addend, flags));
                }
            }
            let off = obj.append_section_data(sid, &bytes, align);
            for (o, s, a, flags) in rels {
                pending.push(Pending {
                    sid,
                    offset: off + o,
                    sym: s,
                    addend: a,
                    flags,
                });
            }
            stats.data_bytes += size;
            (off, size)
        };

        if def.anonymous {
            continue;
        }
        let sym_id = obj.add_symbol(Symbol {
            name: sanitize_symbol_name(name),
            value,
            size: sym_size,
            kind: SymbolKind::Data,
            scope,
            weak: false,
            section: SymbolSection::Section(sid),
            flags: SymbolFlags::None,
        });
        local.insert(name.clone(), sym_id);
    }

    for p in pending {
        let sym = resolve_symbol(&mut obj, &local, &mut undef, &p.sym, format);
        obj.add_relocation(
            p.sid,
            Relocation {
                offset: p.offset,
                symbol: sym,
                addend: p.addend,
                flags: p.flags,
            },
        )
        .with_context(|| format!("add reloc at {:#x}", p.offset))?;
        stats.relocations += 1;
    }

    stats.local_symbols = local.len();
    stats.undef_symbols = undef.len();

    let out = obj.write().context("serialize object")?;
    write_file(out_path, &out)?;
    Ok(stats)
}

/// Section kind for a data symbol's section name.
fn data_section_kind(name: &str) -> SectionKind {
    match name {
        ".bss" | ".tbss" => SectionKind::UninitializedData,
        ".rdata" | ".rodata" => SectionKind::ReadOnlyData,
        ".tls" | ".tdata" => SectionKind::Tls,
        _ => SectionKind::Data,
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd number of hex digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("{e}")))
        .collect()
}

// ---------------------------------------------------------------------------
// iced-x86 recovery (arch-dispatched, normalised to a single reloc shape)
// ---------------------------------------------------------------------------

struct Recovered {
    relocs: Vec<RecRel>,
    instructions: usize,
    unresolved_calls: usize,
    unresolved_rip: usize,
}

struct RecRel {
    offset: u64,
    target: String,
    addend: i64,
}

fn recover(
    model: &IdaModel,
    bytes: &[u8],
    va: u64,
    size: u64,
    symbols: &IdaSymbols,
) -> Result<Recovered> {
    match model.arch {
        IdaArch::X86 => {
            let r = delink_x86::recover(bytes, va, size, symbols)?;
            Ok(Recovered {
                relocs: r
                    .relocs
                    .into_iter()
                    .map(|x| RecRel {
                        offset: x.offset,
                        target: x.target,
                        addend: x.addend,
                    })
                    .collect(),
                instructions: r.diag.instructions,
                unresolved_calls: r.diag.calls_unresolved,
                unresolved_rip: r.diag.rip_refs_unresolved,
            })
        }
        IdaArch::X86_64 => {
            let r = delink_x86_64::recover(bytes, va, size, symbols)?;
            Ok(Recovered {
                relocs: r
                    .relocs
                    .into_iter()
                    .map(|x| RecRel {
                        offset: x.offset,
                        target: x.target,
                        addend: x.addend,
                    })
                    .collect(),
                instructions: r.diag.instructions,
                unresolved_calls: r.diag.calls_unresolved,
                unresolved_rip: r.diag.rip_refs_unresolved,
            })
        }
        IdaArch::Other => Ok(Recovered {
            relocs: vec![],
            instructions: 0,
            unresolved_calls: 0,
            unresolved_rip: 0,
        }),
    }
}

// ---------------------------------------------------------------------------
// Relocation flag mapping
// ---------------------------------------------------------------------------

fn rel32_flags(fmt: OutputFormat, arch: IdaArch) -> RelocationFlags {
    match (fmt, arch) {
        (OutputFormat::Coff, IdaArch::X86_64) => RelocationFlags::Coff {
            typ: object::pe::IMAGE_REL_AMD64_REL32,
        },
        (OutputFormat::Coff, _) => RelocationFlags::Coff {
            typ: object::pe::IMAGE_REL_I386_REL32,
        },
        (OutputFormat::Elf, IdaArch::X86_64) => RelocationFlags::Elf {
            r_type: object::elf::R_X86_64_PC32,
        },
        (OutputFormat::Elf, _) => RelocationFlags::Elf {
            r_type: object::elf::R_386_PC32,
        },
    }
}

fn abs_flags(fmt: OutputFormat, arch: IdaArch, size: u32) -> Option<RelocationFlags> {
    Some(match (fmt, arch, size) {
        (OutputFormat::Coff, IdaArch::X86_64, 8) => RelocationFlags::Coff {
            typ: object::pe::IMAGE_REL_AMD64_ADDR64,
        },
        (OutputFormat::Coff, IdaArch::X86_64, 4) => RelocationFlags::Coff {
            typ: object::pe::IMAGE_REL_AMD64_ADDR32,
        },
        (OutputFormat::Coff, IdaArch::X86, 4) => RelocationFlags::Coff {
            typ: object::pe::IMAGE_REL_I386_DIR32,
        },
        (OutputFormat::Elf, IdaArch::X86_64, 8) => RelocationFlags::Elf {
            r_type: object::elf::R_X86_64_64,
        },
        (OutputFormat::Elf, IdaArch::X86_64, 4) => RelocationFlags::Elf {
            r_type: object::elf::R_X86_64_32,
        },
        (OutputFormat::Elf, IdaArch::X86, 4) => RelocationFlags::Elf {
            r_type: object::elf::R_386_32,
        },
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn obj_arch(model: &IdaModel) -> (Architecture, Endianness) {
    let arch = match model.arch {
        IdaArch::X86 => Architecture::I386,
        IdaArch::X86_64 => Architecture::X86_64,
        IdaArch::Other => Architecture::Unknown,
    };
    let endian = if model.little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };
    (arch, endian)
}

fn text_name(fmt: OutputFormat) -> &'static str {
    match fmt {
        OutputFormat::Coff => ".text",
        OutputFormat::Elf => ".text",
    }
}
fn data_name(_fmt: OutputFormat) -> &'static str {
    ".data"
}
fn const_name(fmt: OutputFormat) -> &'static str {
    match fmt {
        OutputFormat::Coff => ".rdata",
        OutputFormat::Elf => ".rodata",
    }
}
fn bss_name(_fmt: OutputFormat) -> &'static str {
    ".bss"
}

fn resolve_symbol(
    obj: &mut Object,
    local: &HashMap<String, SymbolId>,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
    fmt: OutputFormat,
) -> SymbolId {
    if let Some(id) = local.get(name) {
        return *id;
    }
    resolve_or_add_undef(obj, undef, name, fmt)
}

fn resolve_or_add_undef(
    obj: &mut Object,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
    fmt: OutputFormat,
) -> SymbolId {
    if let Some(id) = undef.get(name) {
        return *id;
    }
    // COFF doesn't support SymbolKind::Unknown; use Data for undefined externs.
    let kind = match fmt {
        OutputFormat::Coff => SymbolKind::Data,
        OutputFormat::Elf => SymbolKind::Unknown,
    };
    let id = obj.add_symbol(Symbol {
        name: sanitize_symbol_name(name),
        value: 0,
        size: 0,
        kind,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

fn sanitize_symbol_name(name: &str) -> Vec<u8> {
    if name.is_empty() {
        return b"<invalid>".to_vec();
    }
    name.as_bytes().to_vec()
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}
