//! COFF `.obj` emitter for PE compilation units.
//!
//! Produces one COFF ET_REL-equivalent per `PeCompilationUnit` plus a single
//! `__shared_data.obj` carrying `.rdata`, `.data`, and `.bss`.
//!
//! Supports both AMD64 (PE32+) and I386 (PE32) inputs:
//!   AMD64: `IMAGE_REL_AMD64_REL32` / `IMAGE_REL_AMD64_ADDR64`
//!   I386:  `IMAGE_REL_I386_REL32`  / `IMAGE_REL_I386_DIR32`

use anyhow::{anyhow, Context, Result};
use object::write::{Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags,
    SymbolKind, SymbolScope,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use crate::cu::{PeCompilationUnit, PeFunction};
use crate::{BaseRelocKind, PeArch, PeContext, PeSection};

// AMD64 relocation type constants.
const REL_AMD64_ADDR64: u16 = object::pe::IMAGE_REL_AMD64_ADDR64;
const REL_AMD64_REL32: u16 = object::pe::IMAGE_REL_AMD64_REL32;

// I386 relocation type constants.
const REL_I386_DIR32: u16 = object::pe::IMAGE_REL_I386_DIR32;
const REL_I386_REL32: u16 = object::pe::IMAGE_REL_I386_REL32;

// object::write::coff::coff_adjust_addend (pub(crate), not externally callable) adds the
// field width to every REL32 addend before embedding it in the section bytes.  It uses the
// ELF S+A−P convention where P is the *start* of the reloc field, so it needs to add 4 to
// reach the next-instruction address that the CPU actually branches relative to.
// We subtract the same amount here so the final embedded value equals r.addend.
const REL32_FIELD_BYTES: i64 = 4;

#[derive(Debug, Default)]
pub struct EmitStats {
    pub text_bytes: u64,
    pub local_symbols: usize,
    pub undef_symbols: usize,
    pub relocations: usize,
    pub unresolved_calls: usize,
    pub unresolved_rip_refs: usize,
    pub instructions: usize,
}

#[derive(Debug, Default)]
pub struct SharedDataStats {
    pub rdata_bytes: u64,
    pub data_bytes: u64,
    pub bss_bytes: u64,
    pub addr64_relocs: usize,
}

#[derive(Debug)]
pub struct CuOutcome {
    pub cu_name: String,
    pub file: std::path::PathBuf,
    pub result: std::result::Result<EmitStats, String>,
}

// ---------------------------------------------------------------------------
// Per-CU emit
// ---------------------------------------------------------------------------

/// Emit one COFF `.obj` for `cu`, writing to `out_path`.
pub fn emit_pe_cu(
    pe: &PeContext,
    cu: &PeCompilationUnit,
    out_path: &Path,
) -> Result<EmitStats> {
    let text_section = pe
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .ok_or_else(|| anyhow!("PE has no .text section"))?;

    // Collect live functions: must have a valid VA inside .text and non-zero size.
    let mut live: Vec<&PeFunction> = cu
        .functions
        .iter()
        .filter(|f| f.size > 0 && text_section.contains_va(f.va))
        .collect();

    if live.is_empty() {
        return Err(anyhow!(
            "module '{}' has no functions inside .text",
            cu.name
        ));
    }
    live.sort_by_key(|f| f.va);

    let coff_arch = match pe.arch {
        PeArch::X86_64 => Architecture::X86_64,
        PeArch::X86 => Architecture::I386,
    };
    let mut obj = Object::new(BinaryFormat::Coff, coff_arch, Endianness::Little);
    let mut local_syms: HashMap<String, SymbolId> = HashMap::new();
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();
    let mut total_text_bytes = 0u64;
    let mut total_relocs = 0usize;
    let mut total_instructions = 0usize;
    let mut total_unresolved_calls = 0usize;
    let mut total_unresolved_rip = 0usize;

    let sid = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);

    for f in &live {
        let fn_start = (f.va - text_section.va) as usize;
        let fn_end = fn_start + f.size as usize;
        if fn_end > text_section.data.len() {
            tracing::warn!(
                "function '{}' at {:#x} extends past .text data; skipping",
                f.name,
                f.va
            );
            continue;
        }
        let mut fn_bytes = text_section.data[fn_start..fn_end].to_vec();
        total_text_bytes += f.size as u64;

        // Run relocation recovery and apply base-reloc absolute-pointer fixups,
        // branching on PE architecture.
        match pe.arch {
            PeArch::X86_64 => {
                let recovery = delink_x86_64::recover(
                    &fn_bytes,
                    f.va,
                    f.size as u64,
                    &pe.symbols,
                )
                .with_context(|| format!("recover relocs for '{}' at {:#x}", f.name, f.va))?;

                total_instructions += recovery.diag.instructions;
                total_unresolved_calls += recovery.diag.calls_unresolved;
                total_unresolved_rip += recovery.diag.rip_refs_unresolved;

                // Zero REL32 positions.
                for r in &recovery.relocs {
                    let off = r.offset as usize;
                    let zero_len = match r.kind {
                        delink_x86_64::RelocKind::Rel32 => 4,
                        delink_x86_64::RelocKind::Addr64 => 8,
                    };
                    if off + zero_len <= fn_bytes.len() {
                        fn_bytes[off..off + zero_len].fill(0);
                    }
                }

                // Zero ADDR64 slots from the PE base-reloc table; stage relocs
                // until after append so offsets are section-relative.
                let mut staged: Vec<(u64, SymbolId, i64, u16)> = Vec::new();
                for br in &pe.base_relocations {
                    if !matches!(br.kind, BaseRelocKind::Dir64) {
                        continue;
                    }
                    if br.va < f.va || br.va + 8 > f.va + f.size as u64 {
                        continue;
                    }
                    let off = (br.va - f.va) as usize;
                    if off + 8 <= fn_bytes.len() {
                        let stored_va =
                            u64::from_le_bytes(fn_bytes[off..off + 8].try_into().unwrap());
                        if let Some((sym_name, addend)) = pe.symbols.resolve_data(stored_va) {
                            let sym = resolve_or_add_undef(&mut obj, &mut undef_cache, &sym_name);
                            fn_bytes[off..off + 8].fill(0);
                            staged.push((off as u64, sym, addend, REL_AMD64_ADDR64));
                        }
                    }
                }

                let fn_offset = obj.append_section_data(sid, &fn_bytes, 1);

                let scope = if f.is_public { SymbolScope::Dynamic } else { SymbolScope::Compilation };
                let sym_id = obj.add_symbol(Symbol {
                    name: f.name.as_bytes().to_vec(),
                    value: fn_offset,
                    size: f.size as u64,
                    kind: SymbolKind::Text,
                    scope,
                    weak: false,
                    section: SymbolSection::Section(sid),
                    flags: SymbolFlags::None,
                });
                local_syms.insert(f.name.clone(), sym_id);

                // Emit symbols for data labels embedded within this function's body.
                for (var_va, var) in pe.symbols.variables.range(f.va..f.va + f.size as u64) {
                    if *var_va == f.va {
                        continue;
                    }
                    let label_scope = if var.is_public { SymbolScope::Dynamic } else { SymbolScope::Compilation };
                    let label_id = obj.add_symbol(Symbol {
                        name: var.name.as_bytes().to_vec(),
                        value: fn_offset + (var_va - f.va),
                        size: 0,
                        kind: SymbolKind::Label,
                        scope: label_scope,
                        weak: false,
                        section: SymbolSection::Section(sid),
                        flags: SymbolFlags::None,
                    });
                    local_syms.insert(var.name.clone(), label_id);
                }

                for (off, sym, addend, typ) in staged {
                    obj.add_relocation(
                        sid,
                        Relocation {
                            offset: fn_offset + off,
                            symbol: sym,
                            addend,
                            flags: RelocationFlags::Coff { typ },
                        },
                    )
                    .with_context(|| format!("add ADDR64 reloc at {:#x}", f.va + off))?;
                    total_relocs += 1;
                }

                for r in &recovery.relocs {
                    let sym_id =
                        resolve_symbol(&mut obj, &local_syms, &mut undef_cache, &r.target);
                    obj.add_relocation(
                        sid,
                        Relocation {
                            offset: fn_offset + r.offset,
                            symbol: sym_id,
                            addend: r.addend - REL32_FIELD_BYTES,
                            flags: RelocationFlags::Coff { typ: REL_AMD64_REL32 },
                        },
                    )
                    .with_context(|| format!("add rel32 reloc at {:#x}", r.offset))?;
                    total_relocs += 1;
                }
            }

            PeArch::X86 => {
                let recovery = delink_x86::recover(
                    &fn_bytes,
                    f.va,
                    f.size as u64,
                    &pe.symbols,
                )
                .with_context(|| format!("recover relocs for '{}' at {:#x}", f.name, f.va))?;

                total_instructions += recovery.diag.instructions;
                total_unresolved_calls += recovery.diag.calls_unresolved;
                total_unresolved_rip += recovery.diag.rip_refs_unresolved;

                // Zero REL32 positions.
                for r in &recovery.relocs {
                    let off = r.offset as usize;
                    if off + 4 <= fn_bytes.len() {
                        fn_bytes[off..off + 4].fill(0);
                    }
                }

                // Zero DIR32 slots from HIGHLOW base-reloc entries; stage relocs
                // until after append so offsets are section-relative.
                let mut staged: Vec<(u64, SymbolId, i64, u16)> = Vec::new();
                for br in &pe.base_relocations {
                    if !matches!(br.kind, BaseRelocKind::HighLow) {
                        continue;
                    }
                    if br.va < f.va || br.va + 4 > f.va + f.size as u64 {
                        continue;
                    }
                    let off = (br.va - f.va) as usize;
                    if off + 4 <= fn_bytes.len() {
                        let stored_va = u32::from_le_bytes(
                            fn_bytes[off..off + 4].try_into().unwrap(),
                        ) as u64;
                        if let Some((sym_name, addend)) = pe.symbols.resolve_data(stored_va) {
                            let sym = resolve_or_add_undef(&mut obj, &mut undef_cache, &sym_name);
                            fn_bytes[off..off + 4].fill(0);
                            staged.push((off as u64, sym, addend, REL_I386_DIR32));
                        }
                    }
                }

                let fn_offset = obj.append_section_data(sid, &fn_bytes, 4);

                let scope = if f.is_public { SymbolScope::Dynamic } else { SymbolScope::Compilation };
                let sym_id = obj.add_symbol(Symbol {
                    name: f.name.as_bytes().to_vec(),
                    value: fn_offset,
                    size: f.size as u64,
                    kind: SymbolKind::Text,
                    scope,
                    weak: false,
                    section: SymbolSection::Section(sid),
                    flags: SymbolFlags::None,
                });
                local_syms.insert(f.name.clone(), sym_id);

                // Emit symbols for data labels embedded within this function's body.
                for (var_va, var) in pe.symbols.variables.range(f.va..f.va + f.size as u64) {
                    if *var_va == f.va {
                        continue;
                    }
                    let label_scope = if var.is_public { SymbolScope::Dynamic } else { SymbolScope::Compilation };
                    let label_id = obj.add_symbol(Symbol {
                        name: var.name.as_bytes().to_vec(),
                        value: fn_offset + (var_va - f.va),
                        size: 0,
                        kind: SymbolKind::Label,
                        scope: label_scope,
                        weak: false,
                        section: SymbolSection::Section(sid),
                        flags: SymbolFlags::None,
                    });
                    local_syms.insert(var.name.clone(), label_id);
                }

                for (off, sym, addend, typ) in staged {
                    obj.add_relocation(
                        sid,
                        Relocation {
                            offset: fn_offset + off,
                            symbol: sym,
                            addend,
                            flags: RelocationFlags::Coff { typ },
                        },
                    )
                    .with_context(|| format!("add DIR32 reloc at {:#x}", f.va + off))?;
                    total_relocs += 1;
                }

                for r in &recovery.relocs {
                    let sym_id =
                        resolve_symbol(&mut obj, &local_syms, &mut undef_cache, &r.target);
                    obj.add_relocation(
                        sid,
                        Relocation {
                            offset: fn_offset + r.offset,
                            symbol: sym_id,
                            addend: r.addend - REL32_FIELD_BYTES,
                            flags: RelocationFlags::Coff { typ: REL_I386_REL32 },
                        },
                    )
                    .with_context(|| format!("add rel32 reloc at {:#x}", r.offset))?;
                    total_relocs += 1;
                }
            }
        }
    }

    // Emit non-.text section contributions for this CU (e.g. .rdata, .data, .bss).
    let (pointer_width, abs_reloc_typ) = match pe.arch {
        PeArch::X86_64 => (8usize, REL_AMD64_ADDR64),
        PeArch::X86 => (4usize, REL_I386_DIR32),
    };
    for contrib in cu.contributions.iter().filter(|c| c.section_name != ".text") {
        let Some(pe_section) = pe.sections.iter().find(|s| s.name == contrib.section_name) else {
            continue;
        };

        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        const IMAGE_SCN_CNT_UNINIT: u32 = 0x0000_0080;
        let kind = if pe_section.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && pe_section.characteristics & IMAGE_SCN_CNT_UNINIT != 0
        {
            SectionKind::UninitializedData
        } else if pe_section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            SectionKind::Data
        } else {
            SectionKind::ReadOnlyData
        };

        let data_sid =
            obj.add_section(Vec::new(), contrib.section_name.as_bytes().to_vec(), kind);

        let section_base: u64;

        if kind == SectionKind::UninitializedData {
            obj.section_mut(data_sid).append_bss(contrib.size as u64, 1);
            section_base = 0;
        } else {
            let start = (contrib.va - pe_section.va) as usize;
            let end = (start + contrib.size as usize).min(pe_section.data.len());
            let mut contrib_bytes = pe_section.data[start..end].to_vec();

            // Zero base-reloc slots and stage their relocations.
            let mut staged_data: Vec<(u64, SymbolId, i64, u16)> = Vec::new();
            for br in &pe.base_relocations {
                let matches = match (&pe.arch, &br.kind) {
                    (PeArch::X86_64, BaseRelocKind::Dir64) => true,
                    (PeArch::X86, BaseRelocKind::HighLow) => true,
                    _ => false,
                };
                if !matches {
                    continue;
                }
                if br.va < contrib.va
                    || br.va + pointer_width as u64 > contrib.va + contrib.size as u64
                {
                    continue;
                }
                let off = (br.va - contrib.va) as usize;
                if off + pointer_width > contrib_bytes.len() {
                    continue;
                }
                let target_va: u64 = match pointer_width {
                    8 => u64::from_le_bytes(contrib_bytes[off..off + 8].try_into().unwrap()),
                    4 => u32::from_le_bytes(contrib_bytes[off..off + 4].try_into().unwrap()) as u64,
                    _ => unreachable!(),
                };
                contrib_bytes[off..off + pointer_width].fill(0);
                if let Some((sym_name, addend)) = pe.symbols.resolve_data(target_va) {
                    let sym = resolve_or_add_undef(&mut obj, &mut undef_cache, &sym_name);
                    staged_data.push((off as u64, sym, addend, abs_reloc_typ));
                }
            }

            section_base = obj.append_section_data(data_sid, &contrib_bytes, 1);

            for (off, sym, addend, typ) in staged_data {
                obj.add_relocation(
                    data_sid,
                    Relocation {
                        offset: section_base + off,
                        symbol: sym,
                        addend,
                        flags: RelocationFlags::Coff { typ },
                    },
                )
                .with_context(|| format!("add data reloc at {:#x}", contrib.va + off))?;
                total_relocs += 1;
            }
        }

        // Emit variable symbols for this contribution's address range.
        for (var_va, var) in pe
            .symbols
            .variables
            .range(contrib.va..contrib.va + contrib.size as u64)
        {
            let offset = section_base + (var_va - contrib.va);
            let scope = if var.is_public {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Compilation
            };
            obj.add_symbol(Symbol {
                name: var.name.as_bytes().to_vec(),
                value: offset,
                size: 0,
                kind: SymbolKind::Data,
                scope,
                weak: false,
                section: SymbolSection::Section(data_sid),
                flags: SymbolFlags::None,
            });
        }
    }

    let bytes = obj.write().context("serialize COFF object")?;
    write_file(out_path, &bytes)?;

    Ok(EmitStats {
        text_bytes: total_text_bytes,
        local_symbols: local_syms.len(),
        undef_symbols: undef_cache.len(),
        relocations: total_relocs,
        unresolved_calls: total_unresolved_calls,
        unresolved_rip_refs: total_unresolved_rip,
        instructions: total_instructions,
    })
}

// ---------------------------------------------------------------------------
// Shared-data emit
// ---------------------------------------------------------------------------

/// Emit `__shared_data.obj` carrying `.rdata`, `.data`, `.bss` from the PE,
/// with absolute-pointer relocations for all applicable base-reloc entries
/// that land in those sections.
pub fn emit_pe_shared(pe: &PeContext, out_path: &Path) -> Result<SharedDataStats> {
    let coff_arch = match pe.arch {
        PeArch::X86_64 => Architecture::X86_64,
        PeArch::X86 => Architecture::I386,
    };
    let mut obj = Object::new(BinaryFormat::Coff, coff_arch, Endianness::Little);
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();
    let mut stats = SharedDataStats::default();

    struct Slot {
        sid: SectionId,
        va: u64,
        size: u64,
    }
    let mut slots: Vec<Slot> = Vec::new();

    let add_section =
        |obj: &mut Object,
         slots: &mut Vec<Slot>,
         stats_bytes: &mut u64,
         section: &PeSection,
         kind: SectionKind,
         start_sym: &str| {
            let sid = obj.add_section(
                Vec::new(),
                section.name.as_bytes().to_vec(),
                kind,
            );
            if kind == SectionKind::UninitializedData {
                obj.section_mut(sid).append_bss(section.virtual_size, 16);
            } else {
                obj.append_section_data(sid, &section.data, 16);
            }
            obj.add_symbol(Symbol {
                name: start_sym.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Data,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(sid),
                flags: SymbolFlags::None,
            });
            *stats_bytes += section.virtual_size;
            slots.push(Slot {
                sid,
                va: section.va,
                size: section.virtual_size,
            });
        };

    if let Some(s) = pe.sections.iter().find(|s| s.name == ".rdata") {
        add_section(
            &mut obj,
            &mut slots,
            &mut stats.rdata_bytes,
            s,
            SectionKind::ReadOnlyData,
            "__delink_pe_rdata_start",
        );
    }
    if let Some(s) = pe.sections.iter().find(|s| s.name == ".data") {
        add_section(
            &mut obj,
            &mut slots,
            &mut stats.data_bytes,
            s,
            SectionKind::Data,
            "__delink_pe_data_start",
        );
    }
    if let Some(s) = pe.sections.iter().find(|s| s.name == ".bss") {
        add_section(
            &mut obj,
            &mut slots,
            &mut stats.bss_bytes,
            s,
            SectionKind::UninitializedData,
            "__delink_pe_bss_start",
        );
    }

    // Translate base relocations that land in our data sections.
    for br in &pe.base_relocations {
        let (pointer_width, abs_reloc_typ) = match (&pe.arch, &br.kind) {
            (PeArch::X86_64, BaseRelocKind::Dir64) => (8usize, REL_AMD64_ADDR64),
            (PeArch::X86, BaseRelocKind::HighLow) => (4usize, REL_I386_DIR32),
            _ => continue,
        };

        let Some(slot) =
            slots.iter().find(|s| br.va >= s.va && br.va + pointer_width as u64 <= s.va + s.size)
        else {
            continue;
        };
        let section_offset = br.va - slot.va;

        let stored_bytes = pe.data_at_va(br.va, pointer_width);
        let Some(stored_bytes) = stored_bytes else {
            continue;
        };

        // Read the stored VA (32-bit or 64-bit).
        let target_va: u64 = match pointer_width {
            8 => u64::from_le_bytes(stored_bytes.try_into().unwrap()),
            4 => u32::from_le_bytes(stored_bytes.try_into().unwrap()) as u64,
            _ => unreachable!(),
        };

        if let Some((sym_name, addend)) = pe.symbols.resolve_data(target_va) {
            let sym_id = resolve_or_add_undef(&mut obj, &mut undef_cache, &sym_name);
            obj.add_relocation(
                slot.sid,
                Relocation {
                    offset: section_offset,
                    symbol: sym_id,
                    addend,
                    flags: RelocationFlags::Coff { typ: abs_reloc_typ },
                },
            )
            .with_context(|| format!("add shared abs reloc at {:#x}", br.va))?;
            stats.addr64_relocs += 1;
        }
    }

    // Collect VAs of variables already defined in per-CU objects (non-.text
    // contributions from CUs that have at least one function).  We must not
    // re-define them here or the linker will report multiply-defined symbols.
    let claimed_vas: std::collections::HashSet<u64> = pe
        .cu_index
        .units
        .iter()
        .filter(|u| u.functions.iter().any(|f| f.size > 0))
        .flat_map(|u| {
            u.contributions
                .iter()
                .filter(|c| c.section_name != ".text")
                .flat_map(|c| {
                    pe.symbols
                        .variables
                        .range(c.va..c.va + c.size as u64)
                        .map(|(va, _)| *va)
                })
        })
        .collect();

    // Emit a COFF symbol for each named data variable that falls inside one of
    // our data sections and was not already exported in a per-CU object.
    for (va, var) in &pe.symbols.variables {
        if claimed_vas.contains(va) {
            continue;
        }
        let Some(slot) = slots.iter().find(|s| *va >= s.va && *va < s.va + s.size) else {
            continue; // variable lives outside our data sections (e.g. in .text)
        };
        let section_offset = va - slot.va;
        let scope = if var.is_public {
            SymbolScope::Dynamic
        } else {
            SymbolScope::Compilation
        };
        obj.add_symbol(Symbol {
            name: var.name.as_bytes().to_vec(),
            value: section_offset,
            size: 0,
            kind: SymbolKind::Data,
            scope,
            weak: false,
            section: SymbolSection::Section(slot.sid),
            flags: SymbolFlags::None,
        });
    }

    let bytes = obj.write().context("serialize shared COFF object")?;
    write_file(out_path, &bytes)?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Parallel split
// ---------------------------------------------------------------------------

pub fn split_all_pe(pe: &PeContext, out_dir: &Path) -> Result<Vec<CuOutcome>> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create {}", out_dir.display()))?;

    let outcomes: Vec<CuOutcome> = pe
        .cu_index
        .units
        .par_iter()
        .filter(|cu| cu.functions.iter().any(|f| f.size > 0))
        .map(|cu| {
            let stem = sanitize_file_stem(&cu.name);
            let file = out_dir.join(format!("{:04}_{stem}.obj", cu.id));
            let result = emit_pe_cu(pe, cu, &file).map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_name: cu.name.clone(),
                file,
                result,
            }
        })
        .collect();

    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_symbol(
    obj: &mut Object,
    local: &HashMap<String, SymbolId>,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = local.get(name) {
        return *id;
    }
    resolve_or_add_undef(obj, undef, name)
}

fn resolve_or_add_undef(
    obj: &mut Object,
    undef: &mut HashMap<String, SymbolId>,
    name: &str,
) -> SymbolId {
    if let Some(id) = undef.get(name) {
        return *id;
    }
    // COFF doesn't support SymbolKind::Unknown; use Data for all undefined externs.
    let id = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    undef.insert(name.to_string(), id);
    id
}

/// Sanitize a PDB module name (full path) into a filesystem-safe stem.
fn sanitize_file_stem(name: &str) -> String {
    // Take only the final path component, strip any extension.
    let basename = name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(name);
    let stem = match basename.rfind('.') {
        Some(i) => &basename[..i],
        None => basename,
    };
    stem.to_string()
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, bytes)
        .with_context(|| format!("write {}", path.display()))
}
