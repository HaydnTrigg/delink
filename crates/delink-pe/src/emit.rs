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

                let fn_offset = obj.append_section_data(sid, &fn_bytes, 16);

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
                            addend: r.addend,
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
                            addend: r.addend,
                            flags: RelocationFlags::Coff { typ: REL_I386_REL32 },
                        },
                    )
                    .with_context(|| format!("add rel32 reloc at {:#x}", r.offset))?;
                    total_relocs += 1;
                }
            }
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
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '/' | '\\' | ':' | ' ' | '\t' => out.push('_'),
            c => out.push(c),
        }
    }
    out.trim_start_matches('_').to_string()
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, bytes)
        .with_context(|| format!("write {}", path.display()))
}
