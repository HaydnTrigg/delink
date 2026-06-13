//! Mach-O relocatable `.o` emitter for Mach-O compilation units.
//!
//! Produces one Mach-O `.o` per `MachoCompilationUnit` (code only) plus a
//! single `__shared_data.o` carrying `__DATA,__data` / `__DATA,__const` /
//! `__DATA,__bss`.
//!
//! Currently handles 32-bit i386 only (GENERIC_RELOC_VANILLA).

use anyhow::{anyhow, Context, Result};
use object::write::{Object, Relocation, Symbol, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags, SymbolKind,
    SymbolScope,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;

use crate::cu::{MachoCompilationUnit, MachoFunction};
use crate::symbols::{SYM_BSS_START, SYM_CONST_START, SYM_DATA_START};
use crate::{MachoArch, MachoContext};

// Mach-O i386 relocation constants (GENERIC_RELOC_VANILLA = 0).
const GENERIC_RELOC_VANILLA: u8 = object::macho::GENERIC_RELOC_VANILLA;
// r_length = 2 → 4-byte field (2^2 = 4).
const R_LENGTH_4: u8 = 2;

#[derive(Debug, Default)]
pub struct EmitStats {
    pub text_bytes: u64,
    pub local_symbols: usize,
    pub undef_symbols: usize,
    pub relocations: usize,
    pub unresolved_calls: usize,
    pub instructions: usize,
}

#[derive(Debug, Default)]
pub struct SharedDataStats {
    pub data_bytes: u64,
    pub const_bytes: u64,
    pub bss_bytes: u64,
}

#[derive(Debug)]
pub struct CuOutcome {
    pub cu_id: usize,
    pub cu_name: String,
    pub file: std::path::PathBuf,
    pub result: std::result::Result<EmitStats, String>,
}

// ---------------------------------------------------------------------------
// Per-CU emit
// ---------------------------------------------------------------------------

pub fn emit_macho_cu(
    ctx: &MachoContext,
    cu: &MachoCompilationUnit,
    out_path: &Path,
) -> Result<EmitStats> {
    let text_section = ctx
        .text_section()
        .ok_or_else(|| anyhow!("binary has no __TEXT,__text section"))?;

    let mut live: Vec<&MachoFunction> = cu
        .functions
        .iter()
        .filter(|f| f.size > 0 && text_section.contains_addr(f.addr))
        .collect();

    if live.is_empty() {
        return Err(anyhow!("CU '{}' has no functions inside __text", cu.name));
    }
    live.sort_by_key(|f| f.addr);

    let (macho_arch, endianness) = arch_to_object(ctx.arch);
    let mut obj = Object::new(BinaryFormat::MachO, macho_arch, endianness);
    let mut local_syms: HashMap<String, SymbolId> = HashMap::new();
    let mut undef_cache: HashMap<String, SymbolId> = HashMap::new();

    let text_sid = obj.add_section(b"__TEXT".to_vec(), b"__text".to_vec(), SectionKind::Text);

    let mut stats = EmitStats::default();
    let recover_x86 = ctx.arch == MachoArch::X86;

    for f in &live {
        let fn_start = (f.addr - text_section.addr) as usize;
        let fn_end = fn_start + f.size as usize;
        if fn_end > text_section.data.len() {
            tracing::warn!(
                "function '{}' at {:#x} extends past __text; skipping",
                f.name,
                f.addr
            );
            continue;
        }
        let mut fn_bytes = text_section.data[fn_start..fn_end].to_vec();
        stats.text_bytes += f.size;

        // For x86 we recover pc-relative relocations from the instruction stream.
        // For other architectures (PPC etc.) we emit raw bytes without synthetic
        // relocations — the bytes are correct but non-relocatable.
        let relocs_to_emit: Vec<delink_x86::recover::RecoveredReloc> = if recover_x86 {
            let recovery = delink_x86::recover(&fn_bytes, f.addr, f.size, &ctx.symbols)
                .with_context(|| format!("recover relocs for '{}' at {:#x}", f.name, f.addr))?;
            stats.instructions += recovery.diag.instructions;
            stats.unresolved_calls += recovery.diag.calls_unresolved;
            // Zero the rel32 displacement fields before appending.
            for r in &recovery.relocs {
                let off = r.offset as usize;
                if off + 4 <= fn_bytes.len() {
                    fn_bytes[off..off + 4].fill(0);
                }
            }
            recovery.relocs
        } else {
            vec![]
        };

        let fn_offset = obj.append_section_data(text_sid, &fn_bytes, 4);

        // Emit the function symbol.
        let scope = if f.external {
            SymbolScope::Dynamic
        } else {
            SymbolScope::Compilation
        };
        let sym_name = sanitize_symbol_name(f.symbol_name());
        let sym_id = obj.add_symbol(Symbol {
            name: sym_name.clone(),
            value: fn_offset,
            size: f.size,
            kind: SymbolKind::Text,
            scope,
            weak: false,
            section: SymbolSection::Section(text_sid),
            flags: SymbolFlags::None,
        });
        local_syms.insert(f.symbol_name().to_string(), sym_id);

        // Emit variable labels that fall inside this function.
        for (var_va, var) in ctx.symbols.variables.range(f.addr..f.addr + f.size) {
            if *var_va == f.addr {
                continue;
            }
            let label_scope = if var.external {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Compilation
            };
            let label_id = obj.add_symbol(Symbol {
                name: sanitize_symbol_name(var.symbol_name()),
                value: fn_offset + (var_va - f.addr),
                size: 0,
                kind: SymbolKind::Label,
                scope: label_scope,
                weak: false,
                section: SymbolSection::Section(text_sid),
                flags: SymbolFlags::None,
            });
            local_syms.insert(var.symbol_name().to_string(), label_id);
        }

        // Emit synthetic relocations (x86 only).
        for r in &relocs_to_emit {
            let sym_id = resolve_symbol(&mut obj, &local_syms, &mut undef_cache, &r.target);
            obj.add_relocation(
                text_sid,
                Relocation {
                    offset: fn_offset + r.offset,
                    symbol: sym_id,
                    // Mach-O i386 uses implicit addends; the object crate adds
                    // `addend` to whatever is already in the section bytes.
                    // Since we zeroed the field above, embedded = addend.
                    addend: r.addend,
                    flags: RelocationFlags::MachO {
                        r_type: GENERIC_RELOC_VANILLA,
                        r_pcrel: true,
                        r_length: R_LENGTH_4,
                    },
                },
            )
            .with_context(|| format!("add reloc at {:#x} → '{}'", f.addr + r.offset, r.target))?;
            stats.relocations += 1;
        }
    }

    stats.local_symbols = local_syms.len();
    stats.undef_symbols = undef_cache.len();

    let bytes = obj.write().context("serialize Mach-O object")?;
    write_file(out_path, &bytes)?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Shared data emit
// ---------------------------------------------------------------------------

pub fn emit_macho_shared(ctx: &MachoContext, out_path: &Path) -> Result<SharedDataStats> {
    let (macho_arch, endianness) = arch_to_object(ctx.arch);
    let mut obj = Object::new(BinaryFormat::MachO, macho_arch, endianness);
    let mut stats = SharedDataStats::default();

    // Track (section_id, section_va, section_size) for each data section added.
    let mut data_slots: Vec<(object::write::SectionId, u64, u64)> = Vec::new();

    if let Some(s) = ctx
        .sections
        .iter()
        .find(|s| s.segment == "__DATA" && s.name == "__data")
    {
        let sid = obj.add_section(b"__DATA".to_vec(), b"__data".to_vec(), SectionKind::Data);
        obj.append_section_data(sid, &s.data, 16);
        obj.add_symbol(Symbol {
            name: SYM_DATA_START.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(sid),
            flags: SymbolFlags::None,
        });
        data_slots.push((sid, s.addr, s.size));
        stats.data_bytes = s.size;
    }

    if let Some(s) = ctx
        .sections
        .iter()
        .find(|s| s.segment == "__DATA" && s.name == "__const")
    {
        let sid = obj.add_section(
            b"__DATA".to_vec(),
            b"__const".to_vec(),
            SectionKind::ReadOnlyData,
        );
        obj.append_section_data(sid, &s.data, 16);
        obj.add_symbol(Symbol {
            name: SYM_CONST_START.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(sid),
            flags: SymbolFlags::None,
        });
        data_slots.push((sid, s.addr, s.size));
        stats.const_bytes = s.size;
    }

    if let Some(s) = ctx
        .sections
        .iter()
        .find(|s| s.segment == "__DATA" && s.name == "__bss")
    {
        let sid = obj.add_section(
            b"__DATA".to_vec(),
            b"__bss".to_vec(),
            SectionKind::UninitializedData,
        );
        obj.section_mut(sid).append_bss(s.size, 16);
        obj.add_symbol(Symbol {
            name: SYM_BSS_START.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(sid),
            flags: SymbolFlags::None,
        });
        data_slots.push((sid, s.addr, s.size));
        stats.bss_bytes = s.size;
    }

    // Emit named variables into whichever data section contains their address.
    for (var_va, var) in &ctx.symbols.variables {
        for &(sid, sec_addr, sec_size) in &data_slots {
            if *var_va >= sec_addr && *var_va < sec_addr + sec_size {
                let offset = var_va - sec_addr;
                let scope = if var.external {
                    SymbolScope::Dynamic
                } else {
                    SymbolScope::Compilation
                };
                obj.add_symbol(Symbol {
                    name: sanitize_symbol_name(var.symbol_name()),
                    value: offset,
                    size: 0,
                    kind: SymbolKind::Data,
                    scope,
                    weak: false,
                    section: SymbolSection::Section(sid),
                    flags: SymbolFlags::None,
                });
                break;
            }
        }
    }

    let bytes = obj.write().context("serialize shared Mach-O object")?;
    write_file(out_path, &bytes)?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Symtab-driven split
// ---------------------------------------------------------------------------

/// Split driven by a user-editable `SymtabJson`.
///
/// Functions that share the same `cu` field are emitted into one object file
/// whose name is exactly that `cu` value.  The output path for each file is
/// `out_dir/<cu>`.
pub fn split_by_symtab(
    ctx: &MachoContext,
    symtab: &crate::symtab_json::SymtabJson,
    lookup: &crate::symtab_json::SymtabLookup,
    out_dir: &Path,
) -> Result<Vec<CuOutcome>> {
    use crate::cu::{MachoCompilationUnit, MachoFunction};

    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let group_vec: Vec<(&String, &Vec<String>)> = symtab.iter().collect();

    let outcomes: Vec<CuOutcome> = group_vec
        .par_iter()
        .enumerate()
        .map(|(id, (cu_filename, names))| {
            let mut resolved: Vec<(String, u64, u64, bool)> = names
                .iter()
                .filter_map(|name| {
                    lookup
                        .get(name.as_str())
                        .map(|info| (name.clone(), info.addr, info.size, info.external))
                })
                .collect();
            resolved.sort_by_key(|(_, addr, _, _)| *addr);

            let functions: Vec<MachoFunction> = resolved
                .iter()
                .map(|(name, addr, size, external)| MachoFunction {
                    name: name.clone(),
                    linkage_name: Some(name.clone()),
                    addr: *addr,
                    size: *size,
                    external: *external,
                })
                .collect();

            let ranges = functions
                .iter()
                .filter(|f| f.size > 0)
                .map(|f| f.addr..f.addr + f.size)
                .collect();

            let cu = MachoCompilationUnit {
                id,
                name: cu_filename
                    .strip_suffix(".o")
                    .unwrap_or(cu_filename)
                    .to_string(),
                comp_dir: None,
                oso_path: None,
                ranges,
                functions,
                variables: vec![],
            };

            // Use the cu field value directly as the output filename.
            let file = out_dir.join(cu_filename);
            let result = emit_macho_cu(ctx, &cu, &file).map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_id: id,
                cu_name: cu_filename.to_string(),
                file,
                result,
            }
        })
        .collect();

    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Parallel split (DWARF/STABS CU-based)
// ---------------------------------------------------------------------------

pub fn split_all_macho(ctx: &MachoContext, out_dir: &Path) -> Result<Vec<CuOutcome>> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let outcomes: Vec<CuOutcome> = ctx
        .cu_index
        .units
        .par_iter()
        .filter(|cu| cu.functions.iter().any(|f| f.size > 0))
        .map(|cu| {
            let stem = sanitize_file_stem(&cu.name);
            let file = out_dir.join(format!("{:04}_{stem}.o", cu.id));
            let result = emit_macho_cu(ctx, cu, &file).map_err(|e| format!("{e:#}"));
            CuOutcome {
                cu_id: cu.id,
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
    let id = obj.add_symbol(Symbol {
        name: sanitize_symbol_name(name),
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

fn sanitize_symbol_name(name: &str) -> Vec<u8> {
    if name.is_empty() {
        return b"<invalid>".to_vec();
    }
    name.as_bytes().to_vec()
}

fn sanitize_file_stem(name: &str) -> String {
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = match basename.rfind('.') {
        Some(i) => &basename[..i],
        None => basename,
    };
    // Replace characters that are invalid in filenames.
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

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn arch_to_object(arch: MachoArch) -> (Architecture, Endianness) {
    match arch {
        MachoArch::X86 => (Architecture::I386, Endianness::Little),
        MachoArch::X86_64 => (Architecture::X86_64, Endianness::Little),
        MachoArch::PPC => (Architecture::PowerPc, Endianness::Big),
        MachoArch::PPC64 => (Architecture::PowerPc64, Endianness::Big),
    }
}
