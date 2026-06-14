//! PDB-based compilation-unit indexing.
//!
//! Walks PDB modules and section contributions to build a `PeCuIndex`
//! mirroring the ELF/DWARF `CuIndex` in `delink-core`.

use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::collections::{BTreeMap, HashMap};

use crate::{PeArch, PeSection};

// CV calling convention code for __stdcall (near standard call, callee cleans stack).
const CV_CALL_NEAR_STD: u8 = 0x07;

#[derive(Debug, Clone)]
pub struct PeFunction {
    pub name: String,
    pub va: u64,
    pub size: u32,
    /// True for `S_GPROC32` (global) vs `S_LPROC32` (local).
    pub is_public: bool,
    pub module_id: usize,
}

/// A global or static data variable extracted from the PDB.
#[derive(Debug, Clone)]
pub struct PeVariable {
    pub name: String,
    pub va: u64,
    /// True for `S_GDATA32` (global) vs `S_LDATA32` (file-static).
    pub is_public: bool,
}

/// A byte range of a PE section that belongs to one PDB module.
#[derive(Debug, Clone)]
pub struct PeContrib {
    /// Absolute VA of the contribution start.
    pub va: u64,
    /// Byte count.
    pub size: u32,
    /// PE section name (e.g. ".text", ".rdata").
    pub section_name: String,
    /// Section characteristics from the PDB contribution record.
    /// Reflects the original object-file section flags (before linker merging),
    /// so IMAGE_SCN_CNT_UNINITIALIZED_DATA is preserved even for contributions
    /// that the linker merged into the PE's .data section.
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeCompilationUnit {
    pub id: usize,
    /// PDB module name (typically the full path of the original .obj file).
    pub name: String,
    /// Object file that was linked (may equal `name`).
    pub obj_file: String,
    pub functions: Vec<PeFunction>,
    /// Section contributions — which ranges of PE sections this module owns.
    pub contributions: Vec<PeContrib>,
}

impl PeCompilationUnit {
    /// True if this module contributed any bytes to the `.text` section.
    pub fn has_text(&self) -> bool {
        self.contributions.iter().any(|c| c.section_name == ".text")
    }

    /// Total byte count of `.text` contributions.
    pub fn text_size(&self) -> u64 {
        self.contributions
            .iter()
            .filter(|c| c.section_name == ".text")
            .map(|c| c.size as u64)
            .sum()
    }
}

pub struct PeCuIndex {
    pub units: Vec<PeCompilationUnit>,
}

type CuIndexResult = (
    PeCuIndex,
    BTreeMap<u64, PeFunction>,
    BTreeMap<u64, PeVariable>,
);

/// Parse a PDB and return `(CuIndex, all_functions_by_VA, all_variables_by_VA)`.
///
/// `image_base` is from the PE optional header; `sections` are the PE
/// sections (needed to look up section names for contributions).
pub fn build_cu_index(
    pdb_data: &[u8],
    image_base: u64,
    sections: &[PeSection],
    arch: PeArch,
) -> Result<CuIndexResult> {
    let cursor = std::io::Cursor::new(pdb_data);
    let mut pdb = pdb::PDB::open(cursor).context("open PDB")?;

    // For x86 32-bit binaries, local (static) functions with __stdcall calling
    // convention may not appear in the public symbols stream with their decorated
    // name (_funcname@N).  Pre-compute a map from procedure TypeIndex to the
    // total bytes of parameters so we can reconstruct the mangled name later.
    let stdcall_param_bytes: HashMap<pdb::TypeIndex, u32> = {
        let mut map = HashMap::new();
        if matches!(arch, PeArch::X86) {
            if let Ok(type_information) = pdb.type_information() {
                let mut type_finder = type_information.finder();
                let mut iter = type_information.iter();
                while let Ok(Some(typ)) = iter.next() {
                    type_finder.update(&iter);
                    if let Ok(pdb::TypeData::Procedure(proc)) = typ.parse() {
                        if proc.attributes.calling_convention() == CV_CALL_NEAR_STD {
                            let bytes = x86_proc_param_bytes(&type_finder, proc.argument_list);
                            map.insert(typ.index(), bytes);
                        }
                    }
                }
            }
        }
        map
    };

    let dbi = pdb.debug_information().context("PDB debug information")?;
    let address_map = pdb.address_map().context("PDB address map")?;

    // --- Build VA → mangled name from the public symbols stream ---
    // Public symbols (S_PUB32) carry decorated/mangled names for both
    // functions and data; we prefer these over the undecorated module names.
    // Data-typed public symbols (not code, not function) are also collected
    // separately so they can fill gaps where no S_GDATA32/S_LDATA32 exists.
    let mut mangled_by_va: HashMap<u64, String> = HashMap::new();
    let mut public_data_by_va: HashMap<u64, String> = HashMap::new();
    {
        let global_syms = pdb.global_symbols().context("PDB global symbols")?;
        let mut iter = global_syms.iter();
        while let Some(sym) = iter.next()? {
            if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
                if let Some(rva) = p.offset.to_rva(&address_map) {
                    let va = image_base + rva.0 as u64;
                    let name = p.name.to_string().into_owned();
                    mangled_by_va.insert(va, name.clone());
                    if !p.function && !p.code {
                        public_data_by_va.insert(va, name);
                    }
                }
            }
        }
    }

    // --- Collect section contributions per module (0-based module index) ---
    let mut module_contribs: HashMap<usize, Vec<(u64, u32, u32)>> = HashMap::new();
    {
        let mut sc_iter = dbi
            .section_contributions()
            .context("section contributions")?;
        while let Some(sc) = sc_iter.next()? {
            let Some(rva) = sc.offset.to_rva(&address_map) else {
                continue;
            };
            module_contribs.entry(sc.module).or_default().push((
                rva.0 as u64,
                sc.size,
                sc.characteristics.0,
            ));
        }
    }

    // --- Walk modules ---
    let mut units: Vec<PeCompilationUnit> = Vec::new();
    let mut all_functions: BTreeMap<u64, PeFunction> = BTreeMap::new();
    let mut all_variables: BTreeMap<u64, PeVariable> = BTreeMap::new();
    let mut cu_id = 0usize;
    let mut mod_index = 0usize;

    let mut mod_iter = dbi.modules().context("PDB modules")?;
    while let Some(module) = mod_iter.next()? {
        let mod_name = module.module_name().to_string();
        let obj_file = module.object_file_name().to_string();

        let mut functions: Vec<PeFunction> = Vec::new();

        if let Some(mod_info) = pdb.module_info(&module).context("module info")? {
            let mut sym_iter = mod_info.symbols().context("module symbols")?;
            while let Some(sym) = sym_iter.next()? {
                match sym.parse() {
                    Ok(pdb::SymbolData::Procedure(p)) => {
                        let Some(rva) = p.offset.to_rva(&address_map) else {
                            continue;
                        };
                        if rva.0 == 0 || p.len == 0 {
                            continue;
                        }
                        let va = image_base + rva.0 as u64;
                        let name = mangled_by_va.get(&va).cloned().unwrap_or_else(|| {
                            let raw = p.name.to_string().into_owned();
                            // For x86 __stdcall, restore the _name@N decoration that the
                            // public symbols stream would normally carry but may be absent
                            // for local (static) functions.
                            if let Some(&param_bytes) = stdcall_param_bytes.get(&p.type_index) {
                                format!("_{raw}@{param_bytes}")
                            } else {
                                raw
                            }
                        });
                        let f = PeFunction {
                            name,
                            va,
                            size: p.len,
                            is_public: p.global,
                            module_id: cu_id,
                        };
                        all_functions.entry(va).or_insert_with(|| f.clone());
                        functions.push(f);
                    }
                    Ok(pdb::SymbolData::Data(d)) => {
                        let Some(rva) = d.offset.to_rva(&address_map) else {
                            continue;
                        };
                        if rva.0 == 0 {
                            continue;
                        }
                        let va = image_base + rva.0 as u64;
                        let name = mangled_by_va.get(&va).cloned().unwrap_or_else(|| {
                            x86_c_data_name(d.name.to_string().into_owned(), arch)
                        });
                        let v = PeVariable {
                            name,
                            va,
                            is_public: d.global,
                        };
                        all_variables.entry(va).or_insert_with(|| v);
                    }
                    Ok(pdb::SymbolData::Label(l)) => {
                        let Some(rva) = l.offset.to_rva(&address_map) else {
                            continue;
                        };
                        if rva.0 == 0 {
                            continue;
                        }
                        let va = image_base + rva.0 as u64;
                        let name = mangled_by_va.get(&va).cloned().unwrap_or_else(|| {
                            x86_c_data_name(l.name.to_string().into_owned(), arch)
                        });
                        all_variables.entry(va).or_insert_with(|| PeVariable {
                            name,
                            va,
                            is_public: false,
                        });
                    }
                    _ => {}
                }
            }
        }

        // Build contributions for this module.
        let contributions: Vec<PeContrib> = module_contribs
            .get(&mod_index)
            .map(|cs| {
                cs.iter()
                    .map(|&(rva, size, characteristics)| {
                        let va = image_base + rva;
                        let section_name = section_name_for_va(sections, va);
                        PeContrib {
                            va,
                            size,
                            section_name,
                            characteristics,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Only keep modules that have code or data contributions.
        if !functions.is_empty() || !contributions.is_empty() {
            units.push(PeCompilationUnit {
                id: cu_id,
                name: mod_name,
                obj_file,
                functions,
                contributions,
            });
            cu_id += 1;
        }

        mod_index += 1;
    }

    // Add public data symbols as fallbacks for any VA not already covered by a
    // module-level S_GDATA32, S_LDATA32, or S_LABEL32 entry.  These are symbols
    // that appear only in the global stream and have no per-module record.
    for (va, name) in public_data_by_va {
        all_variables.entry(va).or_insert_with(|| PeVariable {
            name,
            va,
            is_public: true,
        });
    }

    Ok((PeCuIndex { units }, all_functions, all_variables))
}

fn section_name_for_va(sections: &[PeSection], va: u64) -> String {
    sections
        .iter()
        .find(|s| s.contains_va(va))
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "?".to_string())
}

// ---------------------------------------------------------------------------
// x86 __stdcall parameter-size helpers
// ---------------------------------------------------------------------------

/// Apply the x86 C-name underscore prefix to a data symbol that was not found in
/// the public symbols stream.  On x86, the linker prefixes every C identifier
/// with `_`; the PDB module-level records store the undecorated source name.
fn x86_c_data_name(raw: String, arch: PeArch) -> String {
    if matches!(arch, PeArch::X86) {
        format!("_{raw}")
    } else {
        raw
    }
}

/// Sum the stack bytes consumed by every parameter in `arg_list` on x86.
fn x86_proc_param_bytes(type_finder: &pdb::TypeFinder<'_>, arg_list: pdb::TypeIndex) -> u32 {
    let Ok(type_ref) = type_finder.find(arg_list) else {
        return 0;
    };
    let Ok(pdb::TypeData::ArgumentList(args)) = type_ref.parse() else {
        return 0;
    };
    args.arguments
        .iter()
        .map(|&idx| x86_type_stack_bytes(type_finder, idx))
        .sum()
}

/// Bytes a single parameter type occupies on the x86 stack (minimum 4, aligned to 4).
fn x86_type_stack_bytes(type_finder: &pdb::TypeFinder<'_>, type_idx: pdb::TypeIndex) -> u32 {
    let Ok(type_ref) = type_finder.find(type_idx) else {
        return 4;
    };
    match type_ref.parse() {
        Ok(pdb::TypeData::Primitive(p)) => {
            if p.indirection.is_some() {
                4 // x86 pointer = 4 bytes
            } else {
                x86_primitive_stack_bytes(p.kind)
            }
        }
        Ok(pdb::TypeData::Pointer(_)) => 4,
        Ok(pdb::TypeData::Class(c)) => align4(c.size as u32),
        Ok(pdb::TypeData::Union(u)) => align4(u.size as u32),
        Ok(pdb::TypeData::Modifier(m)) => x86_type_stack_bytes(type_finder, m.underlying_type),
        Ok(pdb::TypeData::Enumeration(e)) => x86_type_stack_bytes(type_finder, e.underlying_type),
        Ok(pdb::TypeData::Bitfield(b)) => x86_type_stack_bytes(type_finder, b.underlying_type),
        _ => 4,
    }
}

fn align4(n: u32) -> u32 {
    (n + 3) & !3
}

fn x86_primitive_stack_bytes(kind: pdb::PrimitiveKind) -> u32 {
    use pdb::PrimitiveKind::*;
    match kind {
        NoType | Void => 0,
        // 8-bit and 16-bit types are sign/zero-extended and pushed as DWORDs.
        I8 | U8 | Char | UChar | RChar | Bool8 => 4,
        I16 | U16 | Short | UShort | WChar | RChar16 | Bool16 | F16 => 4,
        // 32-bit types.
        I32 | U32 | Long | ULong | RChar32 | F32 | F32PP | Bool32 | HRESULT => 4,
        // 64-bit types.
        I64 | U64 | Quad | UQuad | F64 | Bool64 => 8,
        // 80-bit float (10 bytes on x87), padded to next DWORD = 12.
        F80 => 12,
        // 48-bit float (6 bytes, Turbo Pascal), padded to 8.
        F48 => 8,
        // 128-bit types.
        I128 | U128 | Octa | UOcta | F128 => 16,
        // Complex types: 2 × their component width.
        Complex32 => 4,
        Complex64 => 8,
        Complex80 => 12,
        Complex128 => 16,
        _ => 4,
    }
}
