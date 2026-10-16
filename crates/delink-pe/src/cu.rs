//! PDB-based compilation-unit indexing.
//!
//! Walks PDB modules and section contributions to build a `PeCuIndex`
//! mirroring the ELF/DWARF `CuIndex` in `delink-core`.

use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{PeArch, PeSection};

// CV calling convention code for __stdcall (near standard call, callee cleans stack).
const CV_CALL_NEAR_STD: u8 = 0x07;

// CodeView `S_FRAMEPROC` record (0x1012): extra frame/proc information emitted
// immediately after each procedure symbol. Its 32-bit flags word carries
// `fInlSpec` (bit 5) = "function was declared inline" — the same signal
// pdb-decompiler uses to prefix functions with its `_inline` macro.
//
// Within `Symbol::raw_bytes()` (record type included, length prefix excluded)
// the flags word sits at byte offset 24:
//   [0..2] rectyp │ [2..6] cbFrame │ [6..10] cbPad │ [10..14] offPad
//   [14..18] cbSaveRegs │ [18..22] offExHdlr │ [22..24] sectExHdlr │ [24..28] flags
const S_FRAMEPROC: u16 = 0x1012;
const FRAMEPROC_FLAGS_OFFSET: usize = 24;
const FRAMEPROC_INLINE_SPEC: u32 = 1 << 5;

/// Test the `fInlSpec` (declared-inline) bit of an `S_FRAMEPROC` record's flags word.
fn frameproc_declared_inline(raw: &[u8]) -> bool {
    raw.get(FRAMEPROC_FLAGS_OFFSET..FRAMEPROC_FLAGS_OFFSET + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) & FRAMEPROC_INLINE_SPEC != 0)
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct PeFunction {
    pub name: String,
    pub va: u64,
    pub size: u32,
    /// True for `S_GPROC32` (global) vs `S_LPROC32` (local).
    pub is_public: bool,
    pub module_id: usize,
    /// Additional public (S_PUB32) names at the same VA (e.g. the linker folded
    /// `??_E`/`??_G` deleting destructors into one body). Emitted as extra
    /// defined symbols at the same section offset so both names link.
    pub aliases: Vec<String>,
}

/// A global or static data variable extracted from the PDB.
#[derive(Debug, Clone)]
pub struct PeVariable {
    pub name: String,
    pub va: u64,
    /// True for `S_GDATA32` (global) vs `S_LDATA32` (file-static).
    pub is_public: bool,
    /// Byte size from the PDB type, or 0 if unknown. Used to resolve interior
    /// references (e.g. `async_globals+0x2ca8` into a struct global).
    pub size: u32,
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
    BTreeMap<u32, String>,
    BTreeMap<u64, String>,
    Vec<String>,
);

/// Parse a PDB and return
/// `(CuIndex, all_functions_by_VA, all_variables_by_VA, inlined_function_names)`.
///
/// `inlined_function_names` are the mangled names of every procedure whose
/// `S_FRAMEPROC` record marks it as declared inline (`fInlSpec`), sorted and
/// de-duplicated.
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
    // Build a fully-populated type finder (used to size data globals so interior
    // references resolve, and on x86 to reconstruct __stdcall param bytes).
    let type_information = pdb.type_information().ok();
    let mut type_finder = type_information.as_ref().map(|ti| ti.finder());
    let mut stdcall_param_bytes: HashMap<pdb::TypeIndex, u32> = HashMap::new();
    // Complete class/union sizes keyed by mangled unique name, so a forward
    // reference (size 0) on a data global's type can be resolved to the real
    // definition and its interior references bounded correctly.
    let mut udt_sizes: HashMap<String, u32> = HashMap::new();
    if let (Some(ti), Some(finder)) = (type_information.as_ref(), type_finder.as_mut()) {
        let mut iter = ti.iter();
        while let Ok(Some(typ)) = iter.next() {
            finder.update(&iter);
            match typ.parse() {
                Ok(pdb::TypeData::Procedure(proc)) if matches!(arch, PeArch::X86) => {
                    if proc.attributes.calling_convention() == CV_CALL_NEAR_STD {
                        let bytes = x86_proc_param_bytes(finder, proc.argument_list);
                        stdcall_param_bytes.insert(typ.index(), bytes);
                    }
                }
                Ok(pdb::TypeData::Class(c)) if !c.properties.forward_reference() && c.size > 0 => {
                    if let Some(un) = c.unique_name {
                        udt_sizes.insert(un.to_string().into_owned(), c.size as u32);
                    }
                }
                Ok(pdb::TypeData::Union(u)) if !u.properties.forward_reference() && u.size > 0 => {
                    if let Some(un) = u.unique_name {
                        udt_sizes.insert(un.to_string().into_owned(), u.size as u32);
                    }
                }
                _ => {}
            }
        }
    }
    // Immutable views for the data-sizing lookups below.
    let type_finder = type_finder;

    let dbi = pdb.debug_information().context("PDB debug information")?;
    let address_map = pdb.address_map().context("PDB address map")?;

    // --- Build VA → mangled name from the public symbols stream ---
    // Public symbols (S_PUB32) carry decorated/mangled names for both
    // functions and data; we prefer these over the undecorated module names.
    // Data-typed public symbols (not code, not function) are also collected
    // separately so they can fill gaps where no S_GDATA32/S_LDATA32 exists.
    let mut mangled_by_va: HashMap<u64, String> = HashMap::new();
    // Extra public names sharing a VA with the primary (identical-COMDAT-folded
    // functions, e.g. `??_E`/`??_G` deleting destructors). Last public in the
    // stream becomes primary; earlier ones become alias symbols on the function.
    let mut public_aliases_by_va: HashMap<u64, Vec<String>> = HashMap::new();
    let mut public_data_by_va: HashMap<u64, String> = HashMap::new();
    // Public code symbols with no per-module procedure record (statically-linked
    // CRT helpers like `memcpy`), so call targets into them still resolve.
    let mut public_code_by_va: HashMap<u64, String> = HashMap::new();
    // Thread-local variables: `.tls` section-relative offset → mangled name,
    // used to recover SECREL relocations on `mov r32, <tls-offset>` loads.
    // Global TLS (`S_GTHREAD32`) lives in the global stream; file-static TLS
    // (`S_LTHREAD32`) is collected from the module streams below.
    let mut tls_variables: BTreeMap<u32, String> = BTreeMap::new();
    {
        // Public (S_PUB32) names, keyed by section:offset, so a TLS variable's
        // ThreadStorage record (which carries the undecorated name) can be paired
        // with the decorated/mangled public name that the code actually references.
        let mut pub_by_secoff: HashMap<(u16, u32), String> = HashMap::new();
        let mut tls_pending: Vec<(u16, u32, String)> = Vec::new();
        let global_syms = pdb.global_symbols().context("PDB global symbols")?;
        let mut iter = global_syms.iter();
        while let Some(sym) = iter.next().context("global symbols")? {
            match sym.parse() {
                Ok(pdb::SymbolData::Public(p)) => {
                    let name = p.name.to_string().into_owned();
                    pub_by_secoff
                        .entry((p.offset.section, p.offset.offset))
                        .or_insert_with(|| name.clone());
                    if let Some(rva) = p.offset.to_rva(&address_map) {
                        let va = image_base + rva.0 as u64;
                        match mangled_by_va.get_mut(&va) {
                            Some(primary) if *primary != name => {
                                let old = std::mem::replace(primary, name.clone());
                                let aliases = public_aliases_by_va.entry(va).or_default();
                                aliases.retain(|a| *a != name);
                                if !aliases.contains(&old) {
                                    aliases.push(old);
                                }
                            }
                            Some(_) => {}
                            None => {
                                mangled_by_va.insert(va, name.clone());
                            }
                        }
                        // VC6 leaves the public flags at zero, so fall back to
                        // whether the symbol sits in an executable section.
                        if p.function || p.code || section_is_code(sections, va) {
                            public_code_by_va.insert(va, name);
                        } else {
                            public_data_by_va.insert(va, name);
                        }
                    }
                }
                Ok(pdb::SymbolData::ThreadStorage(t)) => {
                    tls_pending.push((
                        t.offset.section,
                        t.offset.offset,
                        t.name.to_string().into_owned(),
                    ));
                }
                _ => {}
            }
        }
        for (section, offset, fallback) in tls_pending {
            let name = pub_by_secoff
                .get(&(section, offset))
                .cloned()
                .unwrap_or(fallback);
            tls_variables.entry(offset).or_insert(name);
        }
    }

    // --- Collect section contributions per module (0-based module index) ---
    let mut module_contribs: HashMap<usize, Vec<(u64, u32, u32)>> = HashMap::new();
    {
        let mut sc_iter = dbi
            .section_contributions()
            .context("section contributions")?;
        while let Some(sc) = sc_iter.next().context("section contributions")? {
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
    let mut inlined_functions: BTreeSet<String> = BTreeSet::new();
    let mut cu_id = 0usize;
    let mut mod_index = 0usize;
    let public_code_starts: BTreeMap<u64, String> = public_code_by_va
        .iter()
        .map(|(va, name)| (*va, name.clone()))
        .collect();

    let mut mod_iter = dbi.modules().context("PDB modules")?;
    while let Some(module) = mod_iter.next().context("PDB modules")? {
        let mod_name = module.module_name().to_string();
        let obj_file = module.object_file_name().to_string();

        let mut functions: Vec<PeFunction> = Vec::new();

        if let Some(mod_info) = pdb.module_info(&module).context("module info")? {
            // Mangled name of the procedure currently in scope, so the
            // `S_FRAMEPROC` record that follows it can be attributed correctly.
            let mut current_proc_name: Option<String> = None;
            let mut sym_iter = mod_info.symbols().context("module symbols")?;
            while let Some(sym) = sym_iter.next().context("module symbols")? {
                // `S_FRAMEPROC` isn't parsed by the `pdb` crate; read its flags
                // from the raw record and mark the enclosing procedure inline.
                if sym.raw_kind() == S_FRAMEPROC {
                    if let Some(name) = &current_proc_name {
                        if frameproc_declared_inline(sym.raw_bytes()) {
                            inlined_functions.insert(name.clone());
                        }
                    }
                    continue;
                }
                match sym.parse() {
                    Ok(pdb::SymbolData::Procedure(p)) => {
                        // A new procedure scope begins; clear until validated.
                        current_proc_name = None;
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
                        current_proc_name = Some(name.clone());
                        let f = PeFunction {
                            name,
                            va,
                            size: p.len,
                            is_public: p.global,
                            module_id: cu_id,
                            aliases: public_aliases_by_va.get(&va).cloned().unwrap_or_default(),
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
                        let size = type_finder
                            .as_ref()
                            .map(|f| type_byte_size(f, d.type_index, arch, &udt_sizes))
                            .unwrap_or(0);
                        let v = PeVariable {
                            name,
                            va,
                            is_public: d.global,
                            size,
                        };
                        all_variables.entry(va).or_insert_with(|| v);
                    }
                    Ok(pdb::SymbolData::ThreadStorage(t)) => {
                        // TLS variables live in `.tls`; key by the section-relative
                        // offset, which is exactly the SECREL value the linker bakes
                        // into `mov r32, <tls-offset>`.
                        let name = t.name.to_string().into_owned();
                        tls_variables.entry(t.offset.offset).or_insert(name);
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
                            size: 0,
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

        if functions.is_empty() {
            functions = functions_from_contributions(
                &contributions,
                &public_code_starts,
                &public_aliases_by_va,
                cu_id,
            );
            for f in &functions {
                all_functions.entry(f.va).or_insert_with(|| f.clone());
            }
        }

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
            size: 0,
        });
    }

    // Public code symbols with no procedure record (e.g. statically-linked CRT
    // routines), keyed by VA, for resolve_code call-target fallback.
    let code_publics: BTreeMap<u64, String> = public_code_by_va
        .into_iter()
        .filter(|(va, _)| !all_functions.contains_key(va))
        .collect();

    Ok((
        PeCuIndex { units },
        all_functions,
        all_variables,
        tls_variables,
        code_publics,
        inlined_functions.into_iter().collect(),
    ))
}

/// `IMAGE_SCN_CNT_CODE` | `IMAGE_SCN_MEM_EXECUTE`.
const SECTION_CODE: u32 = 0x0000_0020 | 0x2000_0000;

fn section_is_code(sections: &[PeSection], va: u64) -> bool {
    sections
        .iter()
        .any(|s| s.contains_va(va) && s.characteristics & SECTION_CODE != 0)
}

/// Functions of a module whose symbol stream has no procedure records, which is
/// what a module compiled without full debug info looks like (e.g. the VC6-era
/// Xbox build of the Halo beta).
///
/// Every `.text` contribution starts a function (function-level linking gives
/// each function its own), and so does every public code symbol inside one. A
/// function runs to the next start or to the end of its contribution. A start
/// with no public name is a file-static function and is named `_sub_<VA>`.
fn functions_from_contributions(
    contributions: &[PeContrib],
    public_code: &BTreeMap<u64, String>,
    aliases: &HashMap<u64, Vec<String>>,
    module_id: usize,
) -> Vec<PeFunction> {
    let mut functions = Vec::new();
    for c in contributions
        .iter()
        .filter(|c| c.section_name == ".text" && c.size > 0)
    {
        let end = c.va + c.size as u64;
        let starts: Vec<u64> = std::iter::once(c.va)
            .chain(public_code.range(c.va + 1..end).map(|(va, _)| *va))
            .collect();
        for (i, &va) in starts.iter().enumerate() {
            let next = starts.get(i + 1).copied().unwrap_or(end);
            let (name, is_public) = match public_code.get(&va) {
                Some(name) => (name.clone(), true),
                None => (format!("_sub_{va:08X}"), false),
            };
            functions.push(PeFunction {
                name,
                va,
                size: (next - va) as u32,
                is_public,
                module_id,
                aliases: aliases.get(&va).cloned().unwrap_or_default(),
            });
        }
    }
    functions
}

fn section_name_for_va(sections: &[PeSection], va: u64) -> String {
    sections
        .iter()
        .find(|s| s.contains_va(va))
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "?".to_string())
}

// ---------------------------------------------------------------------------
// Data type sizing
// ---------------------------------------------------------------------------

/// Byte size of a PDB type, for bounding interior references into data globals.
/// Returns 0 when unknown (interior resolution is then skipped).
fn type_byte_size(
    finder: &pdb::TypeFinder<'_>,
    idx: pdb::TypeIndex,
    arch: PeArch,
    udt_sizes: &HashMap<String, u32>,
) -> u32 {
    let ptr = if matches!(arch, PeArch::X86) { 4 } else { 8 };
    let Ok(t) = finder.find(idx) else {
        return 0;
    };
    // A forward-referenced class/union has size 0; recover it from the complete
    // definition collected by unique name.
    let complete = |size: u64, name: Option<pdb::RawString<'_>>| -> u32 {
        if size > 0 {
            size as u32
        } else {
            name.and_then(|n| udt_sizes.get(&n.to_string().into_owned()).copied())
                .unwrap_or(0)
        }
    };
    match t.parse() {
        Ok(pdb::TypeData::Class(c)) => complete(c.size, c.unique_name),
        Ok(pdb::TypeData::Union(u)) => complete(u.size, u.unique_name),
        // Dimensions are cumulative byte sizes; the last is the whole array.
        Ok(pdb::TypeData::Array(a)) => a.dimensions.last().copied().unwrap_or(0),
        Ok(pdb::TypeData::Pointer(_)) => ptr,
        Ok(pdb::TypeData::Primitive(p)) => {
            if p.indirection.is_some() {
                ptr
            } else {
                primitive_byte_size(p.kind)
            }
        }
        Ok(pdb::TypeData::Enumeration(e)) => {
            type_byte_size(finder, e.underlying_type, arch, udt_sizes)
        }
        Ok(pdb::TypeData::Modifier(m)) => {
            type_byte_size(finder, m.underlying_type, arch, udt_sizes)
        }
        Ok(pdb::TypeData::Bitfield(b)) => {
            type_byte_size(finder, b.underlying_type, arch, udt_sizes)
        }
        _ => 0,
    }
}

/// True byte size of a primitive type (unlike the stack-slot size below).
fn primitive_byte_size(kind: pdb::PrimitiveKind) -> u32 {
    use pdb::PrimitiveKind::*;
    match kind {
        I8 | U8 | Char | UChar | RChar | Bool8 => 1,
        I16 | U16 | Short | UShort | WChar | RChar16 | Bool16 | F16 => 2,
        I32 | U32 | Long | ULong | RChar32 | F32 | F32PP | Bool32 | HRESULT => 4,
        I64 | U64 | Quad | UQuad | F64 | Bool64 => 8,
        F80 => 10,
        I128 | U128 | Octa | UOcta | F128 => 16,
        _ => 0,
    }
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
