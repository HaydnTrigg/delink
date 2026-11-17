//! Debug information carried inside the PE image itself, for images that ship
//! without a PDB.
//!
//! GNU toolchains (MinGW) don't produce PDBs. They embed DWARF in `.debug_*`
//! sections (stored under COFF long names) and leave the COFF symbol table in
//! the image. Either one is enough to split from:
//!
//! * **DWARF** gives exact compilation units, but only for the objects that
//!   were compiled with `-g`; a library built with `-g1` or partial debug info
//!   covers a sliver of the code.
//! * **The COFF symbol table** lists every function. `ld` writes it in link
//!   order — a `.file` record naming the object, then that object's symbols —
//!   so each symbol belongs to the `.file` that precedes it, whether or not it
//!   is `static`. COFF symbols carry no size, so extents come from `.pdata`
//!   (x86-64) or the distance to the next symbol.
//!
//! [`recover`] picks whichever covers more of `.text`, like the ELF path does.

use crate::cu::{PeCompilationUnit, PeContrib, PeCuIndex, PeFunction, PeVariable};
use crate::{PeArch, PeSection};
use anyhow::{anyhow, Context, Result};
use delink_core::binary::DwarfSlice;
use gimli::{EndianSlice, LittleEndian};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use std::collections::{BTreeMap, HashMap};

/// Which debug info a PDB-less split is driven from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugSource {
    /// Whichever covers more of `.text`.
    Auto,
    Dwarf,
    /// The COFF symbol table, grouped by its `.file` records.
    Symtab,
}

/// Prefix for the synthetic functions covering runs of `.text` that no symbol
/// describes (matches the ELF `.symtab` path).
pub const ORPHAN_PREFIX: &str = "__delink_orphan_";

/// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`.
const TEXT_CHARACTERISTICS: u32 = 0x6000_0020;

/// The `.text` ranges a unit's functions occupy. A PDB reports these as section
/// contributions; recording them keeps `has_text` / `text_size` meaningful. The
/// emitter only reads the non-`.text` ones, so this changes nothing it writes.
fn text_contributions(functions: &[PeFunction]) -> Vec<PeContrib> {
    functions
        .iter()
        .map(|f| PeContrib {
            va: f.va,
            size: f.size,
            section_name: ".text".to_string(),
            characteristics: TEXT_CHARACTERISTICS,
        })
        .collect()
}

/// Name of the unit that collects code no `.file` record claims.
const UNATTRIBUTED: &str = "__unattributed";

/// Everything the PE emitter needs, in place of what a PDB would have given.
pub struct Recovered {
    /// Which source was used: `"dwarf"` or `"symtab"`.
    pub label: &'static str,
    pub cu_index: PeCuIndex,
    pub functions: BTreeMap<u64, PeFunction>,
    pub variables: BTreeMap<u64, PeVariable>,
    pub tls_variables: BTreeMap<u32, String>,
    pub code_publics: BTreeMap<u64, String>,
}

pub fn recover(
    exe_data: &[u8],
    arch: PeArch,
    image_base: u64,
    sections: &[PeSection],
    source: DebugSource,
) -> Result<Recovered> {
    let text = sections
        .iter()
        .find(|s| s.name == ".text")
        .ok_or_else(|| anyhow!("PE has no .text section"))?;

    let symtab = if source == DebugSource::Dwarf {
        None
    } else {
        read_coff_symtab(exe_data)
    };
    let from_symtab = symtab
        .as_ref()
        .map(|t| SymtabRecovery::build(t, arch, image_base, sections, text));

    let dwarf = if source == DebugSource::Symtab {
        None
    } else {
        tracing::info!("indexing DWARF…");
        dwarf_recovery(arch, image_base, sections)?
    };

    let dwarf_coverage = dwarf.as_ref().map(|d| d.coverage()).unwrap_or(0);
    let symtab_coverage = from_symtab.as_ref().map(|s| s.coverage()).unwrap_or(0);

    let use_dwarf = match source {
        DebugSource::Dwarf => true,
        DebugSource::Symtab => false,
        DebugSource::Auto => dwarf_coverage >= symtab_coverage && dwarf_coverage > 0,
    };
    if source == DebugSource::Auto {
        tracing::info!(
            "coverage: DWARF {dwarf_coverage} bytes vs COFF symbols {symtab_coverage} bytes → using {}",
            if use_dwarf { "DWARF" } else { "COFF symbols" }
        );
    }

    if use_dwarf {
        let Some(mut d) = dwarf else {
            return Err(anyhow!(
                "no DWARF found in the image (no .debug_info section); \
                 pass --pdb, or use --group-by symtab for the COFF symbol table"
            ));
        };
        if d.units.is_empty() {
            return Err(anyhow!("the image's DWARF has no compilation units"));
        }
        // Fold in what the symbol table knows about everything DWARF doesn't
        // describe, so calls and data references into those still resolve.
        let mut code_publics = BTreeMap::new();
        let mut tls_variables = BTreeMap::new();
        if let Some(s) = from_symtab {
            for f in s
                .extents
                .iter()
                .filter(|e| !d.functions.contains_key(&e.va))
            {
                code_publics.insert(f.va, f.name.clone());
            }
            for (va, v) in s.variables {
                d.variables.entry(va).or_insert(v);
            }
            tls_variables = s.tls_variables;
        }
        let units = d.units;
        return Ok(Recovered {
            label: "dwarf",
            cu_index: PeCuIndex { units },
            functions: d.functions,
            variables: d.variables,
            tls_variables,
            code_publics,
        });
    }

    let Some(s) = from_symtab else {
        return Err(anyhow!(
            "no PDB was given and the image has no usable debug info: \
             no COFF symbol table (stripped), and DWARF covers {dwarf_coverage} bytes"
        ));
    };
    if s.extents.is_empty() {
        return Err(anyhow!(
            "no PDB was given and the COFF symbol table names no functions in .text \
             (the image looks stripped); DWARF covers {dwarf_coverage} bytes"
        ));
    }
    Ok(Recovered {
        label: "symtab",
        cu_index: PeCuIndex { units: s.units },
        functions: s.functions,
        variables: s.variables,
        tls_variables: s.tls_variables,
        code_publics: BTreeMap::new(),
    })
}

// ---------------------------------------------------------------------------
// COFF symbol table
// ---------------------------------------------------------------------------

const C_EXT: u8 = 2;
const C_STAT: u8 = 3;
const C_FILE: u8 = 103;
/// `IMAGE_SYM_DTYPE_FUNCTION` in the high nibble of a symbol's type.
const DTYPE_FUNCTION: u16 = 2;

#[derive(Debug, Clone)]
struct CoffSym {
    name: String,
    /// Section-relative offset (for the symbols we care about; the image's
    /// symbol table is not rebased to RVAs).
    value: u32,
    /// 1-based section number; `0` undefined, negative absolute/debug.
    section: i16,
    typ: u16,
    class: u8,
    /// Index into [`CoffSymtab::files`] of the `.file` record this symbol
    /// follows.
    file: Option<usize>,
}

struct CoffSymtab {
    files: Vec<String>,
    syms: Vec<CoffSym>,
}

fn read_coff_symtab(exe_data: &[u8]) -> Option<CoffSymtab> {
    let e_lfanew = u32::from_le_bytes(exe_data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let coff = e_lfanew.checked_add(4)?;
    let ptr = u32::from_le_bytes(exe_data.get(coff + 8..coff + 12)?.try_into().ok()?) as usize;
    let count = u32::from_le_bytes(exe_data.get(coff + 12..coff + 16)?.try_into().ok()?) as usize;
    if ptr == 0 || count == 0 {
        return None;
    }
    let strings = ptr.checked_add(count.checked_mul(18)?)?;
    let table = exe_data.get(ptr..strings)?;

    let long_name = |off: usize| -> String {
        let bytes = exe_data.get(strings + off..).unwrap_or(&[]);
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    };

    let mut files = Vec::new();
    let mut syms = Vec::with_capacity(count);
    let mut current = None;
    let mut i = 0usize;
    while i < count {
        let rec = table.get(i * 18..i * 18 + 18)?;
        let aux = rec[17] as usize;
        let name = if rec[..4] == [0, 0, 0, 0] {
            long_name(u32::from_le_bytes(rec[4..8].try_into().unwrap()) as usize)
        } else {
            let end = rec[..8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&rec[..end]).into_owned()
        };
        let class = rec[16];

        if class == C_FILE {
            // The file name lives in the auxiliary records that follow.
            let bytes = table.get((i + 1) * 18..(i + 1 + aux) * 18).unwrap_or(&[]);
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            files.push(String::from_utf8_lossy(&bytes[..end]).into_owned());
            current = Some(files.len() - 1);
        } else {
            syms.push(CoffSym {
                name,
                value: u32::from_le_bytes(rec[8..12].try_into().unwrap()),
                section: i16::from_le_bytes(rec[12..14].try_into().unwrap()),
                typ: u16::from_le_bytes(rec[14..16].try_into().unwrap()),
                class,
                file: current,
            });
        }
        i += 1 + aux;
    }
    Some(CoffSymtab { files, syms })
}

/// A function recovered from the symbol table, with its extent worked out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Extent {
    va: u64,
    size: u32,
    name: String,
    aliases: Vec<String>,
    external: bool,
    file: Option<usize>,
}

struct SymtabRecovery {
    extents: Vec<Extent>,
    units: Vec<PeCompilationUnit>,
    functions: BTreeMap<u64, PeFunction>,
    variables: BTreeMap<u64, PeVariable>,
    tls_variables: BTreeMap<u32, String>,
}

impl SymtabRecovery {
    fn coverage(&self) -> u64 {
        self.extents.iter().map(|e| e.size as u64).sum()
    }

    fn build(
        tab: &CoffSymtab,
        arch: PeArch,
        image_base: u64,
        sections: &[PeSection],
        text: &PeSection,
    ) -> Self {
        let section_of = |n: i16| -> Option<&PeSection> {
            usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|n| sections.get(n))
        };

        // Code symbols: anything external in `.text`, plus static symbols that
        // are typed as functions (statics without a type are local labels).
        let mut candidates: Vec<Candidate> = Vec::new();
        for s in &tab.syms {
            let Some(sec) = section_of(s.section) else {
                continue;
            };
            if sec.name != ".text" || s.name.is_empty() || s.name.starts_with('.') {
                continue;
            }
            let is_function = s.typ >> 4 == DTYPE_FUNCTION;
            if !(s.class == C_EXT || (s.class == C_STAT && is_function)) {
                continue;
            }
            candidates.push(Candidate {
                va: image_base + sec.rva + s.value as u64,
                name: s.name.clone(),
                external: s.class == C_EXT,
                file: s.file,
            });
        }

        let pdata = if arch == PeArch::X86_64 {
            read_pdata(sections, image_base)
        } else {
            HashMap::new()
        };
        let mut extents = build_extents(candidates, &pdata, text, arch);

        // Names that two definitions share (`.isra.0` clones, file-local
        // helpers) can't live side by side once split apart and exported, so
        // rename every colliding definition by address, as the ELF path does.
        let mut variables = BTreeMap::new();
        let mut tls_variables = BTreeMap::new();
        for s in &tab.syms {
            let Some(sec) = section_of(s.section) else {
                continue;
            };
            if s.name.is_empty()
                || s.name.starts_with('.')
                || !(s.class == C_EXT || s.class == C_STAT)
                || s.typ >> 4 == DTYPE_FUNCTION
            {
                continue;
            }
            match sec.name.as_str() {
                ".tls" => {
                    tls_variables
                        .entry(s.value)
                        .or_insert_with(|| s.name.clone());
                }
                ".data" | ".rdata" | ".bss" => {
                    let va = image_base + sec.rva + s.value as u64;
                    variables.entry(va).or_insert_with(|| PeVariable {
                        name: s.name.clone(),
                        va,
                        is_public: true,
                        size: 0,
                    });
                }
                _ => {}
            }
        }
        disambiguate(&mut extents, &mut variables);

        let (units, functions) = group_into_units(&extents, &tab.files);
        Self {
            extents,
            units,
            functions,
            variables,
            tls_variables,
        }
    }
}

struct Candidate {
    va: u64,
    name: String,
    external: bool,
    file: Option<usize>,
}

/// Turn code symbols into functions with extents.
///
/// Aliases (several names at one address — `C1`/`C2` constructors) collapse to
/// the first in symbol-table order. A function runs to its `.pdata` end when
/// there is one, otherwise to the next symbol with trailing alignment padding
/// trimmed off. Runs of real code no symbol covers become orphan functions, so
/// no code is lost and calls into it still resolve.
fn build_extents(
    candidates: Vec<Candidate>,
    pdata: &HashMap<u64, u64>,
    text: &PeSection,
    arch: PeArch,
) -> Vec<Extent> {
    let text_end = text.va + text.virtual_size;
    let mut cands: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| c.va >= text.va && c.va < text_end)
        .collect();
    // Stable, so aliases keep symbol-table order.
    cands.sort_by_key(|c| c.va);

    let mut groups: Vec<(Candidate, Vec<String>)> = Vec::new();
    for c in cands {
        match groups.last_mut() {
            Some((head, aliases)) if head.va == c.va => {
                if c.name != head.name && !aliases.contains(&c.name) {
                    aliases.push(c.name);
                }
            }
            _ => groups.push((c, Vec::new())),
        }
    }

    let bytes_at = |from: u64, to: u64| -> &[u8] {
        let (a, b) = ((from - text.va) as usize, (to - text.va) as usize);
        text.data.get(a..b.min(text.data.len())).unwrap_or(&[])
    };

    let mut out: Vec<Extent> = Vec::new();
    // Where code not yet accounted for begins, and the owner of the previous
    // function (orphans belong to whatever precedes them).
    let mut cursor = text.va;
    let mut owner: Option<usize> = None;
    let push_orphan = |out: &mut Vec<Extent>, from: u64, to: u64, owner: Option<usize>| {
        if to > from && trim_trailing_padding(bytes_at(from, to), arch) > 0 {
            out.push(Extent {
                va: from,
                size: (to - from) as u32,
                name: format!("{ORPHAN_PREFIX}{from:x}"),
                aliases: Vec::new(),
                external: false,
                file: owner,
            });
        }
    };

    for (i, (head, aliases)) in groups.iter().enumerate() {
        push_orphan(&mut out, cursor, head.va, owner);

        let next = groups.get(i + 1).map(|(n, _)| n.va).unwrap_or(text_end);
        let size = match pdata.get(&head.va) {
            Some(&end) if end > head.va => end.min(next) - head.va,
            _ => trim_trailing_padding(bytes_at(head.va, next), arch) as u64,
        };
        // A symbol sitting on pure padding still marks a function boundary;
        // keep a one-byte floor so it isn't silently dropped.
        let size = size.max(1).min(next - head.va);

        out.push(Extent {
            va: head.va,
            size: size as u32,
            name: head.name.clone(),
            aliases: aliases.clone(),
            external: head.external,
            file: head.file,
        });
        cursor = head.va + size;
        owner = head.file;
    }
    push_orphan(&mut out, cursor, text_end, owner);
    out
}

/// Length of `bytes` once trailing `nop` / `int3` instructions are removed.
/// Alignment padding is what separates one function from the next.
fn trim_trailing_padding(bytes: &[u8], arch: PeArch) -> usize {
    let bitness = match arch {
        PeArch::X86_64 => 64,
        PeArch::X86 => 32,
    };
    let mut decoder = Decoder::new(bitness, bytes, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    let mut end = 0usize;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        let padding =
            !insn.is_invalid() && matches!(insn.mnemonic(), Mnemonic::Nop | Mnemonic::Int3);
        if !padding {
            end = decoder.position();
        }
    }
    end
}

/// `.pdata` `RUNTIME_FUNCTION` entries as `begin VA → end VA`.
fn read_pdata(sections: &[PeSection], image_base: u64) -> HashMap<u64, u64> {
    let Some(pdata) = sections.iter().find(|s| s.name == ".pdata") else {
        return HashMap::new();
    };
    pdata
        .data
        .chunks_exact(12)
        .filter_map(|e| {
            let begin = u32::from_le_bytes(e[0..4].try_into().unwrap()) as u64;
            let end = u32::from_le_bytes(e[4..8].try_into().unwrap()) as u64;
            (begin != 0).then_some((image_base + begin, image_base + end))
        })
        .collect()
}

/// Suffix every definition whose name another definition shares with its
/// address (`.` can't appear in a C identifier, so the result is unambiguous).
///
/// Aliases count: identical-code folding leaves several names on one body, and
/// a folded `foo.part.0` can share its name with an unrelated function's
/// primary name elsewhere.
fn disambiguate(extents: &mut [Extent], variables: &mut BTreeMap<u64, PeVariable>) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in extents.iter() {
        *counts.entry(e.name.as_str()).or_default() += 1;
        for alias in &e.aliases {
            *counts.entry(alias.as_str()).or_default() += 1;
        }
    }
    for v in variables.values() {
        *counts.entry(v.name.as_str()).or_default() += 1;
    }
    let colliding: std::collections::HashSet<String> = counts
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name.to_string())
        .collect();
    if colliding.is_empty() {
        return;
    }
    for e in extents.iter_mut() {
        if colliding.contains(&e.name) {
            e.name = format!("{}.{:x}", e.name, e.va);
        }
        for alias in e.aliases.iter_mut() {
            if colliding.contains(alias.as_str()) {
                *alias = format!("{alias}.{:x}", e.va);
            }
        }
    }
    for v in variables.values_mut() {
        if colliding.contains(&v.name) {
            v.name = format!("{}.{:x}", v.name, v.va);
        }
    }
    tracing::info!(
        "disambiguated definitions sharing {} names",
        colliding.len()
    );
}

/// One unit per `.file` record, in link order, plus a catch-all for code no
/// record claims.
fn group_into_units(
    extents: &[Extent],
    files: &[String],
) -> (Vec<PeCompilationUnit>, BTreeMap<u64, PeFunction>) {
    let mut by_file: Vec<Vec<&Extent>> = vec![Vec::new(); files.len()];
    let mut unattributed: Vec<&Extent> = Vec::new();
    for e in extents {
        match e.file {
            Some(f) if f < files.len() => by_file[f].push(e),
            _ => unattributed.push(e),
        }
    }

    let mut units = Vec::new();
    let mut functions = BTreeMap::new();
    let named = files
        .iter()
        .map(|f| f.as_str())
        .zip(by_file)
        .chain(std::iter::once((UNATTRIBUTED, unattributed)));
    for (name, mut group) in named {
        if group.is_empty() {
            continue;
        }
        group.sort_by_key(|e| e.va);
        let id = units.len();
        let funcs: Vec<PeFunction> = group
            .iter()
            .map(|e| PeFunction {
                name: e.name.clone(),
                va: e.va,
                size: e.size,
                is_public: true,
                module_id: id,
                aliases: e.aliases.clone(),
            })
            .collect();
        for f in &funcs {
            functions.entry(f.va).or_insert_with(|| f.clone());
        }
        units.push(PeCompilationUnit {
            id,
            name: name.to_string(),
            obj_file: name.to_string(),
            contributions: text_contributions(&funcs),
            functions: funcs,
        });
    }
    (units, functions)
}

// ---------------------------------------------------------------------------
// DWARF
// ---------------------------------------------------------------------------

struct DwarfRecovery {
    units: Vec<PeCompilationUnit>,
    functions: BTreeMap<u64, PeFunction>,
    variables: BTreeMap<u64, PeVariable>,
}

impl DwarfRecovery {
    fn coverage(&self) -> u64 {
        self.functions.values().map(|f| f.size as u64).sum()
    }
}

fn load_dwarf(
    sections: &[PeSection],
) -> std::result::Result<gimli::Dwarf<DwarfSlice<'_>>, gimli::Error> {
    gimli::Dwarf::load(|id: gimli::SectionId| {
        let data = sections
            .iter()
            .find(|s| s.name == id.name())
            .map(|s| &s.data[..])
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    })
}

/// Index the image's DWARF, or `None` when it carries none.
fn dwarf_recovery(
    arch: PeArch,
    image_base: u64,
    sections: &[PeSection],
) -> Result<Option<DwarfRecovery>> {
    let section = |name: &str| -> &[u8] {
        sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| &s.data[..])
            .unwrap_or(&[])
    };
    if section(".debug_info").is_empty() {
        return Ok(None);
    }

    let dwarf = load_dwarf(sections).context("load DWARF")?;
    let index = delink_core::cu::CuIndex::from_dwarf(
        &dwarf,
        section(".debug_abbrev"),
        section(".debug_line"),
    )
    .context("index DWARF")?;

    let text = sections.iter().find(|s| s.name == ".text");
    // Addresses are normally absolute, but accept image-relative ones too.
    let to_va = |addr: u64| -> u64 {
        if addr >= image_base {
            addr
        } else {
            image_base + addr
        }
    };
    // 32-bit MinGW prefixes every C symbol with `_`, and DWARF names omit it.
    let decorate = |name: &str| -> String {
        if arch == PeArch::X86 {
            format!("_{name}")
        } else {
            name.to_string()
        }
    };

    let mut units = Vec::new();
    let mut functions = BTreeMap::new();
    let mut variables = BTreeMap::new();
    for cu in &index.units {
        let id = units.len();
        let mut funcs = Vec::new();
        for f in cu.functions.iter().filter(|f| f.size > 0) {
            let va = to_va(f.addr);
            if !text.is_some_and(|t| t.contains_va(va)) {
                continue;
            }
            let name = decorate(f.linkage_name.as_deref().unwrap_or(&f.name));
            let func = PeFunction {
                name,
                va,
                size: f.size as u32,
                is_public: f.external,
                module_id: id,
                aliases: Vec::new(),
            };
            functions.entry(va).or_insert_with(|| func.clone());
            funcs.push(func);
        }
        for v in cu.variables.iter().filter(|v| v.addr != 0) {
            let va = to_va(v.addr);
            if !sections
                .iter()
                .any(|s| s.name != ".text" && s.contains_va(va))
            {
                continue;
            }
            variables.entry(va).or_insert_with(|| PeVariable {
                name: decorate(v.linkage_name.as_deref().unwrap_or(&v.name)),
                va,
                is_public: v.external,
                size: 0,
            });
        }
        if funcs.is_empty() {
            continue;
        }
        units.push(PeCompilationUnit {
            id,
            name: cu.name.clone(),
            obj_file: cu.name.clone(),
            contributions: text_contributions(&funcs),
            functions: funcs,
        });
    }
    Ok(Some(DwarfRecovery {
        units,
        functions,
        variables,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: Vec<u8>) -> PeSection {
        PeSection {
            name: ".text".into(),
            rva: 0x1000,
            va: 0x1000,
            virtual_size: bytes.len() as u64,
            data: bytes,
            characteristics: 0x6000_0020,
        }
    }

    fn cand(va: u64, name: &str, file: Option<usize>) -> Candidate {
        Candidate {
            va,
            name: name.into(),
            external: true,
            file,
        }
    }

    #[test]
    fn trailing_nops_and_int3_are_trimmed() {
        // xor eax,eax ; ret ; nop ; 2-byte nop ; int3
        let bytes = [0x31, 0xc0, 0xc3, 0x90, 0x66, 0x90, 0xcc];
        assert_eq!(trim_trailing_padding(&bytes, PeArch::X86_64), 3);
        // Pure padding trims to nothing.
        assert_eq!(
            trim_trailing_padding(&[0xcc, 0xcc, 0x90], PeArch::X86_64),
            0
        );
        // A `call` whose displacement ends in 0x00 is code, not padding.
        let call = [0xe8, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(trim_trailing_padding(&call, PeArch::X86_64), 5);
    }

    #[test]
    fn extents_run_to_the_next_symbol_minus_padding() {
        // f: ret + 3 bytes padding ; g: ret + 1 byte padding
        let t = text(vec![0xc3, 0xcc, 0xcc, 0xcc, 0xc3, 0xcc]);
        let ext = build_extents(
            vec![cand(0x1000, "f", Some(0)), cand(0x1004, "g", Some(0))],
            &HashMap::new(),
            &t,
            PeArch::X86_64,
        );
        let got: Vec<_> = ext.iter().map(|e| (e.name.as_str(), e.size)).collect();
        assert_eq!(got, [("f", 1), ("g", 1)]);
    }

    #[test]
    fn pdata_end_wins_over_the_next_symbol() {
        let t = text(vec![0x90, 0x90, 0xc3, 0x90, 0xc3, 0xcc]);
        let pdata = HashMap::from([(0x1000, 0x1003)]);
        let ext = build_extents(
            vec![cand(0x1000, "f", None), cand(0x1004, "g", None)],
            &pdata,
            &t,
            PeArch::X86_64,
        );
        // Leading nops are part of `f` because `.pdata` says so.
        assert_eq!(ext[0].size, 3);
        assert_eq!(ext[1].size, 1);
    }

    #[test]
    fn aliases_collapse_onto_the_first_name() {
        let t = text(vec![0xc3, 0xcc]);
        let ext = build_extents(
            vec![
                cand(0x1000, "ctor_c2", Some(0)),
                cand(0x1000, "ctor_c1", Some(1)),
            ],
            &HashMap::new(),
            &t,
            PeArch::X86_64,
        );
        assert_eq!(ext.len(), 1);
        assert_eq!(ext[0].name, "ctor_c2");
        assert_eq!(ext[0].aliases, ["ctor_c1"]);
        assert_eq!(ext[0].file, Some(0));
    }

    #[test]
    fn code_before_the_first_symbol_becomes_an_orphan() {
        // [code][f: ret]
        let t = text(vec![0x31, 0xc0, 0xc3, 0xc3]);
        let ext = build_extents(
            vec![cand(0x1003, "f", Some(2))],
            &HashMap::new(),
            &t,
            PeArch::X86_64,
        );
        let got: Vec<_> = ext
            .iter()
            .map(|e| (e.name.clone(), e.va, e.size, e.file))
            .collect();
        assert_eq!(
            got,
            [
                (format!("{ORPHAN_PREFIX}1000"), 0x1000, 3, None),
                ("f".to_string(), 0x1003, 1, Some(2)),
            ]
        );
    }

    #[test]
    fn real_code_past_a_pdata_end_becomes_an_orphan_but_pure_padding_does_not() {
        // f(0x1000, ret) | padding | code(0x1004..0x1007) | g(0x1007, ret) | padding
        let t = text(vec![
            0xc3, 0xcc, 0xcc, 0xcc, 0x31, 0xc0, 0xc3, 0xc3, 0xcc, 0xcc,
        ]);
        let pdata = HashMap::from([(0x1000, 0x1001), (0x1007, 0x1008)]);
        let ext = build_extents(
            vec![cand(0x1000, "f", Some(1)), cand(0x1007, "g", Some(3))],
            &pdata,
            &t,
            PeArch::X86_64,
        );
        let got: Vec<_> = ext.iter().map(|e| (e.name.clone(), e.va, e.file)).collect();
        assert_eq!(
            got,
            [
                ("f".to_string(), 0x1000, Some(1)),
                // The gap starts at f's end and carries real code, so it is
                // kept; it inherits the preceding function's file.
                (format!("{ORPHAN_PREFIX}1001"), 0x1001, Some(1)),
                ("g".to_string(), 0x1007, Some(3)),
            ]
        );
        // The tail after `g` is all padding: nothing was emitted for it.
        assert!(ext.iter().all(|e| e.va < 0x1008));
    }

    #[test]
    fn units_follow_file_records_and_unattributed_code_gets_its_own() {
        let ext = vec![
            Extent {
                va: 0x1000,
                size: 4,
                name: "b".into(),
                aliases: vec![],
                external: true,
                file: Some(1),
            },
            Extent {
                va: 0x1010,
                size: 4,
                name: "a".into(),
                aliases: vec![],
                external: true,
                file: Some(0),
            },
            Extent {
                va: 0x1020,
                size: 4,
                name: "x".into(),
                aliases: vec![],
                external: false,
                file: None,
            },
        ];
        let (units, functions) = group_into_units(&ext, &["a.cpp".into(), "b.cpp".into()]);
        let names: Vec<_> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["a.cpp", "b.cpp", UNATTRIBUTED]);
        assert_eq!(functions.len(), 3);
        assert_eq!(units[1].functions[0].module_id, 1);
        assert_eq!(units[0].text_size(), 4);
    }

    #[test]
    fn colliding_names_are_renamed_by_address() {
        let mut ext = vec![
            Extent {
                va: 0x1000,
                size: 1,
                name: "f.isra.0".into(),
                aliases: vec![],
                external: false,
                file: None,
            },
            Extent {
                va: 0x2000,
                size: 1,
                name: "f.isra.0".into(),
                aliases: vec![],
                external: false,
                file: None,
            },
            Extent {
                va: 0x3000,
                size: 1,
                name: "unique".into(),
                aliases: vec![],
                external: true,
                file: None,
            },
        ];
        let mut vars = BTreeMap::new();
        disambiguate(&mut ext, &mut vars);
        assert_eq!(ext[0].name, "f.isra.0.1000");
        assert_eq!(ext[1].name, "f.isra.0.2000");
        assert_eq!(ext[2].name, "unique");
    }

    #[test]
    fn an_alias_colliding_with_another_primary_is_renamed_too() {
        let mk = |va, name: &str, aliases: &[&str]| Extent {
            va,
            size: 1,
            name: name.into(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            external: false,
            file: None,
        };
        let mut ext = vec![
            mk(0x1000, "a.part.0", &["b.part.0"]),
            mk(0x2000, "b.part.0", &[]),
        ];
        disambiguate(&mut ext, &mut BTreeMap::new());
        assert_eq!(ext[0].name, "a.part.0");
        assert_eq!(ext[0].aliases, ["b.part.0.1000"]);
        assert_eq!(ext[1].name, "b.part.0.2000");
    }

    /// `/<n>` section names index the COFF string table.
    #[test]
    fn long_section_names_resolve_through_the_string_table() {
        let mut image = vec![0u8; 16];
        image.extend_from_slice(b"\0\0\0\0.debug_info\0.debug_abbrev\0");
        let table = Some(16);
        assert_eq!(
            crate::resolve_long_section_name(&image, table, "/4").as_deref(),
            Some(".debug_info")
        );
        assert_eq!(
            crate::resolve_long_section_name(&image, table, "/16").as_deref(),
            Some(".debug_abbrev")
        );
        assert_eq!(
            crate::resolve_long_section_name(&image, table, ".text"),
            None
        );
        assert_eq!(crate::resolve_long_section_name(&image, None, "/4"), None);
    }
}
