//! Compilation-unit reconstruction from `.symtab`.
//!
//! Most shipped binaries carry a full static symbol table even when they were
//! built without `-g`. `ld` writes it in link order and, for every input
//! object that contributed local symbols, emits an `STT_FILE` symbol naming
//! the translation unit followed by that object's locals. That gives exact
//! boundaries for every TU that had at least one `static` function.
//!
//! TUs whose functions are all external contribute no locals and therefore no
//! usable anchor. Their code still sits between the anchors of its neighbours
//! (the linker lays `.text` out in the same order), so we attribute every
//! function to the nearest preceding anchor. The result is exact where anchors
//! exist and merges anchor-less TUs into the preceding file — which is why the
//! grouping is written out as an editable JSON the caller can correct.

use crate::binary::Binary;
use crate::cu::{CompilationUnit, CuIndex, Function, Variable};
use crate::error::Result;
use crate::symbols::{GlobalSymbols, VariableRef};
use delink_arch::ElfClass;
use object::{Object as _, ObjectSection as _};
use std::collections::BTreeMap;

// STT_* / STB_* values we care about.
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_FILE: u8 = 4;
const STB_LOCAL: u8 = 0;

/// One parsed `.symtab` entry.
#[derive(Debug, Clone)]
pub struct StaticSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub sym_type: u8,
    pub bind: u8,
    pub shndx: u16,
}

impl StaticSymbol {
    pub fn is_local(&self) -> bool {
        self.bind == STB_LOCAL
    }
}

/// A translation unit recovered from `STT_FILE` grouping.
#[derive(Debug, Clone)]
pub struct FileGroup {
    /// Name from the `STT_FILE` symbol, e.g. `STAGE6OBJ.C`.
    pub file: String,
    /// Lowest `.text` address of a local function in this group, if any.
    /// Groups without one cannot be placed and get folded into a neighbour.
    pub anchor: Option<u64>,
    /// Local symbols emitted between this `STT_FILE` and the next one.
    pub locals: Vec<StaticSymbol>,
}

pub struct SymtabIndex {
    pub symbols: Vec<StaticSymbol>,
    pub groups: Vec<FileGroup>,
    /// Index of the `.text` section header, used to filter code symbols.
    pub text_shndx: Option<u16>,
    /// End address of `.text`, used to size the last function.
    pub text_end: u64,
    /// Synthetic entries covering runs of `.text` that no symbol describes.
    /// See [`SymtabIndex::text_functions`].
    pub orphans: Vec<StaticSymbol>,
}

/// Prefix for the synthetic symbols covering unnamed `.text` regions.
pub const ORPHAN_PREFIX: &str = "__delink_orphan_";

impl SymtabIndex {
    pub fn build(binary: &Binary<'_>) -> Result<Self> {
        let symbols = read_symtab(binary)?;
        let text_shndx = text_section_index(binary);

        let mut groups: Vec<FileGroup> = Vec::new();
        for sym in &symbols {
            if sym.sym_type == STT_FILE {
                groups.push(FileGroup {
                    file: sym.name.clone(),
                    anchor: None,
                    locals: Vec::new(),
                });
                continue;
            }
            let Some(group) = groups.last_mut() else {
                continue;
            };
            if sym.is_local() && matches!(sym.sym_type, STT_FUNC | STT_OBJECT) && sym.shndx != 0 {
                group.locals.push(sym.clone());
            }
        }

        for group in &mut groups {
            group.anchor = group
                .locals
                .iter()
                .filter(|s| s.sym_type == STT_FUNC && s.size > 0 && Some(s.shndx) == text_shndx)
                .map(|s| s.value)
                .min();
        }

        let text_end = binary
            .elf
            .section_by_name(".text")
            .map(|s| s.address() + s.size())
            .unwrap_or(0);

        let text = binary.elf.section_by_name(".text");
        let text_base = text.as_ref().map(|s| s.address()).unwrap_or(0);
        let text_data = text.and_then(|s| s.data().ok()).unwrap_or(&[]);

        let named = collect_text_functions(&symbols, text_shndx, text_end);
        let orphans = find_orphan_regions(&named, text_base, text_data, text_end);
        if !orphans.is_empty() {
            let bytes: u64 = orphans.iter().map(|o| o.size).sum();
            tracing::info!(
                "{} runs of .text ({bytes} bytes) carry no symbol; emitting them as {ORPHAN_PREFIX}*",
                orphans.len()
            );
        }

        Ok(Self {
            symbols,
            groups,
            text_shndx,
            text_end,
            orphans,
        })
    }

    /// Every `STT_FUNC` symbol defined in `.text`, sorted by address and
    /// deduplicated (aliases at the same address collapse to one entry,
    /// preferring the one that carries a size).
    ///
    /// Hand-written assembly routines — `__aeabi_ldivmod`, `__cxa_end_cleanup`,
    /// the `__gnu_Unwind_*` helpers, the crt glue — are frequently emitted
    /// with `st_size == 0`. Left out, their code would be dropped and every
    /// call to them would go unrelocated, so their extent is inferred from the
    /// next symbol instead.
    ///
    /// Runs of `.text` that no symbol covers at all get a synthetic
    /// `__delink_orphan_<addr>` entry for the same reason.
    pub fn text_functions(&self) -> Vec<StaticSymbol> {
        let mut fns = collect_text_functions(&self.symbols, self.text_shndx, self.text_end);
        if !self.orphans.is_empty() {
            fns.extend(self.orphans.iter().cloned());
            fns.sort_by_key(|a| a.value);
        }
        fns
    }

    /// Data symbols (`STT_OBJECT`) with a concrete address, for the shared
    /// data object's symbol table.
    pub fn data_objects(&self) -> Vec<StaticSymbol> {
        let mut objs: Vec<StaticSymbol> = self
            .symbols
            .iter()
            .filter(|s| {
                s.sym_type == STT_OBJECT
                    && s.shndx != 0
                    && Some(s.shndx) != self.text_shndx
                    && s.value != 0
                    && !s.name.is_empty()
            })
            .cloned()
            .collect();
        objs.sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.name.cmp(&b.name)));
        objs.dedup_by(|a, b| a.value == b.value && a.name == b.name);
        objs
    }

    /// Map each `.text` function to the file it most likely came from.
    ///
    /// Anchors are the per-`STT_FILE` minimum local-function addresses, taken
    /// in increasing address order; every function is attributed to the last
    /// anchor at or below it. Functions before the first anchor are reported
    /// under `None`.
    pub fn attribute_functions(&self) -> Vec<(StaticSymbol, Option<&str>)> {
        let mut anchors: Vec<(u64, &str)> = self
            .groups
            .iter()
            .filter_map(|g| g.anchor.map(|a| (a, g.file.as_str())))
            .collect();
        anchors.sort_by_key(|(a, _)| *a);
        anchors.dedup_by_key(|(a, _)| *a);

        self.text_functions()
            .into_iter()
            .map(|f| {
                let idx = anchors.partition_point(|(a, _)| *a <= f.value);
                let file = if idx == 0 {
                    None
                } else {
                    Some(anchors[idx - 1].1)
                };
                (f, file)
            })
            .collect()
    }

    /// Build a `CuIndex` where each recovered file becomes one compilation
    /// unit. Functions that precede the first anchor land in a synthetic
    /// `__unattributed` unit rather than being dropped.
    pub fn to_cu_index(&self) -> CuIndex {
        let mut by_file: BTreeMap<String, Vec<StaticSymbol>> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for (func, file) in self.attribute_functions() {
            let key = file.unwrap_or("__unattributed").to_string();
            if !by_file.contains_key(&key) {
                order.push(key.clone());
            }
            by_file.entry(key).or_default().push(func);
        }

        // Data symbols are attributed by the `STT_FILE` group that declared
        // them; only locals can be attributed this way, which is exactly the
        // set that needs per-object placement.
        let mut vars_by_file: BTreeMap<&str, Vec<&StaticSymbol>> = BTreeMap::new();
        for group in &self.groups {
            let entry = vars_by_file.entry(group.file.as_str()).or_default();
            for sym in &group.locals {
                if sym.sym_type == STT_OBJECT && sym.value != 0 {
                    entry.push(sym);
                }
            }
        }

        let units = order
            .into_iter()
            .enumerate()
            .map(|(id, file)| {
                let funcs = by_file.remove(&file).unwrap_or_default();
                let ranges = funcs.iter().map(|f| f.value..f.value + f.size).collect();
                let functions = funcs
                    .into_iter()
                    .map(|f| Function {
                        name: f.name.clone(),
                        linkage_name: Some(f.name),
                        addr: f.value,
                        size: f.size,
                        external: f.bind != STB_LOCAL,
                    })
                    .collect();
                let variables = vars_by_file
                    .get(file.as_str())
                    .map(|v| {
                        v.iter()
                            .map(|s| Variable {
                                name: s.name.clone(),
                                linkage_name: Some(s.name.clone()),
                                addr: s.value,
                                external: s.bind != STB_LOCAL,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                CompilationUnit {
                    id,
                    name: file,
                    comp_dir: None,
                    producer: None,
                    language: None,
                    ranges,
                    functions,
                    variables,
                    debug_info_range: 0..0,
                    debug_abbrev_range: 0..0,
                    debug_line_range: None,
                    file_name: None,
                }
            })
            .collect();

        CuIndex { units }
    }

    /// Total `.text` bytes covered by sized `STT_FUNC` symbols.
    pub fn text_coverage(&self) -> u64 {
        self.text_functions().iter().map(|f| f.size).sum()
    }

    /// Build the resolver for a `.symtab`-driven split.
    ///
    /// Every `STT_OBJECT` in the symbol table is registered as a variable, so
    /// pointers into `.data`/`.bss`/`.rodata` resolve to a name instead of an
    /// offset from a section-start symbol. Both maps are assembled before
    /// `build_from_maps` runs, so name disambiguation sees all of them.
    pub fn build_symbols(&self, binary: &Binary<'_>, cus: &CuIndex) -> Result<GlobalSymbols> {
        let (functions, mut variables) = GlobalSymbols::maps_from_cus(cus);
        for obj in self.data_objects() {
            // Entries the CU index already attributed win: they carry the
            // translation unit the symbol belongs to.
            variables.entry(obj.value).or_insert_with(|| VariableRef {
                cu_id: usize::MAX,
                name: obj.name.clone(),
                linkage_name: Some(obj.name.clone()),
                external: obj.bind != STB_LOCAL,
            });
        }
        GlobalSymbols::build_from_maps(binary, functions, variables)
    }
}

/// The named `.text` functions, deduplicated and with missing sizes inferred.
fn collect_text_functions(
    symbols: &[StaticSymbol],
    text_shndx: Option<u16>,
    text_end: u64,
) -> Vec<StaticSymbol> {
    let mut fns: Vec<StaticSymbol> = symbols
        .iter()
        .filter(|s| s.sym_type == STT_FUNC && Some(s.shndx) == text_shndx && !s.name.is_empty())
        .cloned()
        .collect();
    // Aliases share an address; keep the one that carries a size.
    fns.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then_with(|| (a.size == 0).cmp(&(b.size == 0)))
            .then_with(|| a.name.cmp(&b.name))
    });
    fns.dedup_by_key(|s| s.value);

    for i in 0..fns.len() {
        if fns[i].size != 0 {
            continue;
        }
        let next = fns
            .get(i + 1)
            .map(|s| s.value)
            .unwrap_or(text_end)
            .max(fns[i].value);
        fns[i].size = next - fns[i].value;
    }
    fns.retain(|s| s.size > 0);

    // Secondary entry points (`__aeabi_uidivmod` jumping into the middle of
    // `__udivsi3`, and similar assembly aliases) appear as their own sized
    // symbols overlapping the function that contains them. Emitting both
    // would duplicate the bytes; dropping the inner one lets references to it
    // resolve as `outer + delta`, which is what it actually is.
    let mut kept: Vec<StaticSymbol> = Vec::with_capacity(fns.len());
    let mut end = 0u64;
    let mut dropped = 0usize;
    for f in fns {
        if f.value < end {
            dropped += 1;
            continue;
        }
        end = f.value + f.size;
        kept.push(f);
    }
    if dropped > 0 {
        tracing::debug!("{dropped} .text symbols overlap an enclosing function; folded in");
    }
    kept
}

/// Find runs of `.text` that no symbol covers and that hold real instructions.
///
/// Linkers drop local symbols for some inputs, leaving live code nameless. If
/// those bytes are not emitted, every branch into them stays unrelocated and
/// the code is simply lost, so each run gets a synthetic local function.
/// Inter-function alignment padding is excluded.
fn find_orphan_regions(
    named: &[StaticSymbol],
    text_base: u64,
    text_data: &[u8],
    text_end: u64,
) -> Vec<StaticSymbol> {
    if text_data.is_empty() || text_end <= text_base {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = text_base;
    let push = |start: u64, end: u64, out: &mut Vec<StaticSymbol>| {
        if end <= start {
            return;
        }
        let (Some(from), Some(to)) = (
            start.checked_sub(text_base).map(|v| v as usize),
            end.checked_sub(text_base).map(|v| v as usize),
        ) else {
            return;
        };
        let Some(bytes) = text_data.get(from..to) else {
            return;
        };
        if is_padding(bytes) {
            return;
        }
        out.push(StaticSymbol {
            name: format!("{ORPHAN_PREFIX}{start:x}"),
            value: start,
            size: end - start,
            sym_type: STT_FUNC,
            bind: STB_LOCAL,
            shndx: named.first().map(|s| s.shndx).unwrap_or(0),
        });
    };

    for f in named {
        if f.value > cursor {
            push(cursor, f.value, &mut out);
        }
        cursor = cursor.max(f.value + f.size);
    }
    push(cursor, text_end, &mut out);
    out
}

/// True when a run of `.text` is nothing but inter-function padding.
fn is_padding(bytes: &[u8]) -> bool {
    // Zero fill, `andeq r0, r0, r0` (the all-zero encoding), and the two
    // canonical A32 no-ops are all a linker ever inserts between functions.
    const NOPS: [u32; 3] = [0x0000_0000, 0xe1a0_0000, 0xe320_f000];
    bytes
        .chunks(4)
        .all(|c| c.len() == 4 && NOPS.contains(&u32::from_le_bytes(c.try_into().unwrap())))
}

/// Real ELF section-header index of `.text` — `SectionIndex`, not the
/// position in `object`'s iterator, which skips the null section.
fn text_section_index(binary: &Binary<'_>) -> Option<u16> {
    binary
        .elf
        .sections()
        .find(|s| s.name().ok() == Some(".text"))
        .map(|s| s.index().0 as u16)
}

fn read_symtab(binary: &Binary<'_>) -> Result<Vec<StaticSymbol>> {
    let Some(symtab) = binary.elf.section_by_name(".symtab") else {
        return Ok(Vec::new());
    };
    let Some(strtab) = binary.elf.section_by_name(".strtab") else {
        return Ok(Vec::new());
    };
    let sym_data = symtab.data()?;
    let str_data = strtab.data()?;
    let entsize = binary.class.sym_entsize();

    let read_name = |off: u32| -> String {
        let off = off as usize;
        if off >= str_data.len() {
            return String::new();
        }
        let end = str_data[off..].iter().position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&str_data[off..off + end]).into_owned()
    };

    let mut out = Vec::with_capacity(sym_data.len() / entsize);
    for chunk in sym_data.chunks_exact(entsize) {
        // ELF32: name(4) value(4) size(4) info(1) other(1) shndx(2)
        // ELF64: name(4) info(1) other(1) shndx(2) value(8) size(8)
        let (st_name, st_value, st_size, st_info, st_shndx) = match binary.class {
            ElfClass::Elf32 => (
                u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                u32::from_le_bytes(chunk[4..8].try_into().unwrap()) as u64,
                u32::from_le_bytes(chunk[8..12].try_into().unwrap()) as u64,
                chunk[12],
                u16::from_le_bytes(chunk[14..16].try_into().unwrap()),
            ),
            ElfClass::Elf64 => (
                u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                u64::from_le_bytes(chunk[8..16].try_into().unwrap()),
                u64::from_le_bytes(chunk[16..24].try_into().unwrap()),
                chunk[4],
                u16::from_le_bytes(chunk[6..8].try_into().unwrap()),
            ),
        };
        let sym_type = st_info & 0xf;
        // AAELF marks Thumb entry points by setting bit 0 of `st_value`; it is
        // an ISA tag, not part of the address.
        let value = if binary.arch == delink_arch::Arch::Arm && sym_type == STT_FUNC {
            st_value & !1
        } else {
            st_value
        };
        out.push(StaticSymbol {
            name: read_name(st_name),
            value,
            size: st_size,
            sym_type,
            bind: st_info >> 4,
            shndx: st_shndx,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &str, value: u64, size: u64, sym_type: u8) -> StaticSymbol {
        StaticSymbol {
            name: name.to_string(),
            value,
            size,
            sym_type,
            bind: STB_LOCAL,
            shndx: 1,
        }
    }

    #[test]
    fn zero_sized_functions_get_a_size_from_the_next_symbol() {
        let syms = vec![
            sym("a", 0x100, 0x40, STT_FUNC),
            sym("asm_helper", 0x140, 0, STT_FUNC),
            sym("b", 0x180, 0x20, STT_FUNC),
        ];
        let fns = collect_text_functions(&syms, Some(1), 0x200);
        let sizes: Vec<(u64, u64)> = fns.iter().map(|f| (f.value, f.size)).collect();
        assert_eq!(sizes, vec![(0x100, 0x40), (0x140, 0x40), (0x180, 0x20)]);
    }

    #[test]
    fn the_last_zero_sized_function_runs_to_the_end_of_text() {
        let syms = vec![sym("tail", 0x100, 0, STT_FUNC)];
        let fns = collect_text_functions(&syms, Some(1), 0x180);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].size, 0x80);
    }

    /// Aliases at one address collapse to a single entry, and the one that
    /// carries a size wins so its extent isn't lost.
    #[test]
    fn aliases_collapse_preferring_the_sized_symbol() {
        let syms = vec![
            sym("alias", 0x100, 0, STT_FUNC),
            sym("real", 0x100, 0x40, STT_FUNC),
        ];
        let fns = collect_text_functions(&syms, Some(1), 0x200);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "real");
        assert_eq!(fns[0].size, 0x40);
    }

    /// A secondary entry point inside another function must not be emitted as
    /// its own function — that would duplicate the bytes.
    #[test]
    fn interior_entry_points_fold_into_the_enclosing_function() {
        let syms = vec![
            sym("outer", 0x100, 0x80, STT_FUNC),
            sym("inner_entry", 0x120, 0x60, STT_FUNC),
            sym("next", 0x180, 0x10, STT_FUNC),
        ];
        let fns = collect_text_functions(&syms, Some(1), 0x200);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["outer", "next"]);
        let total: u64 = fns.iter().map(|f| f.size).sum();
        assert_eq!(total, 0x90, "bytes must be covered exactly once");
    }

    #[test]
    fn symbols_outside_text_are_ignored() {
        let mut elsewhere = sym("data_thing", 0x100, 4, STT_FUNC);
        elsewhere.shndx = 9;
        let fns = collect_text_functions(&[elsewhere], Some(1), 0x200);
        assert!(fns.is_empty());
    }

    #[test]
    fn uncovered_code_becomes_an_orphan_but_padding_does_not() {
        let named = vec![sym("a", 0x1000, 8, STT_FUNC), sym("b", 0x1020, 8, STT_FUNC)];
        let mut text = Vec::new();
        text.extend_from_slice(&[0u8; 8]); // a
        text.extend_from_slice(&0xe52d_e004u32.to_le_bytes()); // real code
        text.extend_from_slice(&0xe1a0_0000u32.to_le_bytes()); // still the gap
        text.extend_from_slice(&[0u8; 8]); // padding before b
        text.extend_from_slice(&[0u8; 8]); // b
        text.extend_from_slice(&[0u8; 8]); // trailing padding

        let orphans = find_orphan_regions(&named, 0x1000, &text, 0x1030);
        assert_eq!(orphans.len(), 1, "only the run holding real code counts");
        assert_eq!(orphans[0].value, 0x1008);
        assert_eq!(orphans[0].size, 0x18);
        assert!(orphans[0].name.starts_with(ORPHAN_PREFIX));
    }

    #[test]
    fn padding_recognizes_zero_and_both_nop_encodings() {
        assert!(is_padding(&[0u8; 8]));
        assert!(is_padding(&0xe1a0_0000u32.to_le_bytes()));
        assert!(is_padding(&0xe320_f000u32.to_le_bytes()));
        assert!(!is_padding(&0xe52d_e004u32.to_le_bytes()));
        // A trailing partial word is not padding: it is unexplained data.
        assert!(!is_padding(&[0u8; 3]));
    }
}
