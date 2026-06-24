//! Symbol resolution for iced-x86 relocation recovery.
//!
//! Builds an address → label map from the exported functions and names, so the
//! recovery passes in [`delink_x86`] / [`delink_x86_64`] can turn a call/jump
//! target or RIP-relative reference into `(symbol_name, addend)`.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use crate::{IdaModel, Reloc, SegClass};

/// Synthetic symbols marking the start of each shared data section, used when a
/// data reference lands inside a section but not on a named address.
pub const SYM_DATA_START: &str = "__delink_ida_data_start";
pub const SYM_CONST_START: &str = "__delink_ida_const_start";
pub const SYM_BSS_START: &str = "__delink_ida_bss_start";

#[derive(Debug, Clone)]
struct FnInfo {
    end: u64,
    name: String,
}

/// A named data variable (a name that is not a function and lives in a data
/// section) — emitted into the shared data object.
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub public: bool,
}

pub struct IdaSymbols {
    /// Exact address → name (functions and named data/code labels).
    names: HashMap<u64, String>,
    /// Function start → info, for resolving targets that land mid-function.
    funcs: BTreeMap<u64, FnInfo>,
    /// Named data variables, by address.
    pub variables: BTreeMap<u64, Variable>,
    /// Fixup-table entries by address, for absolute-relocation lookup.
    relocs: BTreeMap<u64, Reloc>,
    data_range: Option<Range<u64>>,
    const_range: Option<Range<u64>>,
    bss_range: Option<Range<u64>>,
}

impl IdaSymbols {
    /// Build the resolver from the model plus the combined relocation set
    /// (IDA fixups ∪ PE `.reloc`); see [`crate::combined_relocations`].
    pub fn build(model: &IdaModel, relocs: &[Reloc]) -> Self {
        let mut names: HashMap<u64, String> = HashMap::new();
        let mut funcs: BTreeMap<u64, FnInfo> = BTreeMap::new();

        for f in &model.functions {
            funcs.insert(
                f.start,
                FnInfo {
                    end: f.end,
                    name: f.name.clone(),
                },
            );
            names.entry(f.start).or_insert_with(|| f.name.clone());
        }
        // Names take precedence for exact matches (they include data labels and
        // may carry better names than the dummy `sub_*`).
        for n in &model.names {
            names.insert(n.addr, n.name.clone());
        }

        let section_range = |pred: &dyn Fn(SegClass) -> bool| -> Option<Range<u64>> {
            model
                .sections
                .iter()
                .find(|s| pred(s.class))
                .map(|s| s.start..s.end)
        };
        let data_range = section_range(&|c| c == SegClass::Data);
        let const_range = section_range(&|c| c == SegClass::Const);
        let bss_range = section_range(&|c| c == SegClass::Bss);

        // Named variables: names that are not functions and live in a data section.
        let in_data = |va: u64| {
            [&data_range, &const_range, &bss_range]
                .iter()
                .any(|r| r.as_ref().is_some_and(|r| r.contains(&va)))
        };
        let mut variables: BTreeMap<u64, Variable> = BTreeMap::new();
        for n in &model.names {
            if n.is_func || funcs.contains_key(&n.addr) {
                continue;
            }
            if in_data(n.addr) {
                variables.insert(
                    n.addr,
                    Variable {
                        name: n.name.clone(),
                        public: n.public,
                    },
                );
            }
        }

        let relocs = relocs.iter().map(|r| (r.addr, r.clone())).collect();

        Self {
            names,
            funcs,
            variables,
            relocs,
            data_range,
            const_range,
            bss_range,
        }
    }

    /// Fixup-table entries whose location falls within `range`.
    pub fn relocs_in(&self, range: Range<u64>) -> impl Iterator<Item = &Reloc> {
        self.relocs.range(range).map(|(_, r)| r)
    }

    /// Resolve a code target (call/jump destination) → `(symbol, addend)`.
    pub fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        if let Some(name) = self.names.get(&va) {
            return Some((name.clone(), 0));
        }
        if let Some((start, info)) = self.funcs.range(..=va).next_back() {
            if va < info.end {
                return Some((info.name.clone(), (va - start) as i64));
            }
        }
        None
    }

    /// Resolve a data reference → `(symbol, addend)`.
    pub fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        if let Some(name) = self.names.get(&va) {
            return Some((name.clone(), 0));
        }
        if let Some((start, info)) = self.funcs.range(..=va).next_back() {
            if va < info.end {
                return Some((info.name.clone(), (va - start) as i64));
            }
        }
        self.section_relative(va)
    }

    fn section_relative(&self, va: u64) -> Option<(String, i64)> {
        let check = |range: &Option<Range<u64>>, sym: &'static str| {
            range.as_ref().and_then(|r| {
                r.contains(&va)
                    .then(|| (sym.to_string(), (va - r.start) as i64))
            })
        };
        check(&self.data_range, SYM_DATA_START)
            .or_else(|| check(&self.const_range, SYM_CONST_START))
            .or_else(|| check(&self.bss_range, SYM_BSS_START))
    }
}

impl delink_x86::recover::SymbolResolver for IdaSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        IdaSymbols::resolve_code(self, va)
    }
    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        IdaSymbols::resolve_data(self, va)
    }
}

impl delink_x86_64::recover::SymbolResolver for IdaSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        IdaSymbols::resolve_code(self, va)
    }
    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        IdaSymbols::resolve_data(self, va)
    }
}
