//! Global symbol resolver for Mach-O / x86 relocation recovery.

use crate::cu::{MachoCuIndex, MachoFunction, MachoVariable};
use crate::MachoSection;
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

pub struct MachoGlobalSymbols {
    /// VA → function descriptor (from DWARF).
    pub functions: BTreeMap<u64, MachoFunction>,
    /// VA → data variable descriptor (from DWARF).
    pub variables: BTreeMap<u64, MachoVariable>,
    /// Stub VA → external symbol name (from LC_DYSYMTAB).
    pub stubs: HashMap<u64, String>,
    pub text_range: Option<Range<u64>>,
    pub data_range: Option<Range<u64>>,
    pub const_range: Option<Range<u64>>,
    pub bss_range: Option<Range<u64>>,
    pub cstring_range: Option<Range<u64>>,
}

pub const SYM_DATA_START: &str = "__delink_macho_data_start";
pub const SYM_CONST_START: &str = "__delink_macho_const_start";
pub const SYM_BSS_START: &str = "__delink_macho_bss_start";

impl MachoGlobalSymbols {
    pub fn build(
        cu_index: &MachoCuIndex,
        stubs: &HashMap<u64, String>,
        sections: &[MachoSection],
    ) -> Self {
        let mut functions: BTreeMap<u64, MachoFunction> = BTreeMap::new();
        let mut variables: BTreeMap<u64, MachoVariable> = BTreeMap::new();

        for cu in &cu_index.units {
            for f in &cu.functions {
                if f.size > 0 {
                    functions.entry(f.addr).or_insert_with(|| f.clone());
                }
            }
            for v in &cu.variables {
                if v.addr != 0 {
                    variables.entry(v.addr).or_insert_with(|| v.clone());
                }
            }
        }

        let section_range = |seg: &str, name: &str| -> Option<Range<u64>> {
            sections
                .iter()
                .find(|s| s.segment == seg && s.name == name)
                .map(|s| s.addr..s.addr + s.size)
        };

        Self {
            functions,
            variables,
            stubs: stubs.clone(),
            text_range: section_range("__TEXT", "__text"),
            data_range: section_range("__DATA", "__data"),
            const_range: section_range("__DATA", "__const"),
            bss_range: section_range("__DATA", "__bss"),
            cstring_range: section_range("__TEXT", "__cstring"),
        }
    }

    /// Resolve a code target VA (call / jmp destination) to `(symbol_name, addend)`.
    pub fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        if let Some(f) = self.functions.get(&va) {
            return Some((f.symbol_name().to_string(), 0));
        }
        if let Some((start, f)) = self.functions.range(..=va).next_back() {
            if va < *start + f.size {
                return Some((f.symbol_name().to_string(), (va - *start) as i64));
            }
        }
        if let Some(name) = self.stubs.get(&va) {
            return Some((name.clone(), 0));
        }
        None
    }

    /// Resolve a data reference VA to `(symbol_name, addend)`.
    pub fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        if let Some(name) = self.stubs.get(&va) {
            return Some((name.clone(), 0));
        }
        if let Some(v) = self.variables.get(&va) {
            return Some((v.symbol_name().to_string(), 0));
        }
        if let Some(f) = self.functions.get(&va) {
            return Some((f.symbol_name().to_string(), 0));
        }
        if let Some((start, f)) = self.functions.range(..=va).next_back() {
            if va < *start + f.size {
                return Some((f.symbol_name().to_string(), (va - *start) as i64));
            }
        }
        self.section_relative(va)
    }

    fn section_relative(&self, va: u64) -> Option<(String, i64)> {
        let check = |range: &Option<Range<u64>>, sym: &'static str| {
            range.as_ref().and_then(|r| {
                if r.contains(&va) {
                    Some((sym.to_string(), (va - r.start) as i64))
                } else {
                    None
                }
            })
        };
        check(&self.data_range, SYM_DATA_START)
            .or_else(|| check(&self.const_range, SYM_CONST_START))
            .or_else(|| check(&self.bss_range, SYM_BSS_START))
    }

    pub fn in_text(&self, va: u64) -> bool {
        self.text_range.as_ref().is_some_and(|r| r.contains(&va))
    }
}

// Implement the x86 SymbolResolver trait so the recovery module can use us.
impl delink_x86::recover::SymbolResolver for MachoGlobalSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        MachoGlobalSymbols::resolve_code(self, va)
    }

    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        MachoGlobalSymbols::resolve_data(self, va)
    }
}
