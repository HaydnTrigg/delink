//! Global symbol resolver for x86-64 PE relocation recovery.

use crate::cu::PeFunction;
use crate::PeSection;
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

pub struct PeGlobalSymbols {
    /// VA → function descriptor (from PDB).
    pub functions: BTreeMap<u64, PeFunction>,
    /// IAT slot VA → `"__imp_funcname"` (from PE import table).
    pub imports: HashMap<u64, String>,
    /// Well-known data section ranges for section-relative fallbacks.
    pub text_range: Option<Range<u64>>,
    pub rdata_range: Option<Range<u64>>,
    pub data_range: Option<Range<u64>>,
    pub bss_range: Option<Range<u64>>,
    pub idata_range: Option<Range<u64>>,
}

impl PeGlobalSymbols {
    pub fn build(
        functions: BTreeMap<u64, PeFunction>,
        imports: &HashMap<u64, String>,
        sections: &[PeSection],
        _image_base: u64,
    ) -> Self {
        let section_range = |name: &str| -> Option<Range<u64>> {
            sections
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.va..s.va + s.virtual_size)
        };

        Self {
            functions,
            imports: imports.clone(),
            text_range: section_range(".text"),
            rdata_range: section_range(".rdata"),
            data_range: section_range(".data"),
            bss_range: section_range(".bss"),
            idata_range: section_range(".idata"),
        }
    }

    /// Resolve a code target VA (from a call/jmp) to `(symbol_name, addend)`.
    pub fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        // Exact function start.
        if let Some(f) = self.functions.get(&va) {
            return Some((f.name.clone(), 0));
        }
        // Interior of a known function.
        if let Some((start, f)) = self.functions.range(..=va).next_back() {
            if va < *start + f.size as u64 {
                return Some((f.name.clone(), (va - *start) as i64));
            }
        }
        // IAT thunk (indirect calls via __imp_*).
        if let Some(name) = self.imports.get(&va) {
            return Some((name.clone(), 0));
        }
        None
    }

    /// Resolve a data reference VA (from RIP-relative addressing) to `(symbol, addend)`.
    pub fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        // IAT slot → __imp_funcname.
        if let Some(name) = self.imports.get(&va) {
            return Some((name.clone(), 0));
        }
        // Exact function or variable.
        if let Some(f) = self.functions.get(&va) {
            return Some((f.name.clone(), 0));
        }
        // Interior of a function.
        if let Some((start, f)) = self.functions.range(..=va).next_back() {
            if va < *start + f.size as u64 {
                return Some((f.name.clone(), (va - *start) as i64));
            }
        }
        // Section-relative fallback.
        self.section_relative(va)
    }

    fn section_relative(&self, va: u64) -> Option<(String, i64)> {
        let check = |range: &Option<std::ops::Range<u64>>, name: &'static str| {
            range.as_ref().and_then(|r| {
                if r.contains(&va) {
                    Some((name.to_string(), (va - r.start) as i64))
                } else {
                    None
                }
            })
        };
        check(&self.rdata_range, "__delink_pe_rdata_start")
            .or_else(|| check(&self.data_range, "__delink_pe_data_start"))
            .or_else(|| check(&self.bss_range, "__delink_pe_bss_start"))
            .or_else(|| check(&self.idata_range, "__delink_pe_idata_start"))
    }

    pub fn in_text(&self, va: u64) -> bool {
        self.text_range
            .as_ref()
            .is_some_and(|r| r.contains(&va))
    }
}

impl delink_x86_64::recover::SymbolResolver for PeGlobalSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_code(self, va)
    }

    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_data(self, va)
    }
}

impl delink_x86::recover::SymbolResolver for PeGlobalSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_code(self, va)
    }

    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_data(self, va)
    }
}
