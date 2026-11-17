//! Global symbol resolver for x86-64 and x86 PE relocation recovery.

use crate::cu::{PeFunction, PeVariable};
use crate::PeSection;
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

pub struct PeGlobalSymbols {
    /// PE image base (from the optional header); the target of the
    /// `lea reg, [rip+imagebase]` idiom MSVC emits for RVA-relative addressing.
    pub image_base: u64,
    /// VA → function descriptor (from PDB procedures).
    pub functions: BTreeMap<u64, PeFunction>,
    /// VA → data variable descriptor (from PDB S_GDATA32 / S_LDATA32).
    pub variables: BTreeMap<u64, PeVariable>,
    /// `.tls` section-relative offset → thread-local variable name (SECREL target).
    pub tls_variables: BTreeMap<u32, String>,
    /// VA → public code symbol name with no per-module procedure record
    /// (statically-linked CRT routines like `memcpy`). Fallback for call targets.
    pub code_publics: BTreeMap<u64, String>,
    /// IAT slot VA → `"__imp_funcname"` (from PE import table).
    pub imports: HashMap<u64, String>,
    /// Well-known data section ranges for section-relative fallbacks.
    pub text_range: Option<Range<u64>>,
    pub rdata_range: Option<Range<u64>>,
    pub data_range: Option<Range<u64>>,
    pub bss_range: Option<Range<u64>>,
    pub idata_range: Option<Range<u64>>,
    /// `.rdata` section bytes (start VA, data), used to read string-literal
    /// content by address and synthesize its MSVC `??_C@` decorated name when
    /// the PDB has no symbol for it (folded/anonymous string COMDATs).
    rdata: Option<(u64, Vec<u8>)>,
    /// Name anonymous `.rdata` string literals after MSVC's `??_C@…` scheme.
    ///
    /// Right for a PDB-driven split, where the recompiled MSVC objects define
    /// those names. Wrong for an image built by another toolchain (MinGW): no
    /// object would define them, so they must stay section-relative.
    pub synthesize_string_literals: bool,
}

impl PeGlobalSymbols {
    pub fn build(
        functions: BTreeMap<u64, PeFunction>,
        variables: BTreeMap<u64, PeVariable>,
        tls_variables: BTreeMap<u32, String>,
        code_publics: BTreeMap<u64, String>,
        imports: &HashMap<u64, String>,
        sections: &[PeSection],
        image_base: u64,
    ) -> Self {
        let section_range = |name: &str| -> Option<Range<u64>> {
            sections
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.va..s.va + s.virtual_size)
        };

        let rdata = sections
            .iter()
            .find(|s| s.name == ".rdata")
            .map(|s| (s.va, s.data.clone()));

        Self {
            image_base,
            functions,
            variables,
            tls_variables,
            code_publics,
            imports: imports.clone(),
            text_range: section_range(".text"),
            rdata_range: section_range(".rdata"),
            data_range: section_range(".data"),
            bss_range: section_range(".bss"),
            idata_range: section_range(".idata"),
            rdata,
            synthesize_string_literals: true,
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
        // Public code symbol with no procedure record (e.g. `memcpy`). Exact
        // start, or interior bounded by the next such symbol.
        if let Some(name) = self.code_publics.get(&va) {
            return Some((name.clone(), 0));
        }
        if let Some((start, name)) = self.code_publics.range(..=va).next_back() {
            let next = self
                .code_publics
                .range((*start + 1)..)
                .next()
                .map(|(n, _)| *n)
                .unwrap_or(u64::MAX);
            let sec_end = self.text_range.as_ref().map(|r| r.end).unwrap_or(u64::MAX);
            if va < next.min(sec_end) {
                return Some((name.clone(), (va - *start) as i64));
            }
        }
        None
    }

    /// Resolve a data reference VA (RIP-relative or absolute pointer) to `(symbol, addend)`.
    pub fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        // The image base itself: MSVC loads it with `lea reg, [rip+imagebase]`
        // as the anchor for RVA-relative addressing (jump tables, /Gy data).
        // The linker provides `__ImageBase` as an absolute symbol at the base.
        if va == self.image_base {
            return Some(("__ImageBase".to_string(), 0));
        }
        // IAT slot → __imp_funcname.
        if let Some(name) = self.imports.get(&va) {
            return Some((name.clone(), 0));
        }
        // Exact named variable.
        if let Some(v) = self.variables.get(&va) {
            return Some((v.name.clone(), 0));
        }
        // Exact function or data label.
        if let Some(f) = self.functions.get(&va) {
            return Some((f.name.clone(), 0));
        }
        // Interior of a sized data global (e.g. `async_globals+0x2ca8` into a
        // struct/array), bounded by the variable's PDB type size.
        if let Some((start, v)) = self.variables.range(..=va).next_back() {
            if v.size > 0 && va < *start + v.size as u64 {
                return Some((v.name.clone(), (va - *start) as i64));
            }
        }
        // Interior of a function (e.g. reference into a jump table or literal pool
        // that lives inside a function's address range in the PDB).
        if let Some((start, f)) = self.functions.range(..=va).next_back() {
            if va < *start + f.size as u64 {
                return Some((f.name.clone(), (va - *start) as i64));
            }
        }
        // String literal in `.rdata` with no PDB symbol: fold-anonymous string
        // COMDATs carry no symbol record, so look the literal up by address and
        // synthesize the same `??_C@…` decorated name MSVC (and thus our own
        // recompiled object) produces for those bytes.
        if self.synthesize_string_literals {
            if let Some(name) = self.synthesize_string_symbol(va) {
                return Some((name, 0));
            }
        }
        // Interior of an unsized data global (public-only symbol, forward-ref
        // template type): extend to the next variable, capped at the section
        // end. After string synthesis so a section-marker global at the base
        // (e.g. `k_read_only_data_start`) can't swallow real string literals.
        if let Some((start, v)) = self.variables.range(..=va).next_back() {
            if v.size == 0 {
                let next = self
                    .variables
                    .range((*start + 1)..)
                    .next()
                    .map(|(n, _)| *n)
                    .unwrap_or(u64::MAX);
                if va < next.min(self.section_end(*start).unwrap_or(u64::MAX)) {
                    return Some((v.name.clone(), (va - *start) as i64));
                }
            }
        }
        // Section-relative fallback for anonymous data.
        self.section_relative(va)
    }

    /// If `va` points at a narrow (char) string literal in `.rdata` that has no
    /// PDB symbol, reproduce MSVC's `??_C@…` decorated name from the bytes.
    ///
    /// Guards against non-string constant data (float pools, vtables, jump
    /// tables) by requiring a printable, NUL-terminated run that begins at a
    /// literal boundary (preceded by a NUL or the section start).
    fn synthesize_string_symbol(&self, va: u64) -> Option<String> {
        let (start_va, data) = self.rdata.as_ref()?;
        if va < *start_va {
            return None;
        }
        let off = (va - *start_va) as usize;
        // A literal starts at a boundary: section start, or just past a NUL.
        if off != 0 && data.get(off - 1).copied() != Some(0) {
            return None;
        }
        let rest = data.get(off..)?;

        // Scan a printable, NUL-terminated narrow string within a sane bound.
        const MAX_LEN: usize = 4096;
        let mut end = None;
        for (i, &b) in rest.iter().take(MAX_LEN).enumerate() {
            if b == 0 {
                end = Some(i);
                break;
            }
            let printable = matches!(b, b'\t' | b'\n' | b'\r') || (0x20..=0x7E).contains(&b);
            if !printable {
                return None;
            }
        }
        let end = end?;
        // Empty string (`end == 0`, a lone NUL) is still a real literal
        // (`??_C@_00CNPNBAHC@?$AA@`); only reached for actually-referenced VAs.
        Some(crate::mangle::narrow_string_symbol(&rest[..end]))
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
        self.text_range.as_ref().is_some_and(|r| r.contains(&va))
    }

    /// End VA of the data section containing `va` (caps gap-based interior
    /// sizing so an unsized global can't spill across a section boundary).
    fn section_end(&self, va: u64) -> Option<u64> {
        [
            &self.rdata_range,
            &self.data_range,
            &self.bss_range,
            &self.idata_range,
        ]
        .into_iter()
        .flatten()
        .find(|r| r.contains(&va))
        .map(|r| r.end)
    }
}

impl delink_x86_64::recover::SymbolResolver for PeGlobalSymbols {
    fn resolve_code(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_code(self, va)
    }

    fn resolve_data(&self, va: u64) -> Option<(String, i64)> {
        PeGlobalSymbols::resolve_data(self, va)
    }

    fn image_base(&self) -> u64 {
        self.image_base
    }

    fn in_text(&self, va: u64) -> bool {
        PeGlobalSymbols::in_text(self, va)
    }

    fn resolve_tls_offset(&self, offset: u32) -> Option<(String, i64)> {
        self.tls_variables
            .get(&offset)
            .map(|name| (name.clone(), 0))
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
