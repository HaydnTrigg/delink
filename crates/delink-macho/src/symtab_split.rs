//! Symtab-based CU reconstruction for stripped Mach-O binaries.
//!
//! Used when neither DWARF nor STABS debug info is present.  Reads the
//! regular `LC_SYMTAB` N_SECT symbols, filters to those in the `__text`
//! section, sorts them by address, and groups them into synthetic compilation
//! units of a fixed size so the rest of the pipeline still works.

use anyhow::Result;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind};

use crate::cu::{MachoCompilationUnit, MachoFunction, MachoCuIndex};

/// Maximum number of functions bundled into one synthetic CU.
///
/// Keeping this value moderate avoids producing tens-of-thousands of tiny
/// files while still giving reasonable granularity.
const BATCH_SIZE: usize = 100;

pub fn build_cu_index_from_symtab(data: &[u8]) -> Result<MachoCuIndex> {
    let file = object::File::parse(data)?;

    // Find the __TEXT,__text address range so we can filter to code symbols.
    let text_range = file
        .sections()
        .find(|s| {
            s.segment_name().ok().flatten() == Some("__TEXT")
                && s.name().ok() == Some("__text")
        })
        .map(|s| s.address()..s.address() + s.size());

    // Also consider __coalesced_text (templates / inlined code deduplicated by the linker).
    let coal_range = file
        .sections()
        .find(|s| {
            s.segment_name().ok().flatten() == Some("__TEXT")
                && s.name().ok() == Some("__coalesced_text")
        })
        .map(|s| s.address()..s.address() + s.size());

    // Collect all function-like symbols that lie in a text section.
    let mut fns: Vec<(u64, String)> = file
        .symbols()
        .filter(|sym| {
            // Keep defined, named symbols that look like functions.
            if sym.is_undefined() || sym.kind() == SymbolKind::Unknown {
                return false;
            }
            let addr = sym.address();
            let in_text = text_range.as_ref().is_some_and(|r| r.contains(&addr));
            let in_coal = coal_range.as_ref().is_some_and(|r| r.contains(&addr));
            if !in_text && !in_coal {
                return false;
            }
            let name = sym.name().unwrap_or("").trim();
            !name.is_empty()
        })
        .map(|sym| (sym.address(), sym.name().unwrap_or("").to_string()))
        .collect();

    if fns.is_empty() {
        tracing::warn!("symtab fallback: no text symbols found");
        return Ok(MachoCuIndex { units: vec![] });
    }

    fns.sort_by_key(|(addr, _)| *addr);
    fns.dedup_by_key(|(addr, _)| *addr);
    tracing::info!(
        "symtab fallback: {} text symbols → {} synthetic CUs",
        fns.len(),
        fns.len().div_ceil(BATCH_SIZE)
    );

    // Compute function sizes from adjacent symbol addresses.
    let addrs: Vec<u64> = fns.iter().map(|(a, _)| *a).collect();
    let sizes: Vec<u64> = addrs
        .windows(2)
        .map(|w| w[1] - w[0])
        .chain(std::iter::once(0u64))
        .collect();

    // Group into batches and build CUs.
    let mut units = Vec::new();
    let mut cu_id = 0usize;

    for (batch_idx, batch) in fns.chunks(BATCH_SIZE).enumerate() {
        let batch_start = batch_idx * BATCH_SIZE;
        let functions: Vec<MachoFunction> = batch
            .iter()
            .enumerate()
            .map(|(i, (addr, name))| MachoFunction {
                name: name.clone(),
                linkage_name: Some(name.clone()),
                addr: *addr,
                size: sizes[batch_start + i],
                external: true,
            })
            .collect();

        let ranges = functions
            .iter()
            .filter(|f| f.size > 0)
            .map(|f| f.addr..f.addr + f.size)
            .collect();

        let cu_name = functions[0].name.clone();

        units.push(MachoCompilationUnit {
            id: cu_id,
            name: cu_name,
            comp_dir: None,
            oso_path: None,
            ranges,
            functions,
            variables: vec![],
        });
        cu_id += 1;
    }

    Ok(MachoCuIndex { units })
}
