//! STABS symbol-table parser for Mach-O binaries.
//!
//! Reconstructs compilation units from LC_SYMTAB STABS entries when the
//! binary has no `__DWARF` segment.  Produces the same `MachoCuIndex`
//! types as the DWARF path so the rest of the pipeline is unaffected.
//!
//! Supports both little-endian (x86/x86-64) and big-endian (PPC/PPC64)
//! Mach-O binaries.

use anyhow::Result;

use crate::cu::{MachoCompilationUnit, MachoCuIndex, MachoFunction, MachoVariable};

// STABS n_type codes (even values ≥ 0x20 are STABS; odd = regular sym flags).
const N_GSYM: u8 = 0x20; // global data symbol (value=0; addr in symtab)
const N_FUN: u8 = 0x24; // function start (value=addr) / end (name="", value=size)
const N_STSYM: u8 = 0x26; // file-scope static initialized data (value=addr)
const N_LCSYM: u8 = 0x28; // file-scope static .bss data (value=addr)
const N_SO: u8 = 0x64; // source file directory (1st) / filename (2nd) / end ("")
const N_OSO: u8 = 0x66; // object file path (Apple extension)

// nlist_32 layout: strx(4) type(1) sect(1) desc(2) value(4) = 12 bytes
struct Nl {
    strx: u32,
    ntype: u8,
    value: u32,
}

pub fn build_cu_index_from_stabs(data: &[u8], little_endian: bool) -> Result<MachoCuIndex> {
    let (syms, str_data) = match find_symtab(data, little_endian) {
        Some(v) => v,
        None => {
            return Ok(MachoCuIndex {
                units: vec![],
                source: crate::cu::DebugInfoSource::Stabs,
            })
        }
    };

    let read_str = |strx: u32| -> String {
        let strx = strx as usize;
        if strx >= str_data.len() {
            return String::new();
        }
        let end = str_data[strx..].iter().position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&str_data[strx..strx + end]).into_owned()
    };

    let mut units = Vec::new();
    let mut cu_id = 0usize;
    let mut i = 0usize;

    while i < syms.len() {
        // Scan forward to the next N_SO that starts a CU.
        if syms[i].ntype != N_SO {
            i += 1;
            continue;
        }
        let so1 = read_str(syms[i].strx);
        if so1.is_empty() {
            // End-of-CU marker; skip and keep looking.
            i += 1;
            continue;
        }
        i += 1;

        // Determine directory + filename.
        let (comp_dir, cu_name) =
            if i < syms.len() && syms[i].ntype == N_SO && !read_str(syms[i].strx).is_empty() {
                let so2 = read_str(syms[i].strx);
                i += 1;
                (Some(so1), so2)
            } else {
                (None, so1)
            };

        // Capture optional N_OSO (original object file / archive member path).
        let oso_path = if i < syms.len() && syms[i].ntype == N_OSO {
            let s = read_str(syms[i].strx);
            i += 1;
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        // Collect functions and variables until the next N_SO.
        let mut functions: Vec<MachoFunction> = Vec::new();
        let mut variables: Vec<MachoVariable> = Vec::new();
        let mut open_fun: Option<(String, u64)> = None;

        while i < syms.len() {
            let sym = &syms[i];
            match sym.ntype {
                N_SO => break, // CU boundary — do NOT advance i; outer loop handles it.
                N_FUN => {
                    let name = read_str(sym.strx);
                    if name.is_empty() {
                        // Closing record: value = size of the function.
                        if let Some((fname, faddr)) = open_fun.take() {
                            let size = sym.value as u64;
                            functions.push(make_fn(fname, faddr, size));
                        }
                    } else {
                        // Opening record: close any previous unclosed function first.
                        if let Some((fname, faddr)) = open_fun.take() {
                            let size = (sym.value as u64).saturating_sub(faddr);
                            functions.push(make_fn(fname, faddr, size));
                        }
                        open_fun = Some((stabs_name(&name), sym.value as u64));
                    }
                }
                N_STSYM | N_LCSYM => {
                    let addr = sym.value as u64;
                    let raw = read_str(sym.strx);
                    let name = stabs_name(&raw);
                    if addr != 0 && !name.is_empty() {
                        variables.push(MachoVariable {
                            name: name.clone(),
                            linkage_name: Some(name),
                            addr,
                            external: false,
                        });
                    }
                }
                N_GSYM => {
                    // Global data symbol — address is 0 in STABS; skip for now.
                }
                _ => {}
            }
            i += 1;
        }

        // Close any function whose end record was missing.
        if let Some((fname, faddr)) = open_fun.take() {
            if faddr != 0 {
                functions.push(make_fn(fname, faddr, 0));
            }
        }

        if functions.is_empty() && variables.is_empty() {
            continue;
        }

        let ranges = functions
            .iter()
            .filter(|f| f.size > 0)
            .map(|f| f.addr..f.addr + f.size)
            .collect();

        units.push(MachoCompilationUnit {
            id: cu_id,
            name: cu_name,
            comp_dir,
            oso_path,
            ranges,
            functions,
            variables,
        });
        cu_id += 1;
    }

    tracing::info!("STABS: parsed {} compilation units", units.len());
    Ok(MachoCuIndex {
        units,
        source: crate::cu::DebugInfoSource::Stabs,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_symtab(data: &[u8], le: bool) -> Option<(Vec<Nl>, &[u8])> {
    if data.len() < 28 {
        return None;
    }

    let r32 = |off: usize| -> Option<u32> {
        let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };

    let ncmds = r32(16)? as usize;
    let sizeofcmds = r32(20)? as usize;
    let cmds_end = (28 + sizeofcmds).min(data.len());

    let mut symtab_off = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;

    let mut pos = 28usize;
    let mut count = 0;
    while pos + 8 <= cmds_end && count < ncmds {
        let cmd = r32(pos)?;
        let cmdsize = r32(pos + 4)? as usize;
        if cmd == 0x2 && cmdsize >= 24 {
            symtab_off = r32(pos + 8)?;
            nsyms = r32(pos + 12)?;
            stroff = r32(pos + 16)?;
            break;
        }
        if cmdsize == 0 {
            break;
        }
        pos += cmdsize;
        count += 1;
    }

    if nsyms == 0 {
        return None;
    }

    let sym_start = symtab_off as usize;
    let sym_end = sym_start.checked_add(nsyms as usize * 12)?;
    if sym_end > data.len() {
        return None;
    }

    let sym_data = &data[sym_start..sym_end];
    let str_data = if (stroff as usize) < data.len() {
        &data[stroff as usize..]
    } else {
        &[]
    };

    let r32_chunk = |chunk: &[u8], off: usize| -> u32 {
        let b: [u8; 4] = chunk[off..off + 4].try_into().unwrap();
        if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };

    let mut syms = Vec::with_capacity(nsyms as usize);
    for chunk in sym_data.chunks_exact(12) {
        let ntype = chunk[4];
        // Only keep STABS entries (even values ≥ 0x20, no N_EXT / N_PEXT bits).
        if ntype < 0x20 || ntype & 1 != 0 {
            syms.push(Nl {
                strx: 0,
                ntype,
                value: 0,
            });
            continue;
        }
        syms.push(Nl {
            strx: r32_chunk(chunk, 0),
            ntype,
            value: r32_chunk(chunk, 8),
        });
    }

    Some((syms, str_data))
}

fn make_fn(name: String, addr: u64, size: u64) -> MachoFunction {
    MachoFunction {
        name: name.clone(),
        linkage_name: Some(name),
        addr,
        size,
        external: true,
    }
}

/// Strip STABS type descriptor suffix (`:F(0,1)` → keep only up to `:`).
fn stabs_name(raw: &str) -> String {
    match raw.find(':') {
        Some(i) => raw[..i].to_string(),
        None => raw.to_string(),
    }
}
