//! User-editable symtab.json: maps output `.o` filenames to arrays of symbol
//! names.  The default JSON puts each function in its own file.  Edit the
//! arrays to group symbols, rename keys to rename output files, then re-run
//! with `--symtab <path>`.  All metadata is re-read from the binary at split
//! time via `build_lookup`.

use anyhow::Result;
use std::collections::{BTreeMap, HashMap};

// nlist n_type bit masks
const N_EXT: u8 = 0x01;
const N_PEXT: u8 = 0x10;
const N_TYPE_MASK: u8 = 0x0e;
const N_STAB_MASK: u8 = 0xe0;
const N_SECT_VAL: u8 = 0x0e;

// Load-command IDs
const LC_SYMTAB: u32 = 0x2;
const LC_SEGMENT: u32 = 0x1;

const SEGMENT_CMD32_SIZE: usize = 56;
const SECTION32_SIZE: usize = 68;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The editable symtab JSON: output-filename → array of symbol names.
///
/// Rename a key to rename the output file.  Move symbol names between arrays
/// to group multiple functions into the same `.o`.
pub type SymtabJson = BTreeMap<String, Vec<String>>;

/// Rich per-symbol metadata resolved from the binary at split time.
#[derive(Debug, Clone)]
pub struct SymtabInfo {
    pub addr: u64,
    pub size: u64,
    pub n_type: String,
    pub n_sect: u8,
    pub n_desc: Vec<String>,
    pub external: bool,
    pub private_external: bool,
}

/// Symbol name → metadata, built from the binary's LC_SYMTAB.
pub type SymtabLookup = HashMap<String, SymtabInfo>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a default `SymtabJson` from the binary: one symbol name per output file.
pub fn generate(data: &[u8]) -> Result<SymtabJson> {
    let mut json: SymtabJson = BTreeMap::new();
    for sym in parse_text_symbols(data) {
        let cu = format!("{}.o", sanitize_filename(&sym.name));
        json.entry(cu).or_default().push(sym.name);
    }
    Ok(json)
}

/// Build a `SymtabJson` from a DWARF/STABS `MachoCuIndex`, grouping functions
/// by their CU.  The output filename matches the stem used by `split_all_macho`.
pub fn generate_from_cu_index(cu_index: &crate::cu::MachoCuIndex) -> SymtabJson {
    let mut json: SymtabJson = BTreeMap::new();
    for cu in &cu_index.units {
        let stem = {
            let basename = cu.name.rsplit(['/', '\\']).next().unwrap_or(&cu.name);
            let stem = match basename.rfind('.') {
                Some(i) => &basename[..i],
                None => basename,
            };
            stem.chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '_' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        };
        let filename = format!("{:04}_{stem}.o", cu.id);
        let names: Vec<String> = cu
            .functions
            .iter()
            .filter(|f| f.size > 0)
            .map(|f| f.symbol_name().to_string())
            .collect();
        if !names.is_empty() {
            json.insert(filename, names);
        }
    }
    json
}

/// Build a `SymtabLookup` (name → metadata) from the binary's symbol table.
///
/// Includes all N_SECT symbols in `__TEXT,__text` — the same set that
/// `generate` uses for the default JSON.
pub fn build_lookup(data: &[u8]) -> Result<SymtabLookup> {
    let mut map = HashMap::new();
    for sym in parse_text_symbols(data) {
        map.insert(
            sym.name,
            SymtabInfo {
                addr: sym.addr,
                size: sym.size,
                n_type: decode_n_type(sym.n_type_raw),
                n_sect: sym.n_sect,
                n_desc: decode_n_desc(sym.n_desc_raw),
                external: sym.n_type_raw & N_EXT != 0,
                private_external: sym.n_type_raw & N_PEXT != 0,
            },
        );
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Internal parsing
// ---------------------------------------------------------------------------

struct ParsedSym {
    name: String,
    addr: u64,
    size: u64,
    n_type_raw: u8,
    n_sect: u8,
    n_desc_raw: u16,
}

fn parse_text_symbols(data: &[u8]) -> Vec<ParsedSym> {
    let le = detect_little_endian(data);
    let Some(Symtab {
        sym_data,
        str_data,
        text_sect_indices,
    }) = parse_symtab_raw(data, le)
    else {
        return Vec::new();
    };

    let read_str = |strx: u32| -> String {
        let strx = strx as usize;
        if strx >= str_data.len() {
            return String::new();
        }
        let end = str_data[strx..].iter().position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&str_data[strx..strx + end]).into_owned()
    };

    struct Raw {
        name: String,
        addr: u64,
        n_type: u8,
        n_sect: u8,
        n_desc: u16,
    }
    let mut raw: Vec<Raw> = Vec::new();

    for chunk in sym_data.chunks_exact(12) {
        let n_type = chunk[4];
        let n_sect = chunk[5];
        if n_type & N_STAB_MASK != 0 {
            continue;
        }
        if n_type & N_TYPE_MASK != N_SECT_VAL {
            continue;
        }
        if !text_sect_indices.contains(&n_sect) {
            continue;
        }
        let strx = r32_chunk(chunk, 0, le);
        let n_desc = r16_chunk(chunk, 6, le);
        let addr = r32_chunk(chunk, 8, le) as u64;
        let name = read_str(strx);
        if name.is_empty() {
            continue;
        }
        raw.push(Raw {
            name,
            addr,
            n_type,
            n_sect,
            n_desc,
        });
    }

    raw.sort_by_key(|s| (s.addr, s.name.clone()));
    raw.dedup_by_key(|s| s.addr);

    let addrs: Vec<u64> = raw.iter().map(|s| s.addr).collect();
    let sizes: Vec<u64> = addrs
        .windows(2)
        .map(|w| w[1] - w[0])
        .chain(std::iter::once(0u64))
        .collect();

    raw.into_iter()
        .zip(sizes)
        .map(|(s, size)| ParsedSym {
            name: s.name,
            addr: s.addr,
            size,
            n_type_raw: s.n_type,
            n_sect: s.n_sect,
            n_desc_raw: s.n_desc,
        })
        .collect()
}

struct Symtab<'a> {
    sym_data: &'a [u8],
    str_data: &'a [u8],
    text_sect_indices: std::collections::HashSet<u8>,
}

fn parse_symtab_raw(data: &[u8], le: bool) -> Option<Symtab<'_>> {
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
    let mut text_sect_indices: std::collections::HashSet<u8> = std::collections::HashSet::new();
    let mut sect_idx: u8 = 1;

    let mut pos = 28usize;
    let mut count = 0;
    while pos + 8 <= cmds_end && count < ncmds {
        let cmd = r32(pos)?;
        let cmdsize = r32(pos + 4)? as usize;
        if cmdsize == 0 {
            break;
        }

        match cmd {
            LC_SYMTAB if cmdsize >= 24 => {
                symtab_off = r32(pos + 8)?;
                nsyms = r32(pos + 12)?;
                stroff = r32(pos + 16)?;
            }
            LC_SEGMENT if cmdsize >= SEGMENT_CMD32_SIZE => {
                let nsects = r32(pos + 48)? as usize;
                for i in 0..nsects {
                    let sb = pos + SEGMENT_CMD32_SIZE + i * SECTION32_SIZE;
                    if sb + SECTION32_SIZE > cmds_end {
                        break;
                    }
                    let sec_name = cstr(&data[sb..sb + 16]);
                    let seg_name = cstr(&data[sb + 16..sb + 32]);
                    if seg_name == "__TEXT" && sec_name == "__text" {
                        text_sect_indices.insert(sect_idx);
                    }
                    sect_idx = sect_idx.saturating_add(1);
                }
            }
            _ => {}
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
    let str_start = stroff as usize;
    let str_data = if str_start < data.len() {
        &data[str_start..]
    } else {
        &[]
    };

    Some(Symtab {
        sym_data: &data[sym_start..sym_end],
        str_data,
        text_sect_indices,
    })
}

pub fn detect_little_endian(data: &[u8]) -> bool {
    if data.len() < 4 {
        return true;
    }
    let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
    matches!(magic, 0xFEED_FACE | 0xFEED_FACF)
}

fn r32_chunk(chunk: &[u8], off: usize, le: bool) -> u32 {
    let b: [u8; 4] = chunk[off..off + 4].try_into().unwrap();
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn r16_chunk(chunk: &[u8], off: usize, le: bool) -> u16 {
    let b: [u8; 2] = chunk[off..off + 2].try_into().unwrap();
    if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn decode_n_type(n_type: u8) -> String {
    if n_type & N_STAB_MASK != 0 {
        return format!("N_STAB(0x{n_type:02x})");
    }
    let base = match n_type & N_TYPE_MASK {
        0x00 => "N_UNDF",
        0x02 => "N_ABS",
        0x0a => "N_INDR",
        0x0c => "N_PBUD",
        0x0e => "N_SECT",
        other => return format!("0x{other:02x}"),
    };
    let mut s = base.to_string();
    if n_type & N_PEXT != 0 {
        s.push_str("|N_PEXT");
    }
    if n_type & N_EXT != 0 {
        s.push_str("|N_EXT");
    }
    s
}

fn decode_n_desc(n_desc: u16) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    match n_desc & 0x000f {
        0 => {}
        1 => flags.push("REF_LAZY".into()),
        2 => flags.push("REF_DEFINED".into()),
        3 => flags.push("REF_PRIVATE_DEFINED".into()),
        4 => flags.push("REF_PRIVATE_UNDEF_NON_LAZY".into()),
        5 => flags.push("REF_PRIVATE_UNDEF_LAZY".into()),
        n => flags.push(format!("REF(0x{n:x})")),
    }
    if n_desc & 0x0010 != 0 {
        flags.push("REFERENCED_DYNAMICALLY".into());
    }
    if n_desc & 0x0020 != 0 {
        flags.push("N_NO_DEAD_STRIP".into());
    }
    if n_desc & 0x0040 != 0 {
        flags.push("N_DESC_DISCARDED".into());
    }
    if n_desc & 0x0080 != 0 {
        flags.push("N_WEAK_REF".into());
    }
    if n_desc & 0x0100 != 0 {
        flags.push("N_WEAK_DEF".into());
    }
    if n_desc & 0x0200 != 0 {
        flags.push("N_REF_TO_WEAK".into());
    }
    if n_desc & 0x0800 != 0 {
        flags.push("N_ARM_THUMB_DEF".into());
    }
    if n_desc & 0x1000 != 0 {
        flags.push("N_SYMBOL_RESOLVER".into());
    }
    if n_desc & 0x2000 != 0 {
        flags.push("N_ALT_ENTRY".into());
    }
    flags
}

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = s.trim_start_matches(['.', '_']);
    let truncated = &trimmed[..trimmed.len().min(200)];
    if truncated.is_empty() {
        "unknown".to_string()
    } else {
        truncated.to_string()
    }
}
