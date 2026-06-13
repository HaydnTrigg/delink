//! Mach-O (macOS/Darwin) binary loader and compilation-unit splitter.
//!
//! Supports 32-bit i386 Mach-O executables with DWARF debug information.
//! Reads DWARF to identify compilation units, synthesises relocations via
//! the x86 recovery pass, and emits one Mach-O relocatable `.o` per CU.

use anyhow::{anyhow, Context, Result};
use gimli::{EndianSlice, LittleEndian};
use object::{Object as _, ObjectSection as _, SectionFlags};
use std::collections::HashMap;

pub mod cu;
pub mod emit;
pub mod stabs;
pub mod symbols;
pub mod symtab_json;
pub mod symtab_split;

pub use cu::{DebugInfoSource, MachoCompilationUnit, MachoCuIndex, MachoFunction, MachoVariable};
pub use emit::{CuOutcome, EmitStats, SharedDataStats};
pub use symbols::MachoGlobalSymbols;

type DwarfSlice<'a> = EndianSlice<'a, LittleEndian>;
type Dwarf<'a> = gimli::Dwarf<DwarfSlice<'a>>;

/// Target architecture of the loaded Mach-O binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoArch {
    /// 32-bit x86 / i386.
    X86,
    /// 64-bit x86-64.
    X86_64,
    /// 32-bit PowerPC (big-endian).
    PPC,
    /// 64-bit PowerPC (big-endian).
    PPC64,
}

/// A single Mach-O section with its raw bytes and metadata.
#[derive(Debug, Clone)]
pub struct MachoSection {
    /// Segment name, e.g. `"__TEXT"` or `"__DATA"`.
    pub segment: String,
    /// Section name within the segment, e.g. `"__text"` or `"__data"`.
    pub name: String,
    /// Virtual memory address.
    pub addr: u64,
    /// Size in bytes (may be larger than `data.len()` for BSS).
    pub size: u64,
    /// Raw section bytes; empty for BSS-style sections.
    pub data: Vec<u8>,
    /// Section flags from the Mach-O header (`section_32.flags`).
    pub flags: u32,
}

impl MachoSection {
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.addr + self.size
    }

    pub fn data_at_addr(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if addr < self.addr {
            return None;
        }
        let off = (addr - self.addr) as usize;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }
}

/// All parsed data from a Mach-O binary.
pub struct MachoContext {
    pub arch: MachoArch,
    pub little_endian: bool,
    pub sections: Vec<MachoSection>,
    pub cu_index: MachoCuIndex,
    pub symbols: MachoGlobalSymbols,
}

impl MachoContext {
    pub fn section_for_addr(&self, addr: u64) -> Option<&MachoSection> {
        self.sections.iter().find(|s| s.contains_addr(addr))
    }

    /// Returns the `__TEXT,__text` code section.
    pub fn text_section(&self) -> Option<&MachoSection> {
        self.sections
            .iter()
            .find(|s| s.segment == "__TEXT" && s.name == "__text")
    }
}

/// Load a Mach-O binary from raw bytes and index its DWARF.
pub fn load_macho(data: &[u8]) -> Result<MachoContext> {
    let file = object::File::parse(data).context("parse Mach-O")?;

    let arch = match file.architecture() {
        object::Architecture::I386 => MachoArch::X86,
        object::Architecture::X86_64 => MachoArch::X86_64,
        object::Architecture::PowerPc => MachoArch::PPC,
        object::Architecture::PowerPc64 => MachoArch::PPC64,
        other => return Err(anyhow!("unsupported Mach-O architecture: {:?}", other)),
    };

    let little_endian = file.is_little_endian();

    let sections = parse_sections(&file)?;
    let stubs = parse_stubs(data).unwrap_or_else(|e| {
        tracing::warn!("stub parsing failed (ignoring): {e:#}");
        HashMap::new()
    });
    tracing::info!("parsed {} stubs from __symbol_stub", stubs.len());

    let cu_index = {
        let dwarf = load_dwarf(data, &file)?;
        let idx = cu::build_cu_index(&dwarf)?;
        if !idx.units.is_empty() {
            idx
        } else {
            tracing::info!("no DWARF CUs found; falling back to STABS");
            let stabs_idx = stabs::build_cu_index_from_stabs(data, little_endian)?;
            if !stabs_idx.units.is_empty() {
                stabs_idx
            } else {
                tracing::info!("no STABS CUs found; falling back to symtab-based split");
                symtab_split::build_cu_index_from_symtab(data)?
            }
        }
    };

    let symbols = MachoGlobalSymbols::build(&cu_index, &stubs, &sections);

    Ok(MachoContext {
        arch,
        little_endian,
        sections,
        cu_index,
        symbols,
    })
}

// ---------------------------------------------------------------------------
// Section parsing
// ---------------------------------------------------------------------------

fn parse_sections(file: &object::File<'_>) -> Result<Vec<MachoSection>> {
    let mut sections = Vec::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("").to_string();
        let segment = section
            .segment_name()
            .ok()
            .flatten()
            .unwrap_or("")
            .to_string();
        let addr = section.address();
        let size = section.size();
        let data = section.data().unwrap_or(&[]).to_vec();
        let flags = match section.flags() {
            SectionFlags::MachO { flags } => flags,
            _ => 0,
        };
        sections.push(MachoSection {
            segment,
            name,
            addr,
            size,
            data,
            flags,
        });
    }
    Ok(sections)
}

// ---------------------------------------------------------------------------
// DWARF loading
// ---------------------------------------------------------------------------

fn load_dwarf<'a>(_data: &'a [u8], file: &object::File<'a>) -> Result<Dwarf<'a>> {
    let load_section = |id: gimli::SectionId| -> std::result::Result<DwarfSlice<'a>, gimli::Error> {
        // Map ELF-style ".debug_info" → Mach-O "__debug_info"
        let elf_name = id.name();
        let macho_name = format!("__{}", &elf_name[1..]);
        let section_data: &'a [u8] = match file.section_by_name(&macho_name) {
            Some(s) => s.data().unwrap_or(b""),
            None => b"",
        };
        Ok(EndianSlice::new(section_data, LittleEndian))
    };
    gimli::Dwarf::load(load_section).map_err(|e| anyhow!("load DWARF: {e}"))
}

// ---------------------------------------------------------------------------
// Stub parsing  (LC_SYMTAB + LC_DYSYMTAB → stub_addr → symbol_name)
// ---------------------------------------------------------------------------

/// Parse the Mach-O symbol stubs, returning `stub_va → external_symbol_name`.
///
/// Handles 32-bit i386 Mach-O only; returns an empty map for 64-bit or on
/// any parse error so that callers can degrade gracefully.
pub fn parse_stubs(data: &[u8]) -> Result<HashMap<u64, String>> {
    if data.len() < 4 {
        return Ok(HashMap::new());
    }
    let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
    if magic == 0xFEED_FACE {
        parse_stubs_32(data)
    } else {
        // 64-bit or fat binary — not implemented yet
        Ok(HashMap::new())
    }
}

fn parse_stubs_32(data: &[u8]) -> Result<HashMap<u64, String>> {
    // mach_header (32-bit) layout:
    //   magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4)
    //   total = 28 bytes
    if data.len() < 28 {
        return Ok(HashMap::new());
    }
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xB;
    const LC_SEGMENT: u32 = 0x1;
    const S_SYMBOL_STUBS: u32 = 0x8;
    const SECTION_TYPE: u32 = 0xFF;
    const SEGMENT_CMD32_SIZE: usize = 56;
    const SECTION32_SIZE: usize = 68;

    let cmds_start = 28usize;
    let cmds_end = (cmds_start + sizeofcmds).min(data.len());

    let mut symtab_off = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut indirectsymoff = 0u32;
    let mut nindirectsyms = 0u32;
    // (vmaddr, vmsize, first_indirect_idx, stub_size_bytes)
    let mut stub_secs: Vec<(u64, u64, u32, u32)> = Vec::new();

    let mut pos = cmds_start;
    let mut count = 0;
    while pos + 8 <= cmds_end && count < ncmds {
        let cmd = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if cmdsize < 8 || pos + cmdsize > cmds_end {
            break;
        }

        match cmd {
            LC_SYMTAB => {
                // symoff(4) nsyms(4) stroff(4) strsize(4) — starts at pos+8
                if cmdsize >= 24 {
                    symtab_off = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
                    nsyms = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
                    stroff = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
                }
            }
            LC_DYSYMTAB => {
                // indirectsymoff is at byte offset 56 within the command
                if cmdsize >= 64 {
                    indirectsymoff =
                        u32::from_le_bytes(data[pos + 56..pos + 60].try_into().unwrap());
                    nindirectsyms =
                        u32::from_le_bytes(data[pos + 60..pos + 64].try_into().unwrap());
                }
            }
            LC_SEGMENT if cmdsize >= SEGMENT_CMD32_SIZE => {
                // nsects at offset 48 within segment_command_32
                let nsects =
                    u32::from_le_bytes(data[pos + 48..pos + 52].try_into().unwrap()) as usize;
                for i in 0..nsects {
                    let sec_base = pos + SEGMENT_CMD32_SIZE + i * SECTION32_SIZE;
                    if sec_base + SECTION32_SIZE > cmds_end {
                        break;
                    }
                    let sec = &data[sec_base..sec_base + SECTION32_SIZE];
                    // section_32: addr[32..36] size[36..40] flags[56..60]
                    //             reserved1[60..64] reserved2[64..68]
                    let flags = u32::from_le_bytes(sec[56..60].try_into().unwrap());
                    if flags & SECTION_TYPE == S_SYMBOL_STUBS {
                        let addr = u32::from_le_bytes(sec[32..36].try_into().unwrap()) as u64;
                        let size = u32::from_le_bytes(sec[36..40].try_into().unwrap()) as u64;
                        let reserved1 = u32::from_le_bytes(sec[60..64].try_into().unwrap());
                        let reserved2 = u32::from_le_bytes(sec[64..68].try_into().unwrap());
                        if reserved2 > 0 && size > 0 {
                            stub_secs.push((addr, size, reserved1, reserved2));
                        }
                    }
                }
            }
            _ => {}
        }

        pos += cmdsize;
        count += 1;
    }

    // Read symbol table (nlist, 12 bytes per entry: strx(4) type(1) sect(1) desc(2) value(4))
    let sym_entry_size: usize = 12;
    let sym_end = symtab_off as usize + nsyms as usize * sym_entry_size;
    if sym_end > data.len() {
        return Ok(HashMap::new());
    }
    let sym_data = &data[symtab_off as usize..sym_end];
    let str_data = if (stroff as usize) < data.len() {
        &data[stroff as usize..]
    } else {
        &[]
    };

    // Read indirect symbol table (u32 array)
    let indir_end = indirectsymoff as usize + nindirectsyms as usize * 4;
    let indir_data = if indir_end <= data.len() {
        &data[indirectsymoff as usize..indir_end]
    } else {
        &[]
    };

    let read_sym_name = |sym_idx: u32| -> Option<String> {
        if sym_idx >= nsyms {
            return None;
        }
        let off = sym_idx as usize * sym_entry_size;
        let n_strx = u32::from_le_bytes(sym_data[off..off + 4].try_into().ok()?) as usize;
        if n_strx >= str_data.len() {
            return None;
        }
        let end = str_data[n_strx..].iter().position(|&b| b == 0).unwrap_or(0);
        let s = String::from_utf8_lossy(&str_data[n_strx..n_strx + end]).into_owned();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };

    let mut map = HashMap::new();
    for (addr, size, first_idx, stub_size) in &stub_secs {
        let n_stubs = (size / *stub_size as u64) as u32;
        for i in 0..n_stubs {
            let stub_addr = addr + i as u64 * *stub_size as u64;
            let indir_idx = first_idx + i;
            let entry_off = indir_idx as usize * 4;
            if entry_off + 4 > indir_data.len() {
                break;
            }
            let sym_idx =
                u32::from_le_bytes(indir_data[entry_off..entry_off + 4].try_into().unwrap());
            // INDIRECT_SYMBOL_LOCAL (0x80000000) and INDIRECT_SYMBOL_ABS (0x40000000) — skip
            if sym_idx >= 0x4000_0000 {
                continue;
            }
            if let Some(name) = read_sym_name(sym_idx) {
                map.insert(stub_addr, name);
            }
        }
    }

    Ok(map)
}
