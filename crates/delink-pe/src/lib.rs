//! PE (.exe) + PDB loader for `so-delink`.
//!
//! Parses a 64-bit Windows PE executable together with its PDB file and
//! produces a `PeContext` that the rest of the tool can use to:
//!   - iterate compilation units (PDB modules → `PeCompilationUnit`)
//!   - resolve addresses to symbol names (`PeGlobalSymbols`)
//!   - emit per-CU COFF `.obj` files via `delink_pe::emit`

use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub mod cu;
pub mod emit;
pub mod symbols;

pub use cu::{PeCompilationUnit, PeCuIndex, PeContrib, PeFunction};
pub use symbols::PeGlobalSymbols;

/// A single PE section with its raw bytes and virtual-address metadata.
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    /// RVA (relative virtual address from image base).
    pub rva: u64,
    /// Absolute virtual address = image_base + rva.
    pub va: u64,
    /// Virtual size (may be larger than raw data due to BSS padding).
    pub virtual_size: u64,
    /// Raw bytes from the file, zero-extended to `virtual_size` if needed.
    pub data: Vec<u8>,
    pub characteristics: u32,
}

impl PeSection {
    pub fn contains_rva(&self, rva: u64) -> bool {
        rva >= self.rva && rva < self.rva + self.virtual_size
    }

    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.va && va < self.va + self.virtual_size
    }

    /// Borrow the bytes at `rva` (RVA relative to image base) for `len` bytes.
    pub fn data_at_rva(&self, rva: u64, len: usize) -> Option<&[u8]> {
        if rva < self.rva {
            return None;
        }
        let off = (rva - self.rva) as usize;
        let end = off.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[off..end])
    }

    /// Borrow the bytes at an absolute VA for `len` bytes.
    pub fn data_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        if va < self.va {
            return None;
        }
        let rva = va - self.va + self.rva;
        self.data_at_rva(rva, len)
    }
}

/// A base-relocation entry from the `.reloc` section.
#[derive(Debug, Clone)]
pub struct BaseReloc {
    pub va: u64,
    pub kind: BaseRelocKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRelocKind {
    /// `IMAGE_REL_BASED_DIR64` (10) — 64-bit absolute pointer.
    Dir64,
    /// `IMAGE_REL_BASED_HIGHLOW` (3) — 32-bit absolute pointer.
    HighLow,
    /// Other type we don't handle.
    Other(u8),
}

/// All parsed data from a PE + PDB pair.
pub struct PeContext {
    pub image_base: u64,
    pub sections: Vec<PeSection>,
    pub cu_index: PeCuIndex,
    pub symbols: PeGlobalSymbols,
    /// Base relocations from `.reloc` — one entry per embedded absolute pointer.
    pub base_relocations: Vec<BaseReloc>,
    /// IAT slot VA → `"__imp_funcname"` symbol name.
    pub imports: HashMap<u64, String>,
}

impl PeContext {
    /// Find the section that contains `va`.
    pub fn section_for_va(&self, va: u64) -> Option<&PeSection> {
        self.sections.iter().find(|s| s.contains_va(va))
    }

    /// Bytes at an absolute VA, spanning across a single section.
    pub fn data_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        self.section_for_va(va)?.data_at_va(va, len)
    }
}

/// Load a 64-bit PE executable and its associated PDB file.
pub fn load_pe_and_pdb(exe_data: &[u8], pdb_data: &[u8]) -> Result<PeContext> {
    let (image_base, sections) = parse_pe_sections(exe_data)?;
    let base_relocations = parse_base_relocations(&sections, image_base);
    let imports = parse_imports(exe_data, &sections, image_base);

    let (cu_index, all_functions) = cu::build_cu_index(pdb_data, image_base, &sections)?;
    let symbols =
        symbols::PeGlobalSymbols::build(all_functions, &imports, &sections, image_base);

    Ok(PeContext {
        image_base,
        sections,
        cu_index,
        symbols,
        base_relocations,
        imports,
    })
}

// ---------------------------------------------------------------------------
// PE header parsing
// ---------------------------------------------------------------------------

fn parse_pe_sections(exe_data: &[u8]) -> Result<(u64, Vec<PeSection>)> {
    // Minimum size for DOS header + PE offset field.
    if exe_data.len() < 0x40 {
        return Err(anyhow!("file too small for PE header"));
    }
    if &exe_data[0..2] != b"MZ" {
        return Err(anyhow!("not a PE file (no MZ signature)"));
    }

    let e_lfanew =
        u32::from_le_bytes(exe_data[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 4 > exe_data.len() {
        return Err(anyhow!("e_lfanew out of bounds"));
    }
    if &exe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(anyhow!("PE signature not found"));
    }

    // COFF file header: 20 bytes starting at e_lfanew + 4
    let coff_off = e_lfanew + 4;
    if coff_off + 20 > exe_data.len() {
        return Err(anyhow!("COFF header out of bounds"));
    }
    let machine = u16::from_le_bytes(exe_data[coff_off..coff_off + 2].try_into().unwrap());
    if machine != 0x8664 {
        return Err(anyhow!(
            "only AMD64 PE files supported (machine=0x{:04x})",
            machine
        ));
    }
    let num_sections =
        u16::from_le_bytes(exe_data[coff_off + 2..coff_off + 4].try_into().unwrap()) as usize;
    let opt_header_size =
        u16::from_le_bytes(exe_data[coff_off + 16..coff_off + 18].try_into().unwrap()) as usize;

    // Optional header starts right after the COFF file header.
    let opt_off = coff_off + 20;
    if opt_off + 2 > exe_data.len() {
        return Err(anyhow!("optional header offset out of bounds"));
    }
    let magic = u16::from_le_bytes(exe_data[opt_off..opt_off + 2].try_into().unwrap());
    if magic != 0x020B {
        return Err(anyhow!(
            "only PE32+ (64-bit) supported (magic=0x{:04x})",
            magic
        ));
    }

    // ImageBase is at offset 24 in IMAGE_OPTIONAL_HEADER64.
    if opt_off + 32 > exe_data.len() {
        return Err(anyhow!("optional header too short for ImageBase"));
    }
    let image_base =
        u64::from_le_bytes(exe_data[opt_off + 24..opt_off + 32].try_into().unwrap());

    // Section headers start after the optional header.
    let sections_off = opt_off + opt_header_size;
    let section_entry_size = 40usize;
    if sections_off + num_sections * section_entry_size > exe_data.len() {
        return Err(anyhow!("section headers out of bounds"));
    }

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let hdr = &exe_data[sections_off + i * section_entry_size..];
        let name_bytes = &hdr[0..8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        let virtual_size = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
        let virtual_address = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as u64;
        let size_of_raw_data = u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as usize;
        let ptr_to_raw_data = u32::from_le_bytes(hdr[20..24].try_into().unwrap()) as usize;
        let characteristics = u32::from_le_bytes(hdr[36..40].try_into().unwrap());

        let rva = virtual_address;
        let va = image_base + rva;

        // Load raw bytes; zero-extend to virtual_size for BSS regions.
        let mut data = if ptr_to_raw_data == 0 || size_of_raw_data == 0 {
            Vec::new()
        } else {
            let end = ptr_to_raw_data + size_of_raw_data;
            if end > exe_data.len() {
                return Err(anyhow!("section '{}' raw data out of bounds", name));
            }
            exe_data[ptr_to_raw_data..end].to_vec()
        };
        // Pad with zeroes if the virtual size is larger than raw data.
        if (data.len() as u64) < virtual_size {
            data.resize(virtual_size as usize, 0);
        }

        sections.push(PeSection {
            name,
            rva,
            va,
            virtual_size,
            data,
            characteristics,
        });
    }

    Ok((image_base, sections))
}

// ---------------------------------------------------------------------------
// Base relocations (.reloc section)
// ---------------------------------------------------------------------------

fn parse_base_relocations(sections: &[PeSection], image_base: u64) -> Vec<BaseReloc> {
    let Some(reloc_section) = sections.iter().find(|s| s.name == ".reloc") else {
        return Vec::new();
    };
    let data = &reloc_section.data;
    let mut offset = 0usize;
    let mut relocs = Vec::new();

    while offset + 8 <= data.len() {
        let page_rva =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as u64;
        let block_size =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if block_size < 8 {
            break;
        }
        let entries_end = offset + block_size;
        if entries_end > data.len() {
            break;
        }

        let entries = &data[offset + 8..entries_end];
        for chunk in entries.chunks_exact(2) {
            let type_offset = u16::from_le_bytes(chunk.try_into().unwrap());
            let reloc_type = (type_offset >> 12) as u8;
            let page_offset = (type_offset & 0x0FFF) as u64;

            // Skip padding entries (type 0 = IMAGE_REL_BASED_ABSOLUTE).
            if reloc_type == 0 {
                continue;
            }

            let va = image_base + page_rva + page_offset;
            let kind = match reloc_type {
                3 => BaseRelocKind::HighLow,
                10 => BaseRelocKind::Dir64,
                other => BaseRelocKind::Other(other),
            };
            relocs.push(BaseReloc { va, kind });
        }

        offset = entries_end;
    }

    relocs
}

// ---------------------------------------------------------------------------
// Import table (IAT) parsing
// ---------------------------------------------------------------------------

fn parse_imports(
    exe_data: &[u8],
    sections: &[PeSection],
    image_base: u64,
) -> HashMap<u64, String> {
    match try_parse_imports(exe_data, sections, image_base) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("import table parse failed (ignoring): {e:#}");
            HashMap::new()
        }
    }
}

fn try_parse_imports(
    exe_data: &[u8],
    sections: &[PeSection],
    image_base: u64,
) -> Result<HashMap<u64, String>> {
    // Optional header layout for PE32+ (PE64):
    //   offset 0: Magic (2)       offset 24: ImageBase (8)   ...
    //   offset 112: DataDirectory[0] (8 bytes each)
    //   DataDirectory[1] = Import Table = opt_off + 112 + 8
    if exe_data.len() < 0x40 {
        return Ok(HashMap::new());
    }
    let e_lfanew = u32::from_le_bytes(exe_data[0x3c..0x40].try_into().unwrap()) as usize;
    let coff_off = e_lfanew + 4;
    let opt_off = coff_off + 20;

    // Import directory is DataDirectory[1], at opt_off + 112 + 1*8.
    let import_dir_off = opt_off + 112 + 8;
    if import_dir_off + 8 > exe_data.len() {
        return Ok(HashMap::new());
    }
    let import_rva =
        u32::from_le_bytes(exe_data[import_dir_off..import_dir_off + 4].try_into().unwrap());
    if import_rva == 0 {
        return Ok(HashMap::new());
    }

    let mut map = HashMap::new();
    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes.
    let mut desc_rva = import_rva as u64;
    loop {
        let Some(desc) = rva_slice(sections, desc_rva, 20) else {
            break;
        };
        let original_first_thunk = u32::from_le_bytes(desc[0..4].try_into().unwrap()) as u64;
        let name_rva = u32::from_le_bytes(desc[12..16].try_into().unwrap()) as u64;
        let first_thunk = u32::from_le_bytes(desc[16..20].try_into().unwrap()) as u64;

        if original_first_thunk == 0 && first_thunk == 0 {
            break; // end of descriptor array
        }

        let hint_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut entry_idx = 0u64;
        loop {
            let Some(thunk_bytes) = rva_slice(sections, hint_rva + entry_idx * 8, 8) else {
                break;
            };
            let thunk = u64::from_le_bytes(thunk_bytes.try_into().unwrap());
            if thunk == 0 {
                break;
            }

            let iat_va = image_base + first_thunk + entry_idx * 8;
            let func_name = if thunk >> 63 == 1 {
                // Import by ordinal.
                let ordinal = thunk as u16;
                let dll = name_rva
                    .checked_sub(1)
                    .and_then(|_| rva_cstr(sections, name_rva))
                    .unwrap_or_default();
                format!("{}#{}", dll, ordinal)
            } else {
                // Import by name: thunk is RVA of IMAGE_IMPORT_BY_NAME (2-byte hint + name).
                let ibn_rva = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as u64;
                rva_cstr(sections, ibn_rva + 2).unwrap_or_default()
            };

            if !func_name.is_empty() {
                map.insert(iat_va, format!("__imp_{}", func_name));
            }
            entry_idx += 1;
        }

        desc_rva += 20;
    }

    Ok(map)
}

// ---------------------------------------------------------------------------
// RVA helpers
// ---------------------------------------------------------------------------

pub(crate) fn rva_slice<'a>(sections: &'a [PeSection], rva: u64, len: usize) -> Option<&'a [u8]> {
    for s in sections {
        if rva >= s.rva && rva + len as u64 <= s.rva + s.virtual_size {
            let off = (rva - s.rva) as usize;
            return s.data.get(off..off + len);
        }
    }
    None
}

pub(crate) fn rva_cstr(sections: &[PeSection], rva: u64) -> Option<String> {
    // Find the section and read until null terminator.
    for s in sections {
        if rva >= s.rva && rva < s.rva + s.virtual_size {
            let off = (rva - s.rva) as usize;
            let bytes = &s.data[off..];
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            return Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
        }
    }
    None
}
