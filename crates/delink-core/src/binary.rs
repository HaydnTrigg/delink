//! Load and index a debug `.so`.
//!
//! `Binary` borrows from a byte slice (typically an mmap owned by the caller)
//! so parsing is zero-copy. Holds the parsed ELF plus a `gimli::Dwarf` handle.
//!
//! Both ELF classes are accepted: AArch64 shared objects (ELF64) and 32-bit
//! ARM shared objects (ELF32). The class and architecture are recorded on the
//! `Binary` so downstream passes can pick the right relocation encoding —
//! AArch64 uses `SHT_RELA` with explicit addends, ARM uses `SHT_REL` with the
//! addend stored in the relocated field.

use crate::error::{Error, Result};
use delink_arch::{Arch, ElfClass};
use gimli::{EndianSlice, LittleEndian};
use object::read::File;
use object::{Object as _, ObjectSection as _};

pub type Endian = LittleEndian;
pub type DwarfSlice<'a> = EndianSlice<'a, Endian>;
pub type Dwarf<'a> = gimli::Dwarf<DwarfSlice<'a>>;

pub struct Binary<'a> {
    pub data: &'a [u8],
    /// Class-agnostic reader. `object::File` transparently handles ELF32 and
    /// ELF64, so section/symbol lookups are shared between architectures.
    pub elf: File<'a>,
    pub dwarf: Dwarf<'a>,
    pub arch: Arch,
    pub class: ElfClass,
}

impl<'a> Binary<'a> {
    pub fn load(data: &'a [u8]) -> Result<Self> {
        let raw = RawHeader::parse(data)?;
        if !raw.little_endian {
            return Err(Error::Unsupported("big-endian ELF".into()));
        }
        if raw.e_type != object::elf::ET_DYN.0 {
            return Err(Error::Unsupported(format!(
                "expected ET_DYN shared object, got e_type=0x{:x}",
                raw.e_type
            )));
        }
        let arch = Arch::from_elf_machine(raw.e_machine).ok_or_else(|| {
            Error::Unsupported(format!(
                "unsupported machine e_machine=0x{:x} (supported: 0xb7 EM_AARCH64, 0x28 EM_ARM)",
                raw.e_machine
            ))
        })?;
        // AArch64 code in an ELF32 container (ILP32) is not something we
        // generate relocations for; reject rather than mis-encode.
        match (arch, raw.class) {
            (Arch::Aarch64, ElfClass::Elf64) | (Arch::Arm, ElfClass::Elf32) => {}
            (a, c) => {
                return Err(Error::Unsupported(format!("{a} in an {c} container")));
            }
        }

        let elf = File::parse(data)?;
        let dwarf = load_dwarf(&elf)?;

        Ok(Self {
            data,
            elf,
            dwarf,
            arch,
            class: raw.class,
        })
    }

    pub fn has_dwarf(&self) -> bool {
        self.elf
            .section_by_name(".debug_info")
            .and_then(|s| s.data().ok())
            .is_some_and(|d| !d.is_empty())
    }

    /// Byte range and data of the section containing virtual address `addr`.
    pub fn section_data_at(&self, addr: u64) -> Option<(u64, &'a [u8])> {
        for section in self.elf.sections() {
            let start = section.address();
            if start == 0 {
                continue;
            }
            if addr >= start && addr < start + section.size() {
                // `.bss`-style sections have no file bytes; `data()` returns an
                // empty slice for them, which the callers below treat as "no
                // readable word here".
                let data = section.data().ok()?;
                return Some((start, data));
            }
        }
        None
    }

    /// Read the pointer-sized word stored at virtual address `addr`.
    ///
    /// Used to recover the implicit addend of `SHT_REL` dynamic relocations
    /// (ARM stores it in the relocated field) and to follow `.got` slots.
    pub fn read_word_at(&self, addr: u64) -> Option<u64> {
        let (start, data) = self.section_data_at(addr)?;
        let off = (addr - start) as usize;
        match self.class {
            ElfClass::Elf32 => {
                let bytes = data.get(off..off + 4)?;
                Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64)
            }
            ElfClass::Elf64 => {
                let bytes = data.get(off..off + 8)?;
                Some(u64::from_le_bytes(bytes.try_into().ok()?))
            }
        }
    }
}

/// The handful of `e_ident` / `e_*` fields we need before handing the buffer
/// to `object`. Read by hand because `object::File` erases the ELF class.
struct RawHeader {
    class: ElfClass,
    little_endian: bool,
    e_type: u16,
    e_machine: u16,
}

impl RawHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 24 || data[..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(Error::Unsupported("not an ELF file".into()));
        }
        let class = match data[4] {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            other => {
                return Err(Error::Unsupported(format!("unknown EI_CLASS {other}")));
            }
        };
        let little_endian = data[5] == 1;
        let read_u16 = |off: usize| -> u16 {
            let b: [u8; 2] = data[off..off + 2].try_into().unwrap();
            if little_endian {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        Ok(Self {
            class,
            little_endian,
            e_type: read_u16(16),
            e_machine: read_u16(18),
        })
    }
}

fn load_dwarf<'a>(elf: &File<'a>) -> Result<Dwarf<'a>> {
    let load_section = |id: gimli::SectionId| -> std::result::Result<DwarfSlice<'a>, gimli::Error> {
        let name = id.name();
        let data = match elf.section_by_name(name) {
            Some(section) => section.data().unwrap_or(&[]),
            None => &[],
        };
        Ok(EndianSlice::new(data, LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(load_section)?;
    Ok(dwarf)
}
