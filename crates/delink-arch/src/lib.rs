//! Architecture backend trait. Implemented for AArch64 (ELF64) and ARM (ELF32).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Aarch64,
    /// 32-bit ARM (AArch32), A32 instruction set.
    Arm,
}

impl Arch {
    /// Natural pointer width in bytes.
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::Aarch64 => 8,
            Arch::Arm => 4,
        }
    }

    /// True when the ABI's static relocations carry explicit addends
    /// (`SHT_RELA`). ARM uses `SHT_REL` with addends stored in the field.
    pub fn uses_rela(self) -> bool {
        match self {
            Arch::Aarch64 => true,
            Arch::Arm => false,
        }
    }

    pub fn from_elf_machine(e_machine: u16) -> Option<Self> {
        match e_machine {
            0xb7 => Some(Arch::Aarch64), // EM_AARCH64
            0x28 => Some(Arch::Arm),     // EM_ARM
            _ => None,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arch::Aarch64 => f.write_str("aarch64"),
            Arch::Arm => f.write_str("arm"),
        }
    }
}

/// ELF class of the input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    pub fn pointer_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        }
    }

    /// Size of one `Elf_Rel` entry.
    pub fn rel_entsize(self) -> usize {
        match self {
            ElfClass::Elf32 => 8,
            ElfClass::Elf64 => 16,
        }
    }

    /// Size of one `Elf_Rela` entry.
    pub fn rela_entsize(self) -> usize {
        match self {
            ElfClass::Elf32 => 12,
            ElfClass::Elf64 => 24,
        }
    }

    /// Size of one `Elf_Sym` entry.
    pub fn sym_entsize(self) -> usize {
        match self {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        }
    }
}

impl fmt::Display for ElfClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfClass::Elf32 => f.write_str("elf32"),
            ElfClass::Elf64 => f.write_str("elf64"),
        }
    }
}
