//! ARM (AArch32, A32) relocation recovery.

pub mod recover;

pub use recover::{
    apply_addend, elf_reloc_type, recover, RecoveredReloc, RecoveryDiagnostics, RecoveryOutput,
    RelocKind,
};
