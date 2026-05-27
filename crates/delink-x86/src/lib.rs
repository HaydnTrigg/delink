//! x86 (32-bit) relocation recovery for PE compilation units.

pub mod recover;
pub use recover::{recover, RecoveredReloc, RecoveryDiagnostics, RecoveryOutput, RelocKind};
