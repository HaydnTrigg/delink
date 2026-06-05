//! x86 (32-bit) relocation recovery from linked PE code.
//!
//! Handles:
//!   * `E8 rel32`    (call rel32)   → IMAGE_REL_I386_REL32 at offset 1
//!   * `E9 rel32`    (jmp rel32)    → IMAGE_REL_I386_REL32 at offset 1
//!   * `0F 8x rel32` (jcc rel32)   → IMAGE_REL_I386_REL32 at offset 2
//!
//! 32-bit absolute pointer fixups (IMAGE_REL_I386_DIR32) are derived from the
//! PE base-relocation table (HIGHLOW entries) and handled in the emitter, not
//! here.
//!
//! Intra-function branches are skipped. Unresolved targets are counted.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// IMAGE_REL_I386_REL32 — 32-bit PC-relative (calls, jumps).
    Rel32,
}

#[derive(Debug, Clone)]
pub struct RecoveredReloc {
    /// Byte offset within the function bytes where the fixup field lives.
    pub offset: u64,
    /// Instruction address (fn_va + offset of instruction start).
    pub pc: u64,
    pub kind: RelocKind,
    /// Symbol name the reloc targets.
    pub target: String,
    /// Addend relative to the symbol (0 = target is exactly the symbol start).
    pub addend: i64,
}

#[derive(Debug, Default)]
pub struct RecoveryDiagnostics {
    pub instructions: usize,
    pub decode_failures: usize,
    pub calls_resolved: usize,
    pub calls_unresolved: usize,
    /// Always 0 for x86 (no RIP-relative addressing); kept for API symmetry.
    pub rip_refs_unresolved: usize,
}

pub struct RecoveryOutput {
    pub relocs: Vec<RecoveredReloc>,
    pub diag: RecoveryDiagnostics,
}

/// Trait that callers implement to resolve VAs to symbol names.
pub trait SymbolResolver {
    /// Resolve a code target (call/jmp destination) → (symbol_name, addend).
    fn resolve_code(&self, va: u64) -> Option<(String, i64)>;
    /// Resolve a data reference → (symbol_name, addend).
    fn resolve_data(&self, va: u64) -> Option<(String, i64)>;
    /// Returns true if `target_va` is inside the current function body.
    fn is_intra_function(&self, fn_va: u64, fn_size: u64, target_va: u64) -> bool {
        target_va >= fn_va && target_va < fn_va + fn_size
    }
}

/// Walk `fn_bytes` starting at `fn_va`, synthesise COFF relocations for
/// all direct calls and jumps that leave the function.
pub fn recover<R: SymbolResolver>(
    fn_bytes: &[u8],
    fn_va: u64,
    fn_size: u64,
    resolver: &R,
) -> Result<RecoveryOutput> {
    // For 32-bit PE, fn_va fits in 32 bits; pass the low 32 bits as IP.
    let mut decoder = Decoder::with_ip(32, fn_bytes, fn_va & 0xFFFF_FFFF, DecoderOptions::NONE);
    let mut insn = Instruction::default();

    let mut out = RecoveryOutput {
        relocs: Vec::new(),
        diag: RecoveryDiagnostics::default(),
    };

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        out.diag.instructions += 1;

        if insn.is_invalid() {
            out.diag.decode_failures += 1;
            continue;
        }

        let pc = insn.ip();
        let insn_offset = pc - (fn_va & 0xFFFF_FFFF);
        let insn_len = insn.len() as u64;

        // Only direct near branches (call rel32 / jmp rel32 / jcc rel32).
        // rel8 branches are 2 bytes; rel32 are 5 (E8/E9) or 6 (0F 8x) bytes.
        match insn.flow_control() {
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
                if insn_len >= 5 =>
            {
                // near_branch32() gives the absolute 32-bit target VA.
                let target_va = insn.near_branch32() as u64;

                if !resolver.is_intra_function(fn_va, fn_size, target_va) {
                    // The rel32 field is always the last 4 bytes of these instructions.
                    let rel32_off = insn_len - 4;

                    match resolver.resolve_code(target_va) {
                        Some((sym, addend)) => {
                            out.relocs.push(RecoveredReloc {
                                offset: insn_offset + rel32_off,
                                pc,
                                kind: RelocKind::Rel32,
                                target: sym,
                                addend,
                            });
                            out.diag.calls_resolved += 1;
                        }
                        None => {
                            trace!("{:#x}: unresolved call/jmp target {:#x}", pc, target_va);
                            out.diag.calls_unresolved += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(out)
}
