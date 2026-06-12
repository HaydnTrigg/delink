//! x86-64 relocation recovery from linked PE code.
//!
//! Handles:
//!   * `E8 rel32`       (call rel32)         → IMAGE_REL_AMD64_REL32 at offset 1
//!   * `E9 rel32`       (jmp rel32)          → IMAGE_REL_AMD64_REL32 at offset 1
//!   * `0F 8x rel32`    (jcc rel32)          → IMAGE_REL_AMD64_REL32 at offset 2
//!   * `[rip + disp32]` (RIP-relative mem)   → IMAGE_REL_AMD64_REL32 at disp field
//!
//! Intra-function branches are skipped (no reloc emitted).
//! Unresolved targets are counted but not reloc'd.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// IMAGE_REL_AMD64_REL32 — 32-bit PC-relative (calls, jumps, [rip+disp]).
    Rel32,
    /// IMAGE_REL_AMD64_ADDR64 — 64-bit absolute pointer embedded in code/data.
    Addr64,
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
    pub rip_refs_resolved: usize,
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
    /// Resolve a data reference (RIP-relative) → (symbol_name, addend).
    fn resolve_data(&self, va: u64) -> Option<(String, i64)>;
    /// Returns true if `va` is inside the current function (intra-function branch).
    fn is_intra_function(&self, fn_va: u64, fn_size: u64, target_va: u64) -> bool {
        target_va >= fn_va && target_va < fn_va + fn_size
    }
}

/// Walk `fn_bytes` starting at `fn_va`, synthesise COFF relocations.
///
/// `fn_size` is the function's byte count (used to detect intra-function
/// branches that need no reloc). Provide `fn_size = fn_bytes.len() as u64`
/// when splitting functions individually.
pub fn recover<R: SymbolResolver>(
    fn_bytes: &[u8],
    fn_va: u64,
    fn_size: u64,
    resolver: &R,
) -> Result<RecoveryOutput> {
    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_va, DecoderOptions::NONE);
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
        let insn_offset = pc - fn_va;
        let insn_len = insn.len() as u64;

        // --- Direct near branches with a 32-bit relative operand ---
        // FlowControl::Call        = CALL rel32
        // FlowControl::UnconditionalBranch = JMP rel32
        // FlowControl::ConditionalBranch   = Jcc rel32 or Jcc rel8
        //
        // rel8 branches are exactly 2 bytes; rel32 are 5 (E8/E9) or 6 (0F 8x) bytes.
        // Only rel32 can cross function boundaries and need a relocation.
        match insn.flow_control() {
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                if insn_len >= 5 {
                    let target_va = insn.near_branch64();

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
                // Skip RIP-relative check for branch instructions.
                continue;
            }
            _ => {}
        }

        // --- RIP-relative memory operands [rip + disp32] ---
        // These appear in all non-branch instruction classes, including
        // indirect calls/jumps like `call [rip+x]` (IAT thunks).
        for op_idx in 0..insn.op_count() {
            if insn.op_kind(op_idx) != OpKind::Memory {
                continue;
            }
            if insn.memory_base() != Register::RIP {
                continue;
            }

            // memory_displacement64() is the raw sign-extended disp32 from the
            // instruction bytes; add next_ip() to obtain the absolute target VA.
            let target_va = insn.memory_displacement64();

            // The disp32 field is always the last 4 bytes of the instruction.
            let disp_off = insn_len - 4;

            match resolver.resolve_data(target_va) {
                Some((sym, addend)) => {
                    out.relocs.push(RecoveredReloc {
                        offset: insn_offset + disp_off,
                        pc,
                        kind: RelocKind::Rel32,
                        target: sym,
                        addend,
                    });
                    out.diag.rip_refs_resolved += 1;
                }
                None => {
                    trace!("{:#x}: unresolved RIP-relative ref to {:#x}", pc, target_va);
                    out.diag.rip_refs_unresolved += 1;
                }
            }
            // Each instruction has at most one RIP-relative operand.
            break;
        }
    }

    Ok(out)
}
