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

use anyhow::{Context, Result};
use capstone::arch::x86;
use capstone::prelude::*;
use tracing::trace;

// Capstone x86_64 register ID for RIP (stable in capstone 4.x / capstone-rs 0.13).
const X86_REG_RIP: u16 = 41;

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
    /// Addend (usually 0 for Rel32; embedded in the bytes for COFF).
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
    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .context("init capstone x86_64")?;

    let insns = cs
        .disasm_all(fn_bytes, fn_va)
        .context("disassemble x86_64 function")?;

    let mut out = RecoveryOutput {
        relocs: Vec::new(),
        diag: RecoveryDiagnostics::default(),
    };

    for insn in insns.iter() {
        out.diag.instructions += 1;
        let pc = insn.address();
        let insn_offset = pc - fn_va; // offset within fn_bytes
        let bytes = insn.bytes();
        let insn_end = pc + bytes.len() as u64;

        if bytes.is_empty() {
            out.diag.decode_failures += 1;
            continue;
        }

        // --- Direct calls and jumps (rel32) ---
        // E8 rel32    call
        // E9 rel32    jmp
        // 0F 8x rel32 jcc
        let (is_rel32, rel32_field_off, opcode_len) = classify_rel32(bytes);
        if is_rel32 {
            if bytes.len() < opcode_len + 4 {
                out.diag.decode_failures += 1;
                continue;
            }
            let rel32 = i32::from_le_bytes(
                bytes[opcode_len..opcode_len + 4].try_into().unwrap(),
            ) as i64;
            let target_va = insn_end.wrapping_add(rel32 as u64);

            // Skip intra-function branches (they need no reloc).
            if resolver.is_intra_function(fn_va, fn_size, target_va) {
                continue;
            }

            match resolver.resolve_code(target_va) {
                Some((sym, addend)) => {
                    out.relocs.push(RecoveredReloc {
                        offset: insn_offset + rel32_field_off as u64,
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
            continue;
        }

        // --- RIP-relative memory operands [rip + disp32] ---
        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => {
                out.diag.decode_failures += 1;
                continue;
            }
        };
        let arch_detail = detail.arch_detail();
        let Some(x86_detail) = arch_detail.x86() else {
            out.diag.decode_failures += 1;
            continue;
        };

        for op in x86_detail.operands() {
            if let x86::X86OperandType::Mem(mem) = op.op_type {
                if mem.base().0 != X86_REG_RIP {
                    continue;
                }
                // RIP-relative: disp32 is always the last 4 bytes of the instruction.
                if bytes.len() < 4 {
                    continue;
                }
                let disp_field_off = bytes.len() as u64 - 4;
                let target_va = insn_end.wrapping_add(mem.disp() as u64);

                match resolver.resolve_data(target_va) {
                    Some((sym, addend)) => {
                        out.relocs.push(RecoveredReloc {
                            offset: insn_offset + disp_field_off,
                            pc,
                            kind: RelocKind::Rel32,
                            target: sym,
                            addend,
                        });
                        out.diag.rip_refs_resolved += 1;
                    }
                    None => {
                        trace!(
                            "{:#x}: unresolved RIP-relative ref to {:#x}",
                            pc, target_va
                        );
                        out.diag.rip_refs_unresolved += 1;
                    }
                }
                // Each instruction has at most one RIP-relative operand.
                break;
            }
        }
    }

    Ok(out)
}

/// Returns `(is_rel32, rel32_field_byte_offset, opcode_byte_count)`.
fn classify_rel32(bytes: &[u8]) -> (bool, usize, usize) {
    match bytes[0] {
        0xE8 | 0xE9 => (true, 1, 1), // call/jmp rel32
        0x0F if bytes.len() >= 2 && (bytes[1] & 0xF0 == 0x80) => (true, 2, 2), // jcc rel32
        _ => (false, 0, 0),
    }
}
