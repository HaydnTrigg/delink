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

use anyhow::{Context, Result};
use capstone::arch::x86;
use capstone::prelude::*;
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
    /// Addend (usually 0 for Rel32).
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
    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode32)
        .detail(false)
        .build()
        .context("init capstone x86")?;

    let insns = cs
        .disasm_all(fn_bytes, fn_va)
        .context("disassemble x86 function")?;

    let mut out = RecoveryOutput {
        relocs: Vec::new(),
        diag: RecoveryDiagnostics::default(),
    };

    for insn in insns.iter() {
        out.diag.instructions += 1;
        let pc = insn.address();
        let insn_offset = pc - fn_va;
        let bytes = insn.bytes();
        let insn_end = pc + bytes.len() as u64;

        if bytes.is_empty() {
            out.diag.decode_failures += 1;
            continue;
        }

        let (is_rel32, rel32_field_off, opcode_len) = classify_rel32(bytes);
        if !is_rel32 {
            continue;
        }
        if bytes.len() < opcode_len + 4 {
            out.diag.decode_failures += 1;
            continue;
        }

        let rel32 = i32::from_le_bytes(
            bytes[opcode_len..opcode_len + 4].try_into().unwrap(),
        ) as i64;
        // 32-bit wrapping add: address space is 32-bit.
        let target_va = (insn_end as u32).wrapping_add(rel32 as u32) as u64;

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
    }

    Ok(out)
}

/// Returns `(is_rel32, rel32_field_byte_offset, opcode_byte_count)`.
fn classify_rel32(bytes: &[u8]) -> (bool, usize, usize) {
    match bytes[0] {
        0xE8 | 0xE9 => (true, 1, 1),
        0x0F if bytes.len() >= 2 && (bytes[1] & 0xF0 == 0x80) => (true, 2, 2),
        _ => (false, 0, 0),
    }
}
