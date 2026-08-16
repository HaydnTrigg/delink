//! Walk a slice of ARM (A32) code and synthesize relocations.
//!
//! Position-independent ARM code built by GCC reaches everything outside the
//! current function through a PC-relative literal pool:
//!
//! ```text
//!   ldr r3, [pc, #N]      ; r3 = <pool word>
//!   add r3, pc, r3        ; r3 = &sym                 -> R_ARM_REL32 on the word
//!
//!   ldr r3, [pc, #N]      ; r3 = <pool word>
//!   ldr r3, [pc, r3]      ; r3 = *GOT(sym)            -> R_ARM_GOT_PREL on the word
//! ```
//!
//! so the relocation belongs to the *pool word*, not to either instruction.
//! Branches are the simple case: `bl` and out-of-function `b`/`b<cc>` carry
//! `R_ARM_CALL` / `R_ARM_JUMP24` on the instruction itself.
//!
//! ARM uses `SHT_REL`, so every relocation's addend has to be written back
//! into the field. [`apply_addend`] does that encoding; the emitter calls it
//! on its private copy of the code bytes before handing them to the writer.
//!
//! `movw`/`movt` pairs are deliberately *not* lifted. In PIC objects GCC only
//! uses them for wide immediate constants — treating them as addresses
//! produces relocations against whatever section the constant happens to
//! collide with.

use anyhow::{Context, Result};
use capstone::arch::arm::{ArmOperandType, ArmShift};
use capstone::arch::{arm, BuildsCapstone};
use capstone::prelude::*;
use capstone::{Capstone, RegId};
use delink_core::symbols::{DataSource, GlobalSymbols, ResolvedTarget};
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::trace;

/// PC reads eight bytes ahead of the executing A32 instruction.
const ARM_PC_BIAS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// `bl` — `R_ARM_CALL`.
    Call,
    /// `b` / `b<cc>` leaving the function — `R_ARM_JUMP24`.
    Jump24,
    /// PC-relative pointer in a literal pool word — `R_ARM_REL32`.
    Rel32,
    /// GOT-relative pointer in a literal pool word — `R_ARM_GOT_PREL`.
    GotPrel,
    /// Absolute pointer — `R_ARM_ABS32`.
    Abs32,
    /// 31-bit PC-relative, used by `.ARM.exidx` — `R_ARM_PREL31`.
    Prel31,
}

#[derive(Debug, Clone)]
pub struct RecoveredReloc {
    /// Offset of the relocated field from the start of the recovered slice.
    pub offset: u64,
    /// Virtual address of the instruction that motivated this relocation
    /// (for `Rel32`/`GotPrel` this is the referring instruction, not the
    /// pool word).
    pub pc: u64,
    pub kind: RelocKind,
    pub target: String,
    /// Implicit addend. ARM is `SHT_REL`, so this must be encoded into the
    /// field with [`apply_addend`] rather than stored in the relocation.
    pub addend: i64,
    pub target_addr: u64,
}

#[derive(Debug, Default, Clone)]
pub struct RecoveryDiagnostics {
    pub instructions: usize,
    pub decode_failures: usize,
    pub bl_resolved: usize,
    pub bl_unresolved: usize,
    /// `ldr rN, [pc, #imm]` sites seen.
    pub pool_loads: usize,
    /// Pool words successfully turned into a relocation.
    pub pool_relocated: usize,
    /// Pool words whose target resolved to no known symbol.
    pub pool_unresolved: usize,
    /// Pool words that live outside the slice being emitted, so the addend
    /// cannot be patched in this object.
    pub pool_out_of_range: usize,
    /// GOT loads whose slot resolved to a module-local address that is not a
    /// symbol start; the interior offset cannot be expressed by `GOT_PREL`.
    pub got_slot_interior: usize,
    /// Two references disagreed about the same pool word.
    pub pool_conflicts: usize,
}

pub struct RecoveryOutput {
    pub relocs: Vec<RecoveredReloc>,
    pub diag: RecoveryDiagnostics,
}

/// The code section being recovered from, so pool words that sit outside the
/// current function are still readable.
pub struct CodeImage<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
}

impl CodeImage<'_> {
    pub fn word(&self, addr: u64) -> Option<u32> {
        let off = addr.checked_sub(self.base)? as usize;
        let bytes = self.bytes.get(off..off + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }
}

/// Disassemble `[fn_addr, fn_addr + fn_size)` out of `image` and synthesize
/// relocations. Offsets in the returned relocs are relative to `fn_addr`.
pub fn recover(
    fn_addr: u64,
    fn_size: u64,
    image: &CodeImage<'_>,
    symbols: &GlobalSymbols,
) -> Result<RecoveryOutput> {
    let cs = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Arm)
        .detail(true)
        .build()
        .context("init capstone arm")?;

    let start = fn_addr
        .checked_sub(image.base)
        .context("function starts before the code image")? as usize;
    let end = start + fn_size as usize;
    let bytes = image
        .bytes
        .get(start..end)
        .context("function extends past the code image")?;

    let mut out = RecoveryOutput {
        relocs: Vec::new(),
        diag: RecoveryDiagnostics::default(),
    };

    // Literal pools are data embedded in `.text`; find them first so the
    // second pass doesn't disassemble constants as instructions. Growing the
    // set monotonically guarantees the loop terminates.
    let mut pools: BTreeSet<u64> = BTreeSet::new();
    for _ in 0..3 {
        let found = scan_pool_words(&cs, bytes, fn_addr, &pools);
        let before = pools.len();
        pools.extend(found);
        if pools.len() == before {
            break;
        }
    }

    let mut tracker: HashMap<u32, PoolLoad> = HashMap::new();
    // One pool word can only carry one relocation; remember what we decided.
    let mut claimed: HashMap<u64, (RelocKind, String, i64)> = HashMap::new();

    for (insn_addr, insn_bytes) in code_runs(bytes, fn_addr, &pools) {
        let Ok(insns) = cs.disasm_all(insn_bytes, insn_addr) else {
            out.diag.decode_failures += 1;
            continue;
        };
        for insn in insns.iter() {
            out.diag.instructions += 1;
            let pc = insn.address();
            let Some(mnemonic) = insn.mnemonic() else {
                out.diag.decode_failures += 1;
                tracker.clear();
                continue;
            };
            let Ok(detail) = cs.insn_detail(insn) else {
                out.diag.decode_failures += 1;
                tracker.clear();
                continue;
            };
            let arch_detail = detail.arch_detail();
            let Some(arm) = arch_detail.arm() else {
                out.diag.decode_failures += 1;
                tracker.clear();
                continue;
            };
            let ops: Vec<arm::ArmOperand> = arm.operands().collect();

            match classify(&ops, insn) {
                Insn::Branch { link, target } => {
                    let inside = target >= fn_addr && target < fn_addr + fn_size;
                    if link {
                        handle_branch(symbols, pc - fn_addr, pc, target, RelocKind::Call, &mut out);
                    } else if !inside {
                        handle_branch(
                            symbols,
                            pc - fn_addr,
                            pc,
                            target,
                            RelocKind::Jump24,
                            &mut out,
                        );
                    }
                    if link {
                        // A call clobbers the caller-saved scratch registers.
                        tracker.clear();
                    }
                }
                Insn::PoolLoad { rd, pool_addr } => {
                    out.diag.pool_loads += 1;
                    match image.word(pool_addr) {
                        Some(value) => {
                            tracker.insert(rd, PoolLoad { pool_addr, value });
                        }
                        None => {
                            tracker.remove(&rd);
                        }
                    }
                }
                Insn::AddPc { rd, rn } => {
                    if let Some(site) = tracker.get(&rn).copied() {
                        let target = pc
                            .wrapping_add(ARM_PC_BIAS)
                            .wrapping_add(site.value as i32 as i64 as u64);
                        emit_pcrel(
                            symbols,
                            &site,
                            pc,
                            target,
                            fn_addr,
                            fn_size,
                            &mut claimed,
                            &mut out,
                        );
                    }
                    tracker.remove(&rd);
                }
                Insn::PcIndexedLoad { rd, rn } => {
                    if let Some(site) = tracker.get(&rn).copied() {
                        let target = pc
                            .wrapping_add(ARM_PC_BIAS)
                            .wrapping_add(site.value as i32 as i64 as u64);
                        if symbols.in_got(target) {
                            emit_got(
                                symbols,
                                &site,
                                pc,
                                target,
                                fn_addr,
                                fn_size,
                                &mut claimed,
                                &mut out,
                            );
                        } else {
                            emit_pcrel(
                                symbols,
                                &site,
                                pc,
                                target,
                                fn_addr,
                                fn_size,
                                &mut claimed,
                                &mut out,
                            );
                        }
                    }
                    tracker.remove(&rd);
                }
                Insn::Other => {
                    for r in written_registers(mnemonic, &ops) {
                        tracker.remove(&r);
                    }
                }
                Insn::Barrier => tracker.clear(),
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct PoolLoad {
    pool_addr: u64,
    value: u32,
}

enum Insn {
    Branch {
        link: bool,
        target: u64,
    },
    /// `ldr rD, [pc, #imm]`
    PoolLoad {
        rd: u32,
        pool_addr: u64,
    },
    /// `add rD, pc, rN`
    AddPc {
        rd: u32,
        rn: u32,
    },
    /// `ldr rD, [pc, rN]`
    PcIndexedLoad {
        rd: u32,
        rn: u32,
    },
    /// Ends a basic block / clobbers everything we track.
    Barrier,
    Other,
}

const ARM_REG_PC: u32 = arm::ArmReg::ARM_REG_PC;

fn insn_id(insn: &capstone::Insn<'_>) -> u32 {
    insn.id().0
}

/// Classify by capstone instruction id rather than mnemonic text: conditional
/// forms (`beq`, `blne`, …) share an id with their unconditional counterpart,
/// and `bl`-prefixed mnemonics like `bls` ("b, ls") do not.
fn classify(ops: &[arm::ArmOperand], insn: &capstone::Insn<'_>) -> Insn {
    use capstone_arm_ids::*;
    let id = insn_id(insn);

    if id == ARM_INS_BL || id == ARM_INS_BLX {
        return match first_imm(ops) {
            Some(target) => Insn::Branch { link: true, target },
            // `blx rN` — an indirect call; still clobbers scratch registers.
            None => Insn::Barrier,
        };
    }
    if id == ARM_INS_B {
        return match first_imm(ops) {
            Some(target) => Insn::Branch {
                link: false,
                target,
            },
            None => Insn::Barrier,
        };
    }
    if id == ARM_INS_BX || id == ARM_INS_BXJ {
        return Insn::Barrier;
    }

    if id == ARM_INS_LDR && ops.len() == 2 {
        if let (Some(rd), ArmOperandType::Mem(mem)) = (reg_of(&ops[0]), &ops[1].op_type) {
            if mem.base().0 as u32 == ARM_REG_PC && matches!(ops[1].shift, ArmShift::Invalid) {
                if mem.index().0 == 0 {
                    let pool_addr = insn
                        .address()
                        .wrapping_add(ARM_PC_BIAS)
                        .wrapping_add(mem.disp() as i64 as u64);
                    return Insn::PoolLoad { rd, pool_addr };
                }
                if !ops[1].subtracted {
                    return Insn::PcIndexedLoad {
                        rd,
                        rn: mem.index().0 as u32,
                    };
                }
            }
        }
    }

    if id == ARM_INS_ADD && ops.len() == 3 && matches!(ops[2].shift, ArmShift::Invalid) {
        if let (Some(rd), Some(rn), Some(rm)) = (reg_of(&ops[0]), reg_of(&ops[1]), reg_of(&ops[2]))
        {
            if rn == ARM_REG_PC {
                return Insn::AddPc { rd, rn: rm };
            }
        }
    }

    if id == ARM_INS_POP || id == ARM_INS_LDM {
        // `pop {..., pc}` returns; anything else just clobbers registers.
        if ops.iter().any(|o| reg_of(o) == Some(ARM_REG_PC)) {
            return Insn::Barrier;
        }
    }

    Insn::Other
}

/// The handful of capstone ARM instruction ids we branch on.
mod capstone_arm_ids {
    use capstone::arch::arm::ArmInsn;
    pub const ARM_INS_ADD: u32 = ArmInsn::ARM_INS_ADD as u32;
    pub const ARM_INS_B: u32 = ArmInsn::ARM_INS_B as u32;
    pub const ARM_INS_BL: u32 = ArmInsn::ARM_INS_BL as u32;
    pub const ARM_INS_BLX: u32 = ArmInsn::ARM_INS_BLX as u32;
    pub const ARM_INS_BX: u32 = ArmInsn::ARM_INS_BX as u32;
    pub const ARM_INS_BXJ: u32 = ArmInsn::ARM_INS_BXJ as u32;
    pub const ARM_INS_LDM: u32 = ArmInsn::ARM_INS_LDM as u32;
    pub const ARM_INS_LDR: u32 = ArmInsn::ARM_INS_LDR as u32;
    pub const ARM_INS_POP: u32 = ArmInsn::ARM_INS_POP as u32;
}

fn reg_of(op: &arm::ArmOperand) -> Option<u32> {
    match op.op_type {
        ArmOperandType::Reg(RegId(r)) => Some(r as u32),
        _ => None,
    }
}

fn first_imm(ops: &[arm::ArmOperand]) -> Option<u64> {
    ops.iter().find_map(|op| match op.op_type {
        ArmOperandType::Imm(v) => Some(v as u32 as u64),
        _ => None,
    })
}

/// Which registers does this instruction overwrite? Capstone's ARM operands
/// only carry access flags under its "full" feature, so infer from the
/// mnemonic and err toward over-invalidation: a stale tracker entry would
/// produce a *wrong* relocation, a missing one merely produces none.
fn written_registers(mnemonic: &str, ops: &[arm::ArmOperand]) -> Vec<u32> {
    let writes_none = mnemonic.starts_with("str")
        || mnemonic.starts_with("vstr")
        || mnemonic.starts_with("stm")
        || mnemonic.starts_with("push")
        || mnemonic.starts_with("cmp")
        || mnemonic.starts_with("cmn")
        || mnemonic.starts_with("tst")
        || mnemonic.starts_with("teq");
    if writes_none {
        return Vec::new();
    }
    // `ldm`/`pop` write every register in their list.
    if mnemonic.starts_with("ldm") || mnemonic.starts_with("pop") {
        return ops.iter().filter_map(reg_of).collect();
    }
    ops.iter().take(1).filter_map(reg_of).collect()
}

/// First pass: find every word loaded as a PC-relative literal, so the second
/// pass can skip it instead of decoding a constant as an instruction.
fn scan_pool_words(cs: &Capstone, bytes: &[u8], base: u64, known: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    let limit = base + bytes.len() as u64;
    for (addr, run) in code_runs(bytes, base, known) {
        let Ok(insns) = cs.disasm_all(run, addr) else {
            continue;
        };
        for insn in insns.iter() {
            let Some(mnemonic) = insn.mnemonic() else {
                continue;
            };
            // `ldr` holds addresses; `vldr`/`ldrd` hold constants, but both
            // occupy pool space that must not be decoded.
            if !(mnemonic.starts_with("ldr") || mnemonic.starts_with("vldr")) {
                continue;
            }
            let Ok(detail) = cs.insn_detail(insn) else {
                continue;
            };
            let arch_detail = detail.arch_detail();
            let Some(arm) = arch_detail.arm() else {
                continue;
            };
            for op in arm.operands() {
                if let ArmOperandType::Mem(mem) = op.op_type {
                    if mem.base().0 as u32 == ARM_REG_PC && mem.index().0 == 0 {
                        let target = insn
                            .address()
                            .wrapping_add(ARM_PC_BIAS)
                            .wrapping_add(mem.disp() as i64 as u64);
                        if target >= base && target < limit && target % 4 == 0 {
                            found.insert(target);
                            // `ldrd`/`vldr <Dn>` cover two words.
                            if (mnemonic.starts_with("ldrd") || mnemonic.starts_with("vldr"))
                                && target + 4 < limit
                            {
                                found.insert(target + 4);
                            }
                        }
                    }
                }
            }
        }
    }
    found
}

/// Split `bytes` into the maximal runs that contain no known pool word.
fn code_runs<'a>(bytes: &'a [u8], base: u64, pools: &BTreeSet<u64>) -> Vec<(u64, &'a [u8])> {
    let mut runs = Vec::new();
    let mut run_start = 0usize;
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let addr = base + cursor as u64;
        if pools.contains(&addr) {
            if cursor > run_start {
                runs.push((base + run_start as u64, &bytes[run_start..cursor]));
            }
            run_start = cursor + 4;
        }
        cursor += 4;
    }
    if run_start < bytes.len() {
        runs.push((base + run_start as u64, &bytes[run_start..]));
    }
    runs
}

fn handle_branch(
    symbols: &GlobalSymbols,
    offset: u64,
    pc: u64,
    target: u64,
    kind: RelocKind,
    out: &mut RecoveryOutput,
) {
    // R_ARM_CALL / R_ARM_JUMP24 compute `(S + A) - P` and the CPU adds the
    // 8-byte PC bias back on, so a plain call to `S` needs `A == -8`.
    let bias = -(ARM_PC_BIAS as i64);
    let (name, addend) = match symbols.resolve(target) {
        ResolvedTarget::Internal(func) => (func.export_name().to_string(), bias),
        ResolvedTarget::ExternalPlt(name) => (name.to_string(), bias),
        ResolvedTarget::Unknown => match symbols.resolve_into(target) {
            Some((func, delta)) => (func.export_name().to_string(), bias + delta as i64),
            None => {
                trace!("{pc:#x}: {kind:?} to unresolved {target:#x}");
                out.diag.bl_unresolved += 1;
                return;
            }
        },
    };

    out.relocs.push(RecoveredReloc {
        offset,
        pc,
        kind,
        target: name,
        addend,
        target_addr: target,
    });
    out.diag.bl_resolved += 1;
}

#[allow(clippy::too_many_arguments)]
fn emit_pcrel(
    symbols: &GlobalSymbols,
    site: &PoolLoad,
    ref_pc: u64,
    target: u64,
    fn_addr: u64,
    fn_size: u64,
    claimed: &mut HashMap<u64, (RelocKind, String, i64)>,
    out: &mut RecoveryOutput,
) {
    let Some(res) = symbols.resolve_data(target) else {
        trace!(
            "{ref_pc:#x}: pc-relative pool word -> unresolved {target:#x} (in {})",
            symbols.classify_section(target)
        );
        out.diag.pool_unresolved += 1;
        return;
    };
    // R_ARM_REL32 stores `S + A - P` at the pool word `P`; the referring
    // instruction then computes `ref_pc + 8 + word`, so
    // `A = P - (ref_pc + 8) + res.addend`.
    let addend = site.pool_addr as i64 - (ref_pc + ARM_PC_BIAS) as i64 + res.addend;
    push_pool_reloc(
        site,
        ref_pc,
        RelocKind::Rel32,
        res.symbol,
        addend,
        target,
        fn_addr,
        fn_size,
        claimed,
        out,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_got(
    symbols: &GlobalSymbols,
    site: &PoolLoad,
    ref_pc: u64,
    slot_addr: u64,
    fn_addr: u64,
    fn_size: u64,
    claimed: &mut HashMap<u64, (RelocKind, String, i64)>,
    out: &mut RecoveryOutput,
) {
    let Some(res) = symbols.resolve_got_slot(slot_addr) else {
        trace!("{ref_pc:#x}: GOT load from unmapped slot {slot_addr:#x}");
        out.diag.pool_unresolved += 1;
        return;
    };
    if res.addend != 0 && res.source != DataSource::GotSlot {
        // The slot points into the middle of a symbol. `GOT_PREL` can only
        // name a symbol, so the interior offset would be lost.
        out.diag.got_slot_interior += 1;
    }
    // R_ARM_GOT_PREL stores `GOT(S) + A - P`; the load computes
    // `ref_pc + 8 + word`, so `A = P - (ref_pc + 8)`.
    let addend = site.pool_addr as i64 - (ref_pc + ARM_PC_BIAS) as i64;
    push_pool_reloc(
        site,
        ref_pc,
        RelocKind::GotPrel,
        res.symbol,
        addend,
        slot_addr,
        fn_addr,
        fn_size,
        claimed,
        out,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_pool_reloc(
    site: &PoolLoad,
    ref_pc: u64,
    kind: RelocKind,
    symbol: String,
    addend: i64,
    target_addr: u64,
    fn_addr: u64,
    fn_size: u64,
    claimed: &mut HashMap<u64, (RelocKind, String, i64)>,
    out: &mut RecoveryOutput,
) {
    if site.pool_addr < fn_addr || site.pool_addr + 4 > fn_addr + fn_size {
        // Shared pool outside this function's bytes: the word lives in another
        // object after the split, so we cannot patch its addend here.
        out.diag.pool_out_of_range += 1;
        trace!(
            "{ref_pc:#x}: pool word {:#x} lies outside {fn_addr:#x}+{fn_size:#x}",
            site.pool_addr
        );
        return;
    }
    if let Some(prev) = claimed.get(&site.pool_addr) {
        if prev.0 != kind || prev.1 != symbol || prev.2 != addend {
            out.diag.pool_conflicts += 1;
            trace!(
                "{ref_pc:#x}: pool word {:#x} already claimed by {:?}/{} (now {kind:?}/{symbol})",
                site.pool_addr,
                prev.0,
                prev.1
            );
        }
        return;
    }
    claimed.insert(site.pool_addr, (kind, symbol.clone(), addend));
    out.relocs.push(RecoveredReloc {
        offset: site.pool_addr - fn_addr,
        pc: ref_pc,
        kind,
        target: symbol,
        addend,
        target_addr,
    });
    out.diag.pool_relocated += 1;
}

/// ELF relocation type for a recovered kind.
pub fn elf_reloc_type(kind: RelocKind) -> u32 {
    use object::elf::*;
    match kind {
        RelocKind::Call => R_ARM_CALL,
        RelocKind::Jump24 => R_ARM_JUMP24,
        RelocKind::Rel32 => R_ARM_REL32,
        RelocKind::GotPrel => R_ARM_GOT_PREL,
        RelocKind::Abs32 => R_ARM_ABS32,
        RelocKind::Prel31 => R_ARM_PREL31,
    }
}

/// Encode `addend` into the relocated field at `offset` in `buf`.
///
/// ARM relocations are `SHT_REL`: the linker reads the addend back out of the
/// field, so the original linked-in value has to be replaced.
pub fn apply_addend(kind: RelocKind, buf: &mut [u8], offset: usize, addend: i64) -> Result<()> {
    let field = buf
        .get_mut(offset..offset + 4)
        .with_context(|| format!("relocation offset {offset} past end of section data"))?;
    match kind {
        RelocKind::Rel32 | RelocKind::Abs32 | RelocKind::GotPrel => {
            field.copy_from_slice(&(addend as i32).to_le_bytes());
        }
        RelocKind::Prel31 => {
            let old = u32::from_le_bytes(field[..].try_into().unwrap());
            let value = ((addend as i32) as u32) & 0x7fff_ffff;
            field.copy_from_slice(&((old & 0x8000_0000) | value).to_le_bytes());
        }
        RelocKind::Call | RelocKind::Jump24 => {
            // Keep the condition code and opcode, replace the 24-bit
            // word-offset immediate.
            let old = u32::from_le_bytes(field[..].try_into().unwrap());
            let imm = ((addend >> 2) as u32) & 0x00ff_ffff;
            field.copy_from_slice(&((old & 0xff00_0000) | imm).to_le_bytes());
        }
    }
    Ok(())
}

/// Set of relocation offsets, used by the emitter to assert it never patches
/// the same field twice.
pub type PatchedOffsets = HashSet<u64>;

#[cfg(test)]
mod tests {
    use super::*;

    /// `bl` with the canonical "unresolved call" displacement: the field must
    /// keep its condition/opcode byte and encode `A = -8` as `0xfffffe`.
    #[test]
    fn call_addend_encodes_the_canonical_bl() {
        // `bl #0x1234` as originally linked.
        let mut buf = 0xeb00_0487u32.to_le_bytes().to_vec();
        apply_addend(RelocKind::Call, &mut buf, 0, -8).unwrap();
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0xebff_fffe);
    }

    #[test]
    fn jump24_keeps_the_condition_code() {
        // `beq` — condition `0000`, so the top byte is 0x0a.
        let mut buf = 0x0a00_1234u32.to_le_bytes().to_vec();
        apply_addend(RelocKind::Jump24, &mut buf, 0, -8).unwrap();
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0x0aff_fffe);
    }

    #[test]
    fn call_addend_carries_an_interior_offset() {
        let mut buf = 0xeb00_0000u32.to_le_bytes().to_vec();
        // Branching to `sym + 0x20` needs `A = -8 + 0x20 = 0x18`.
        apply_addend(RelocKind::Call, &mut buf, 0, 0x18).unwrap();
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0xeb00_0006);
    }

    #[test]
    fn data_addends_replace_the_whole_word() {
        for kind in [RelocKind::Rel32, RelocKind::Abs32, RelocKind::GotPrel] {
            let mut buf = 0xdead_beefu32.to_le_bytes().to_vec();
            apply_addend(kind, &mut buf, 0, 0x104).unwrap();
            assert_eq!(u32::from_le_bytes(buf.clone().try_into().unwrap()), 0x104);

            let mut buf = vec![0u8; 4];
            apply_addend(kind, &mut buf, 0, -0x104).unwrap();
            assert_eq!(
                i32::from_le_bytes(buf.try_into().unwrap()),
                -0x104,
                "{kind:?} must round-trip a negative addend"
            );
        }
    }

    /// PREL31 owns 31 bits; bit 31 of an `.ARM.exidx` word is a flag and has
    /// to survive.
    #[test]
    fn prel31_preserves_the_top_bit() {
        let mut buf = 0x8000_0000u32.to_le_bytes().to_vec();
        apply_addend(RelocKind::Prel31, &mut buf, 0, 0x20).unwrap();
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0x8000_0020);

        let mut buf = 0u32.to_le_bytes().to_vec();
        apply_addend(RelocKind::Prel31, &mut buf, 0, -0x20).unwrap();
        assert_eq!(u32::from_le_bytes(buf.try_into().unwrap()), 0x7fff_ffe0);
    }

    #[test]
    fn addend_past_the_end_is_an_error() {
        let mut buf = vec![0u8; 4];
        assert!(apply_addend(RelocKind::Rel32, &mut buf, 2, 0).is_err());
    }

    #[test]
    fn reloc_types_match_aaelf() {
        assert_eq!(elf_reloc_type(RelocKind::Call), 28);
        assert_eq!(elf_reloc_type(RelocKind::Jump24), 29);
        assert_eq!(elf_reloc_type(RelocKind::Rel32), 3);
        assert_eq!(elf_reloc_type(RelocKind::Abs32), 2);
        assert_eq!(elf_reloc_type(RelocKind::Prel31), 42);
        assert_eq!(elf_reloc_type(RelocKind::GotPrel), 96);
    }

    /// Pool words must be carved out of the runs handed to the disassembler,
    /// or constants get decoded as instructions.
    #[test]
    fn code_runs_skip_pool_words() {
        // Seven words at 0x1000..0x101c, with pools at the second and sixth.
        let bytes = vec![0u8; 28];
        let pools = BTreeSet::from([0x1004, 0x1014]);
        let runs = code_runs(&bytes, 0x1000, &pools);
        let shape: Vec<(u64, usize)> = runs.iter().map(|(a, b)| (*a, b.len())).collect();
        assert_eq!(shape, vec![(0x1000, 4), (0x1008, 12), (0x1018, 4)]);
    }

    #[test]
    fn code_runs_without_pools_is_one_span() {
        let bytes = vec![0u8; 12];
        let runs = code_runs(&bytes, 0x2000, &BTreeSet::new());
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, 0x2000);
        assert_eq!(runs[0].1.len(), 12);
    }

    #[test]
    fn code_image_reads_within_bounds() {
        let bytes = 0x1122_3344u32.to_le_bytes().to_vec();
        let image = CodeImage {
            base: 0x8000,
            bytes: &bytes,
        };
        assert_eq!(image.word(0x8000), Some(0x1122_3344));
        assert_eq!(image.word(0x7ffc), None);
        assert_eq!(image.word(0x8004), None);
    }
}
