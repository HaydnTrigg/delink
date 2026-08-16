//! Global symbol resolver.
//!
//! Maps every known address in the binary to a symbol: functions and globals
//! from DWARF CUs (or the reconstructed `.symtab` index), plus imported
//! symbols reached through the PLT or GOT. The arch-specific relocation
//! recovery pass consults this when lifting code patterns like `bl <addr>`,
//! `adrp x0, page; ldr x1, [x0, #lo12]` (AArch64) or
//! `ldr r3, [pc, #n]; ldr r3, [pc, r3]` (ARM).

use crate::binary::Binary;
use crate::cu::CuIndex;
use crate::error::Result;
use delink_arch::{Arch, ElfClass};
use object::{Object as _, ObjectSection as _};
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

#[derive(Debug, Clone)]
pub struct FunctionRef {
    pub cu_id: usize,
    pub name: String,
    pub linkage_name: Option<String>,
    pub size: u64,
    pub external: bool,
}

impl FunctionRef {
    pub fn export_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct VariableRef {
    pub cu_id: usize,
    pub name: String,
    pub linkage_name: Option<String>,
    pub external: bool,
}

impl VariableRef {
    pub fn export_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub enum ResolvedTarget<'a> {
    /// Resolved to a function inside one of our CUs.
    Internal(&'a FunctionRef),
    /// Resolved via the PLT to an imported dynamic symbol.
    ExternalPlt(&'a str),
    /// Address falls outside all known ranges.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DataResolution {
    pub symbol: String,
    pub addend: i64,
    pub source: DataSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    Function,
    Variable,
    GotSlot,
    SectionRelative,
}

/// Canonical symbol names we emit at the start of each shared data section.
/// Per-CU `.o`s reference these via addends; `__shared_data.o` defines them.
pub const SYM_RODATA_START: &str = "__delink_rodata_start";
pub const SYM_DATA_START: &str = "__delink_data_start";
pub const SYM_DATA_REL_RO_START: &str = "__delink_data_rel_ro_start";
pub const SYM_DATA_REL_RO_LOCAL_START: &str = "__delink_data_rel_ro_local_start";
pub const SYM_BSS_START: &str = "__delink_bss_start";

pub struct GlobalSymbols {
    /// Function start address → function descriptor.
    pub functions: BTreeMap<u64, FunctionRef>,
    /// Global variable address → variable descriptor.
    pub variables: BTreeMap<u64, VariableRef>,
    /// PLT stub address → dynamic symbol name.
    pub plt: HashMap<u64, String>,
    /// `.got` slot address → dynamic symbol name (symbol-bearing slots only).
    pub got: HashMap<u64, String>,
    /// `.got` slot address → module-local address it points at.
    pub got_local: HashMap<u64, u64>,
    pub plt_range: Option<Range<u64>>,
    pub got_range: Option<Range<u64>>,
    pub text_range: Range<u64>,
    pub rodata_range: Option<Range<u64>>,
    pub data_range: Option<Range<u64>>,
    pub data_rel_ro_range: Option<Range<u64>>,
    pub data_rel_ro_local_range: Option<Range<u64>>,
    pub bss_range: Option<Range<u64>>,
    pub arch: Arch,
}

const AARCH64_PLT_HEADER_SIZE: u64 = 32;
const AARCH64_PLT_ENTRY_SIZE: u64 = 16;
/// Classic AAELF PLT: a 20-byte PLT0 followed by 12-byte entries.
const ARM_PLT_HEADER_SIZE: u64 = 20;
const ARM_PLT_ENTRY_SIZE: u64 = 12;

impl GlobalSymbols {
    pub fn build(binary: &Binary<'_>, cus: &CuIndex) -> Result<Self> {
        let (functions, variables) = Self::maps_from_cus(cus);
        Self::build_from_maps(binary, functions, variables)
    }

    /// Collect the function and variable maps a `CuIndex` describes, before
    /// any name disambiguation. Callers that have additional symbols to fold
    /// in (the `.symtab` path) extend these and then call
    /// [`GlobalSymbols::build_from_maps`] once, so every name is considered
    /// together.
    pub fn maps_from_cus(
        cus: &CuIndex,
    ) -> (BTreeMap<u64, FunctionRef>, BTreeMap<u64, VariableRef>) {
        let mut functions = BTreeMap::new();
        let mut variables = BTreeMap::new();
        for cu in &cus.units {
            for f in &cu.functions {
                if f.size == 0 {
                    continue;
                }
                functions.insert(
                    f.addr,
                    FunctionRef {
                        cu_id: cu.id,
                        name: f.name.clone(),
                        linkage_name: f.linkage_name.clone(),
                        size: f.size,
                        external: f.external,
                    },
                );
            }
            for v in &cu.variables {
                if v.addr == 0 {
                    continue;
                }
                variables.insert(
                    v.addr,
                    VariableRef {
                        cu_id: cu.id,
                        name: v.name.clone(),
                        linkage_name: v.linkage_name.clone(),
                        external: v.external,
                    },
                );
            }
        }
        (functions, variables)
    }

    /// Build from pre-resolved function/variable maps. Used by the `.symtab`
    /// reconstruction path, which derives its own function set.
    pub fn build_from_maps(
        binary: &Binary<'_>,
        mut functions: BTreeMap<u64, FunctionRef>,
        mut variables: BTreeMap<u64, VariableRef>,
    ) -> Result<Self> {
        disambiguate_names(&mut functions, &mut variables);

        let section_range = |name: &str| {
            binary
                .elf
                .section_by_name(name)
                .map(|s| s.address()..s.address() + s.size())
        };

        let plt_range = section_range(".plt");
        let got_range = merge_ranges(section_range(".got"), section_range(".got.plt"));
        let text_range = section_range(".text").unwrap_or(0..0);
        let rodata_range = section_range(".rodata");
        let data_range = section_range(".data");
        let data_rel_ro_range = section_range(".data.rel.ro");
        let data_rel_ro_local_range = section_range(".data.rel.ro.local");
        let bss_range = section_range(".bss");

        let dyn_relocs = read_all_dyn_relocs(binary)?;
        let plt = build_plt_map(binary, &dyn_relocs, plt_range.clone())?;
        let (got, got_local) = build_got_maps(binary, &dyn_relocs);

        Ok(Self {
            functions,
            variables,
            plt,
            got,
            got_local,
            plt_range,
            got_range,
            text_range,
            rodata_range,
            data_range,
            data_rel_ro_range,
            data_rel_ro_local_range,
            bss_range,
            arch: binary.arch,
        })
    }

    pub fn resolve(&self, target: u64) -> ResolvedTarget<'_> {
        if let Some(f) = self.functions.get(&target) {
            return ResolvedTarget::Internal(f);
        }
        if let Some(range) = &self.plt_range {
            if range.contains(&target) {
                if let Some(name) = self.plt.get(&target) {
                    return ResolvedTarget::ExternalPlt(name);
                }
            }
        }
        ResolvedTarget::Unknown
    }

    /// If `target` lands inside a known function (not just at its start),
    /// return the owning function and the offset within it.
    pub fn resolve_into(&self, target: u64) -> Option<(&FunctionRef, u64)> {
        let (start, f) = self.functions.range(..=target).next_back()?;
        if target < *start + f.size {
            Some((f, target - *start))
        } else {
            None
        }
    }

    /// Resolve a data/code address that materialized from e.g. `adrp+add`
    /// (AArch64) or a PC-relative literal pool word (ARM).
    pub fn resolve_data(&self, addr: u64) -> Option<DataResolution> {
        if let Some(v) = self.variables.get(&addr) {
            return Some(DataResolution {
                symbol: v.export_name().to_string(),
                addend: 0,
                source: DataSource::Variable,
            });
        }
        if let Some(f) = self.functions.get(&addr) {
            return Some(DataResolution {
                symbol: f.export_name().to_string(),
                addend: 0,
                source: DataSource::Function,
            });
        }
        if let Some((start, f)) = self.functions.range(..=addr).next_back() {
            if addr < *start + f.size {
                return Some(DataResolution {
                    symbol: f.export_name().to_string(),
                    addend: (addr - *start) as i64,
                    source: DataSource::Function,
                });
            }
        }
        if let Some(name) = self.got.get(&addr) {
            return Some(DataResolution {
                symbol: name.clone(),
                addend: 0,
                source: DataSource::GotSlot,
            });
        }
        if let Some(r) = self.section_relative(addr) {
            return Some(r);
        }
        None
    }

    /// Resolve what a `.got` slot at `slot_addr` names, following module-local
    /// slots through to the address they hold.
    ///
    /// Returns the symbol the caller should reference plus the addend needed
    /// to reach the exact target.
    pub fn resolve_got_slot(&self, slot_addr: u64) -> Option<DataResolution> {
        if let Some(name) = self.got.get(&slot_addr) {
            return Some(DataResolution {
                symbol: name.clone(),
                addend: 0,
                source: DataSource::GotSlot,
            });
        }
        let target = *self.got_local.get(&slot_addr)?;
        self.resolve_data(target)
    }

    fn section_relative(&self, addr: u64) -> Option<DataResolution> {
        let hit = |range: &Option<Range<u64>>, name: &'static str| -> Option<DataResolution> {
            range.as_ref().and_then(|r| {
                if r.contains(&addr) {
                    Some(DataResolution {
                        symbol: name.to_string(),
                        addend: (addr - r.start) as i64,
                        source: DataSource::SectionRelative,
                    })
                } else {
                    None
                }
            })
        };
        hit(&self.rodata_range, SYM_RODATA_START)
            .or_else(|| hit(&self.data_range, SYM_DATA_START))
            .or_else(|| hit(&self.bss_range, SYM_BSS_START))
            .or_else(|| hit(&self.data_rel_ro_range, SYM_DATA_REL_RO_START))
            .or_else(|| hit(&self.data_rel_ro_local_range, SYM_DATA_REL_RO_LOCAL_START))
    }

    pub fn in_got(&self, addr: u64) -> bool {
        self.got_range.as_ref().is_some_and(|r| r.contains(&addr))
    }

    pub fn in_plt(&self, addr: u64) -> bool {
        self.plt_range.as_ref().is_some_and(|r| r.contains(&addr))
    }

    pub fn classify_section(&self, addr: u64) -> &'static str {
        fn hit(r: &Option<Range<u64>>, a: u64) -> bool {
            r.as_ref().is_some_and(|x| x.contains(&a))
        }
        if self.text_range.contains(&addr) {
            ".text"
        } else if hit(&self.plt_range, addr) {
            ".plt"
        } else if hit(&self.got_range, addr) {
            ".got"
        } else if hit(&self.rodata_range, addr) {
            ".rodata"
        } else if hit(&self.data_rel_ro_local_range, addr) {
            ".data.rel.ro.local"
        } else if hit(&self.data_rel_ro_range, addr) {
            ".data.rel.ro"
        } else if hit(&self.data_range, addr) {
            ".data"
        } else if hit(&self.bss_range, addr) {
            ".bss"
        } else {
            "?"
        }
    }
}

/// Make every exported name unique by suffixing the collisions with their
/// address.
///
/// `static` definitions from different translation units routinely share a
/// name (`announce_se_counter`, `CSWTCH.5`, …). Once the split has taken them
/// apart, references between the resulting objects go through the symbol
/// table, where the name is all the linker has to go on — so an ambiguous
/// name silently binds to the wrong definition. Renaming here fixes both
/// sides at once: the emitter names each definition through this map, and
/// `resolve_data` hands out the same string to whoever references it.
fn disambiguate_names(
    functions: &mut BTreeMap<u64, FunctionRef>,
    variables: &mut BTreeMap<u64, VariableRef>,
) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in functions.values() {
        *counts.entry(f.export_name()).or_default() += 1;
    }
    for v in variables.values() {
        *counts.entry(v.export_name()).or_default() += 1;
    }
    let colliding: std::collections::HashSet<String> = counts
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name.to_string())
        .collect();
    if colliding.is_empty() {
        return;
    }

    let mut renamed = 0usize;
    for (addr, f) in functions.iter_mut() {
        if colliding.contains(f.export_name()) {
            // `.` cannot appear in a C identifier, so the suffix can never
            // collide with a source-level name.
            f.linkage_name = Some(format!("{}.{addr:x}", f.export_name()));
            renamed += 1;
        }
    }
    for (addr, v) in variables.iter_mut() {
        if colliding.contains(v.export_name()) {
            v.linkage_name = Some(format!("{}.{addr:x}", v.export_name()));
            renamed += 1;
        }
    }
    tracing::info!(
        "disambiguated {renamed} definitions sharing {} names",
        colliding.len()
    );
}

fn merge_ranges(a: Option<Range<u64>>, b: Option<Range<u64>>) -> Option<Range<u64>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.start.min(b.start)..a.end.max(b.end)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

// ---------------------------------------------------------------------------
// PLT / GOT reconstruction
// ---------------------------------------------------------------------------

fn build_plt_map(
    binary: &Binary<'_>,
    dyn_relocs: &[DynReloc],
    plt_range: Option<Range<u64>>,
) -> Result<HashMap<u64, String>> {
    let mut map = HashMap::new();
    let Some(plt_range) = plt_range else {
        return Ok(map);
    };

    // On ARM the PLT stub itself names the GOT slot it jumps through, so
    // decoding beats trusting the `.rel.plt` ordering. Fall back to index
    // order when a stub doesn't match the classic three-instruction shape.
    if binary.arch == Arch::Arm {
        let slot_names: HashMap<u64, String> = dyn_relocs
            .iter()
            .filter(|r| !r.sym_name.is_empty())
            .map(|r| (r.r_offset, r.sym_name.clone()))
            .collect();
        if let Some(section) = binary.elf.section_by_name(".plt") {
            if let Ok(data) = section.data() {
                let mut decoded = 0usize;
                let mut cursor = ARM_PLT_HEADER_SIZE;
                while cursor + ARM_PLT_ENTRY_SIZE <= section.size() {
                    let stub_addr = plt_range.start + cursor;
                    let off = cursor as usize;
                    if let Some(slot) = arm_plt_entry_got_slot(&data[off..off + 12], stub_addr) {
                        if let Some(name) = slot_names.get(&slot) {
                            map.insert(stub_addr, name.clone());
                            decoded += 1;
                        }
                    }
                    cursor += ARM_PLT_ENTRY_SIZE;
                }
                if decoded > 0 {
                    return Ok(map);
                }
                tracing::debug!("ARM PLT decode found no entries; using .rel.plt index order");
            }
        }
    }

    let (header, entry) = match binary.arch {
        Arch::Aarch64 => (AARCH64_PLT_HEADER_SIZE, AARCH64_PLT_ENTRY_SIZE),
        Arch::Arm => (ARM_PLT_HEADER_SIZE, ARM_PLT_ENTRY_SIZE),
    };
    let plt_relocs: Vec<&DynReloc> = dyn_relocs
        .iter()
        .filter(|r| r.from_plt_section && !r.sym_name.is_empty())
        .collect();
    for (i, entry_reloc) in plt_relocs.iter().enumerate() {
        let stub_addr = plt_range.start + header + (i as u64) * entry;
        map.insert(stub_addr, entry_reloc.sym_name.clone());
    }
    Ok(map)
}

/// Decode a classic 12-byte ARM PLT entry and return the `.got` slot it
/// dispatches through:
///
/// ```text
///   add ip, pc, #a       ; a = imm8 ror rot, PC bias +8
///   add ip, ip, #b
///   ldr pc, [ip, #c]!
/// ```
fn arm_plt_entry_got_slot(bytes: &[u8], stub_addr: u64) -> Option<u64> {
    let w = |i: usize| -> u32 { u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) };
    let (i0, i1, i2) = (w(0), w(4), w(8));

    // add ip, pc, #imm  ->  cond 0010 1000 1111 1100 rrrr iiiiiiii
    if i0 & 0x0fff_f000 != 0x028f_c000 {
        return None;
    }
    // add ip, ip, #imm  ->  cond 0010 1000 1100 1100 ...
    if i1 & 0x0fff_f000 != 0x028c_c000 {
        return None;
    }
    // ldr pc, [ip, #imm]! ->  cond 0101 1011 1100 1111 ...
    if i2 & 0x0fff_f000 != 0x05bc_f000 {
        return None;
    }
    let a = arm_expand_imm12(i0 & 0xfff);
    let b = arm_expand_imm12(i1 & 0xfff);
    let c = i2 & 0xfff;
    // PC bias for the first `add` is stub_addr + 8.
    Some(
        (stub_addr + 8)
            .wrapping_add(a as u64)
            .wrapping_add(b as u64)
            .wrapping_add(c as u64),
    )
}

/// ARM data-processing modified immediate: 8-bit value rotated right by 2×rot.
fn arm_expand_imm12(imm12: u32) -> u32 {
    let rot = (imm12 >> 8) & 0xf;
    let val = imm12 & 0xff;
    val.rotate_right(rot * 2)
}

fn build_got_maps(
    binary: &Binary<'_>,
    dyn_relocs: &[DynReloc],
) -> (HashMap<u64, String>, HashMap<u64, u64>) {
    let mut named = HashMap::new();
    let mut local = HashMap::new();
    for rel in dyn_relocs {
        if !rel.sym_name.is_empty() {
            named.insert(rel.r_offset, rel.sym_name.clone());
        } else if is_relative_reloc(binary.arch, rel.r_type) {
            // `*_RELATIVE` names no symbol; the module-local address it
            // installs is the addend (explicit on AArch64, read out of the
            // relocated field on ARM).
            local.insert(rel.r_offset, rel.r_addend as u64);
        }
    }
    (named, local)
}

fn is_relative_reloc(arch: Arch, r_type: u32) -> bool {
    match arch {
        Arch::Aarch64 => r_type == object::elf::R_AARCH64_RELATIVE.0,
        Arch::Arm => r_type == object::elf::R_ARM_RELATIVE.0,
    }
}

// ---------------------------------------------------------------------------
// Dynamic relocation reading (SHT_REL and SHT_RELA, ELF32 and ELF64)
// ---------------------------------------------------------------------------

/// A single entry from a dynamic relocation section, with the dynamic symbol's
/// name resolved (empty for relocations that target no specific symbol, e.g.
/// `R_AARCH64_RELATIVE` / `R_ARM_RELATIVE`).
#[derive(Debug, Clone)]
pub struct DynReloc {
    pub r_offset: u64,
    pub r_type: u32,
    pub r_sym: u32,
    /// Explicit addend for `SHT_RELA`; for `SHT_REL` this is the implicit
    /// addend read out of the relocated field.
    pub r_addend: i64,
    pub sym_name: String,
    /// True when the entry came from `.rel.plt` / `.rela.plt`.
    pub from_plt_section: bool,
}

/// Read all dynamic relocations from the binary's dynamic relocation sections.
pub fn read_all_dyn_relocs(binary: &Binary<'_>) -> Result<Vec<DynReloc>> {
    let mut out = Vec::new();
    for (name, is_rela) in [
        (".rel.dyn", false),
        (".rel.plt", false),
        (".rela.dyn", true),
        (".rela.plt", true),
    ] {
        out.extend(read_dyn_reloc_section(binary, name, is_rela)?);
    }
    Ok(out)
}

fn read_dyn_reloc_section(
    binary: &Binary<'_>,
    section_name: &str,
    is_rela: bool,
) -> Result<Vec<DynReloc>> {
    let Some(section) = binary.elf.section_by_name(section_name) else {
        return Ok(Vec::new());
    };
    let data = section.data()?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let class = binary.class;
    let entsize = if is_rela {
        class.rela_entsize()
    } else {
        class.rel_entsize()
    };
    let from_plt_section = section_name.ends_with(".plt");

    let dynsym = binary
        .elf
        .section_by_name(".dynsym")
        .and_then(|s| s.data().ok())
        .unwrap_or(&[]);
    let dynstr = binary
        .elf
        .section_by_name(".dynstr")
        .and_then(|s| s.data().ok())
        .unwrap_or(&[]);
    let sym_entsize = class.sym_entsize();

    let mut out = Vec::with_capacity(data.len() / entsize);
    for chunk in data.chunks_exact(entsize) {
        let (r_offset, r_info, explicit_addend) = match class {
            ElfClass::Elf32 => {
                let r_offset = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as u64;
                let r_info = u32::from_le_bytes(chunk[4..8].try_into().unwrap()) as u64;
                let addend = if is_rela {
                    i32::from_le_bytes(chunk[8..12].try_into().unwrap()) as i64
                } else {
                    0
                };
                (r_offset, r_info, addend)
            }
            ElfClass::Elf64 => {
                let r_offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                let r_info = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
                let addend = if is_rela {
                    i64::from_le_bytes(chunk[16..24].try_into().unwrap())
                } else {
                    0
                };
                (r_offset, r_info, addend)
            }
        };
        // ELF32 packs (sym << 8 | type); ELF64 packs (sym << 32 | type).
        let (r_sym, r_type) = match class {
            ElfClass::Elf32 => ((r_info >> 8) as u32, (r_info & 0xff) as u32),
            ElfClass::Elf64 => ((r_info >> 32) as u32, (r_info & 0xffff_ffff) as u32),
        };

        let r_addend = if is_rela {
            explicit_addend
        } else {
            // SHT_REL: the addend lives in the field being relocated.
            binary
                .read_word_at(r_offset)
                .map(sign_extend(class))
                .unwrap_or(0)
        };

        let sym_name = if r_sym == 0 {
            String::new()
        } else {
            let sym_off = (r_sym as usize) * sym_entsize;
            match dynsym.get(sym_off..sym_off + 4) {
                Some(bytes) => {
                    let st_name = u32::from_le_bytes(bytes.try_into().unwrap());
                    read_cstr(dynstr, st_name as usize).unwrap_or_default()
                }
                None => String::new(),
            }
        };

        out.push(DynReloc {
            r_offset,
            r_type,
            r_sym,
            r_addend,
            sym_name,
            from_plt_section,
        });
    }
    Ok(out)
}

fn sign_extend(class: ElfClass) -> impl Fn(u64) -> i64 {
    move |v| match class {
        ElfClass::Elf32 => v as u32 as i64,
        ElfClass::Elf64 => v as i64,
    }
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0).unwrap_or(0);
    std::str::from_utf8(&data[offset..offset + end])
        .ok()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classic 12-byte AAELF PLT entry, taken verbatim from a gold-linked
    /// Android `.so`:
    ///
    /// ```text
    ///   1576fc: add ip, pc, #0x100000
    ///   157700: add ip, ip, #168, 20
    ///   157704: ldr pc, [ip, #0x64c]!
    /// ```
    ///
    /// which dispatches through the `.got` slot at 0x2ffd50.
    #[test]
    fn arm_plt_entry_decodes_to_its_got_slot() {
        let mut bytes = Vec::new();
        for word in [0xe28f_c601u32, 0xe28c_caa8, 0xe5bc_f64c] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(arm_plt_entry_got_slot(&bytes, 0x1576fc), Some(0x2ffd50));
    }

    #[test]
    fn non_plt_bytes_decode_to_nothing() {
        let bytes = [0u8; 12];
        assert_eq!(arm_plt_entry_got_slot(&bytes, 0x1000), None);
    }

    #[test]
    fn modified_immediates_rotate_by_twice_the_field() {
        assert_eq!(arm_expand_imm12(0x001), 1);
        // 0x601: value 0x01 rotated right by 12 -> 0x0010_0000.
        assert_eq!(arm_expand_imm12(0x601), 0x0010_0000);
        // 0xaa8: value 0xa8 rotated right by 20 -> 0x000a_8000.
        assert_eq!(arm_expand_imm12(0xaa8), 0x000a_8000);
    }

    fn func(name: &str) -> FunctionRef {
        FunctionRef {
            cu_id: 0,
            name: name.to_string(),
            linkage_name: None,
            size: 4,
            external: false,
        }
    }

    fn var(name: &str) -> VariableRef {
        VariableRef {
            cu_id: 0,
            name: name.to_string(),
            linkage_name: None,
            external: false,
        }
    }

    /// `static` definitions from different translation units share names. Once
    /// split apart they are referenced across objects by name, so every
    /// colliding definition has to be renamed — including across the function
    /// and variable namespaces.
    #[test]
    fn colliding_names_are_renamed_by_address() {
        let mut functions = BTreeMap::from([(0x100, func("shared")), (0x200, func("unique"))]);
        let mut variables = BTreeMap::from([(0x300, var("shared")), (0x400, var("counter"))]);

        disambiguate_names(&mut functions, &mut variables);

        assert_eq!(functions[&0x100].export_name(), "shared.100");
        assert_eq!(variables[&0x300].export_name(), "shared.300");
        assert_eq!(functions[&0x200].export_name(), "unique");
        assert_eq!(variables[&0x400].export_name(), "counter");
    }

    #[test]
    fn unique_names_are_left_alone() {
        let mut functions = BTreeMap::from([(0x100, func("a")), (0x200, func("b"))]);
        let mut variables = BTreeMap::from([(0x300, var("c"))]);
        disambiguate_names(&mut functions, &mut variables);
        assert!(functions.values().all(|f| f.linkage_name.is_none()));
        assert!(variables.values().all(|v| v.linkage_name.is_none()));
    }

    #[test]
    fn renaming_is_driven_by_the_exported_name() {
        // Two functions whose `name` differs but whose linkage name collides.
        let mut a = func("one");
        a.linkage_name = Some("_Zmangled".into());
        let mut b = func("two");
        b.linkage_name = Some("_Zmangled".into());
        let mut functions = BTreeMap::from([(0x10, a), (0x20, b)]);
        let mut variables = BTreeMap::new();
        disambiguate_names(&mut functions, &mut variables);
        assert_eq!(functions[&0x10].export_name(), "_Zmangled.10");
        assert_eq!(functions[&0x20].export_name(), "_Zmangled.20");
    }
}
