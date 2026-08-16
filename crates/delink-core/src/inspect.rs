//! Human-readable summary of a loaded `.so`.

use crate::binary::Binary;
use crate::cu::CuIndex;
use crate::error::Result;
use crate::symtab::SymtabIndex;
use delink_arch::Arch;
use object::{Object as _, ObjectSection as _};
use std::fmt::Write as _;

pub struct InspectReport {
    pub arch: String,
    pub class: String,
    /// Recovered `STT_FILE` translation units, and how many carry a usable
    /// `.text` anchor.
    pub symtab_files: usize,
    pub symtab_anchored: usize,
    pub symtab_functions: usize,
    pub sections: Vec<SectionRow>,
    pub dyn_relocs: Vec<(String, usize)>,
    pub cu_rows: Vec<CuRow>,
    pub total_functions: usize,
    pub total_variables: usize,
    pub has_dwarf: bool,
}

pub struct SectionRow {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
}

pub struct CuRow {
    pub name: String,
    pub comp_dir: Option<String>,
    pub ranges: usize,
    pub functions: usize,
    pub variables: usize,
    pub coverage: u64,
}

pub fn inspect(binary: &Binary<'_>) -> Result<InspectReport> {
    let arch = binary.arch.to_string();
    let class = binary.class.to_string();
    let has_dwarf = binary.has_dwarf();

    let mut sections = Vec::new();
    for section in binary.elf.sections() {
        let name = section.name().unwrap_or("<?>").to_string();
        if name.is_empty() {
            continue;
        }
        sections.push(SectionRow {
            name,
            addr: section.address(),
            size: section.size(),
            kind: format!("{:?}", section.kind()),
        });
    }

    let dyn_relocs = count_dyn_relocs(binary);

    let (cu_rows, total_functions, total_variables) = if has_dwarf {
        let idx = CuIndex::build(binary)?;
        let rows = idx
            .units
            .iter()
            .map(|u| CuRow {
                name: u.name.clone(),
                comp_dir: u.comp_dir.clone(),
                ranges: u.ranges.len(),
                functions: u.functions.len(),
                variables: u.variables.len(),
                coverage: u.ranges.iter().map(|r| r.end - r.start).sum(),
            })
            .collect();
        (rows, idx.total_functions(), idx.total_variables())
    } else {
        (Vec::new(), 0, 0)
    };

    let symtab = SymtabIndex::build(binary)?;
    let symtab_files = symtab.groups.len();
    let symtab_anchored = symtab.groups.iter().filter(|g| g.anchor.is_some()).count();
    let symtab_functions = symtab.text_functions().len();

    Ok(InspectReport {
        arch,
        class,
        symtab_files,
        symtab_anchored,
        symtab_functions,
        sections,
        dyn_relocs,
        cu_rows,
        total_functions,
        total_variables,
        has_dwarf,
    })
}

fn count_dyn_relocs(binary: &Binary<'_>) -> Vec<(String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    let Ok(relocs) = crate::symbols::read_all_dyn_relocs(binary) else {
        return Vec::new();
    };
    for rel in &relocs {
        *counts.entry(rel.r_type).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(k, v)| (reloc_name(binary.arch, k), v))
        .collect()
}

/// Human-readable name for a relocation type.
pub fn reloc_name(arch: Arch, t: u32) -> String {
    // `object` models `r_type` as a per-format newtype; we carry the raw value
    // around and wrap it only to match against the constants.
    let t = object::elf::RelocationType(t);
    match arch {
        Arch::Aarch64 => aarch64_reloc_name(t),
        Arch::Arm => arm_reloc_name(t),
    }
}

fn arm_reloc_name(t: object::elf::RelocationType) -> String {
    use object::elf::*;
    let name = match t {
        R_ARM_NONE => "R_ARM_NONE",
        R_ARM_ABS32 => "R_ARM_ABS32",
        R_ARM_REL32 => "R_ARM_REL32",
        R_ARM_THM_PC22 => "R_ARM_THM_CALL",
        R_ARM_GLOB_DAT => "R_ARM_GLOB_DAT",
        R_ARM_JUMP_SLOT => "R_ARM_JUMP_SLOT",
        R_ARM_RELATIVE => "R_ARM_RELATIVE",
        R_ARM_GOTOFF => "R_ARM_GOTOFF32",
        R_ARM_GOTPC => "R_ARM_BASE_PREL",
        R_ARM_GOT32 => "R_ARM_GOT_BREL",
        R_ARM_PLT32 => "R_ARM_PLT32",
        R_ARM_CALL => "R_ARM_CALL",
        R_ARM_JUMP24 => "R_ARM_JUMP24",
        R_ARM_THM_JUMP24 => "R_ARM_THM_JUMP24",
        R_ARM_TARGET1 => "R_ARM_TARGET1",
        R_ARM_PREL31 => "R_ARM_PREL31",
        R_ARM_MOVW_ABS_NC => "R_ARM_MOVW_ABS_NC",
        R_ARM_MOVT_ABS => "R_ARM_MOVT_ABS",
        R_ARM_GOT_PREL => "R_ARM_GOT_PREL",
        R_ARM_COPY => "R_ARM_COPY",
        R_ARM_IRELATIVE => "R_ARM_IRELATIVE",
        R_ARM_TLS_DTPMOD32 => "R_ARM_TLS_DTPMOD32",
        R_ARM_TLS_DTPOFF32 => "R_ARM_TLS_DTPOFF32",
        R_ARM_TLS_TPOFF32 => "R_ARM_TLS_TPOFF32",
        _ => return format!("R_ARM_{t}"),
    };
    name.to_string()
}

fn aarch64_reloc_name(t: object::elf::RelocationType) -> String {
    use object::elf::*;
    let name = match t {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_ABS32 => "R_AARCH64_ABS32",
        R_AARCH64_ABS16 => "R_AARCH64_ABS16",
        R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        R_AARCH64_PREL16 => "R_AARCH64_PREL16",
        R_AARCH64_ADR_PREL_PG_HI21 => "R_AARCH64_ADR_PREL_PG_HI21",
        R_AARCH64_ADD_ABS_LO12_NC => "R_AARCH64_ADD_ABS_LO12_NC",
        R_AARCH64_CALL26 => "R_AARCH64_CALL26",
        R_AARCH64_JUMP26 => "R_AARCH64_JUMP26",
        R_AARCH64_ADR_GOT_PAGE => "R_AARCH64_ADR_GOT_PAGE",
        R_AARCH64_LD64_GOT_LO12_NC => "R_AARCH64_LD64_GOT_LO12_NC",
        R_AARCH64_COPY => "R_AARCH64_COPY",
        R_AARCH64_GLOB_DAT => "R_AARCH64_GLOB_DAT",
        R_AARCH64_JUMP_SLOT => "R_AARCH64_JUMP_SLOT",
        R_AARCH64_RELATIVE => "R_AARCH64_RELATIVE",
        R_AARCH64_TLS_DTPMOD => "R_AARCH64_TLS_DTPMOD",
        R_AARCH64_TLS_DTPREL => "R_AARCH64_TLS_DTPREL",
        R_AARCH64_TLS_TPREL => "R_AARCH64_TLS_TPREL",
        R_AARCH64_TLSDESC => "R_AARCH64_TLSDESC",
        R_AARCH64_IRELATIVE => "R_AARCH64_IRELATIVE",
        _ => return format!("R_AARCH64_{t}"),
    };
    name.to_string()
}

pub fn format_text(r: &InspectReport) -> String {
    let mut out = String::new();
    writeln!(out, "arch: {} ({})", r.arch, r.class).unwrap();
    writeln!(
        out,
        "dwarf: {}",
        if r.has_dwarf { "present" } else { "MISSING" }
    )
    .unwrap();
    writeln!(
        out,
        "symtab: {} STT_FILE units ({} with a .text anchor), {} sized functions in .text",
        r.symtab_files, r.symtab_anchored, r.symtab_functions
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "SECTIONS").unwrap();
    writeln!(out, "  {:<28} {:>16} {:>10}  kind", "name", "addr", "size").unwrap();
    for s in &r.sections {
        writeln!(
            out,
            "  {:<28} {:016x} {:>10}  {}",
            truncate(&s.name, 28),
            s.addr,
            s.size,
            s.kind
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "DYNAMIC RELOCATIONS").unwrap();
    if r.dyn_relocs.is_empty() {
        writeln!(out, "  (none)").unwrap();
    } else {
        for (name, count) in &r.dyn_relocs {
            writeln!(out, "  {:<40} {:>8}", name, count).unwrap();
        }
    }
    writeln!(out).unwrap();

    writeln!(
        out,
        "COMPILATION UNITS: {} ({} functions, {} variables)",
        r.cu_rows.len(),
        r.total_functions,
        r.total_variables
    )
    .unwrap();
    writeln!(
        out,
        "  {:<50} {:>6} {:>6} {:>6} {:>10}",
        "name", "ranges", "funcs", "vars", "bytes"
    )
    .unwrap();
    for cu in &r.cu_rows {
        writeln!(
            out,
            "  {:<50} {:>6} {:>6} {:>6} {:>10}",
            truncate(&cu.name, 50),
            cu.ranges,
            cu.functions,
            cu.variables,
            cu.coverage
        )
        .unwrap();
    }

    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len() - (max - 1)..])
    }
}
