//! DWARF-based compilation unit indexing for Mach-O binaries.
//!
//! Mirrors the logic in `delink-core::cu` but adapted to work with a generic
//! `gimli::Dwarf` handle rather than an ELF-specific `Binary<'a>`.

use anyhow::{anyhow, Result};
use gimli::{AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian, Unit};
use std::ops::Range;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone)]
pub struct MachoFunction {
    /// Demangled or source name.
    pub name: String,
    /// Mangled / linkage name (preferred as the symbol name in .o files).
    pub linkage_name: Option<String>,
    pub addr: u64,
    pub size: u64,
    pub external: bool,
}

impl MachoFunction {
    pub fn symbol_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct MachoVariable {
    pub name: String,
    pub linkage_name: Option<String>,
    pub addr: u64,
    pub external: bool,
}

impl MachoVariable {
    pub fn symbol_name(&self) -> &str {
        self.linkage_name.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct MachoCompilationUnit {
    pub id: usize,
    pub name: String,
    pub comp_dir: Option<String>,
    /// Path to the original object file, as recorded in STABS N_OSO or DWARF DW_AT_comp_dir.
    pub oso_path: Option<String>,
    pub ranges: Vec<Range<u64>>,
    pub functions: Vec<MachoFunction>,
    pub variables: Vec<MachoVariable>,
}

impl MachoCompilationUnit {
    pub fn text_size(&self) -> u64 {
        self.functions.iter().map(|f| f.size).sum()
    }
}

pub struct MachoCuIndex {
    pub units: Vec<MachoCompilationUnit>,
}

pub fn build_cu_index(dwarf: &Dwarf<Slice<'_>>) -> Result<MachoCuIndex> {
    let mut units = Vec::new();
    let mut cu_id = 0usize;
    let mut headers = dwarf.units();

    while let Some(header) = headers.next().map_err(|e| anyhow!("DWARF units: {e}"))? {
        let unit = dwarf
            .unit(header)
            .map_err(|e| anyhow!("DWARF unit: {e}"))?;
        if let Some(cu) = build_unit(dwarf, &unit, cu_id)? {
            units.push(cu);
            cu_id += 1;
        }
    }

    Ok(MachoCuIndex { units })
}

fn build_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    id: usize,
) -> Result<Option<MachoCompilationUnit>> {
    let mut entries = unit.entries();
    let Some(root) = entries
        .next_dfs()
        .map_err(|e| anyhow!("DIE tree: {e}"))?
    else {
        return Ok(None);
    };
    if root.tag() != gimli::DW_TAG_compile_unit {
        return Ok(None);
    }

    let name =
        attr_string(dwarf, unit, root, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
    let comp_dir = attr_string(dwarf, unit, root, gimli::DW_AT_comp_dir)?;

    let mut ranges = Vec::new();
    let mut range_iter = dwarf
        .unit_ranges(unit)
        .map_err(|e| anyhow!("unit ranges: {e}"))?;
    while let Some(r) = range_iter
        .next()
        .map_err(|e| anyhow!("range entry: {e}"))?
    {
        if r.begin < r.end {
            ranges.push(r.begin..r.end);
        }
    }

    let mut functions = Vec::new();
    let mut variables = Vec::new();

    let mut entries = unit.entries();
    while let Some(entry) = entries
        .next_dfs()
        .map_err(|e| anyhow!("DIE entry: {e}"))?
    {
        match entry.tag() {
            gimli::DW_TAG_subprogram => {
                if let Some(f) = extract_function(dwarf, unit, entry)? {
                    functions.push(f);
                }
            }
            gimli::DW_TAG_variable => {
                if let Some(v) = extract_variable(dwarf, unit, entry)? {
                    variables.push(v);
                }
            }
            _ => {}
        }
    }

    if functions.is_empty() && variables.is_empty() && ranges.is_empty() {
        return Ok(None);
    }

    Ok(Some(MachoCompilationUnit {
        id,
        name,
        comp_dir,
        oso_path: None,
        ranges,
        functions,
        variables,
    }))
}

fn extract_function(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
) -> Result<Option<MachoFunction>> {
    // Skip abstract/inline-only entries.
    if entry.attr_value(gimli::DW_AT_inline).is_some()
        && entry.attr_value(gimli::DW_AT_low_pc).is_none()
    {
        return Ok(None);
    }

    let Some(addr) = attr_address(dwarf, unit, entry, gimli::DW_AT_low_pc)? else {
        return Ok(None);
    };
    let size = match entry.attr_value(gimli::DW_AT_high_pc) {
        Some(AttributeValue::Addr(end)) => end.saturating_sub(addr),
        Some(AttributeValue::Udata(s)) => s,
        Some(AttributeValue::Data1(s)) => s as u64,
        Some(AttributeValue::Data2(s)) => s as u64,
        Some(AttributeValue::Data4(s)) => s as u64,
        Some(AttributeValue::Data8(s)) => s,
        _ => 0,
    };

    let (name, linkage_name, external) = resolve_names(dwarf, unit, entry)?;
    let name = name.unwrap_or_else(|| "<anon>".into());

    Ok(Some(MachoFunction {
        name,
        linkage_name,
        addr,
        size,
        external,
    }))
}

fn extract_variable(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
) -> Result<Option<MachoVariable>> {
    let Some(addr) = variable_address(dwarf, unit, entry)? else {
        return Ok(None);
    };
    let name =
        attr_string(dwarf, unit, entry, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
    let linkage_name = attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)?
        .or(attr_string(dwarf, unit, entry, gimli::DW_AT_MIPS_linkage_name)?);
    let external = matches!(
        entry.attr_value(gimli::DW_AT_external),
        Some(AttributeValue::Flag(true))
    );
    Ok(Some(MachoVariable {
        name,
        linkage_name,
        addr,
        external,
    }))
}

fn variable_address(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
) -> Result<Option<u64>> {
    let Some(attr) = entry.attr_value(gimli::DW_AT_location) else {
        return Ok(None);
    };
    let expr = match attr {
        AttributeValue::Exprloc(e) => e,
        _ => return Ok(None),
    };
    let mut ops = expr.operations(unit.encoding());
    match ops.next().map_err(|e| anyhow!("DWARF op: {e}"))? {
        Some(gimli::Operation::Address { address }) => Ok(Some(address)),
        Some(gimli::Operation::AddressIndex { index }) => {
            Ok(Some(dwarf.address(unit, index).map_err(|e| anyhow!("{e}"))?))
        }
        _ => Ok(None),
    }
}

/// Walk DW_AT_specification / DW_AT_abstract_origin to find name + linkage_name.
fn resolve_names(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
) -> Result<(Option<String>, Option<String>, bool)> {
    let mut name = attr_string(dwarf, unit, entry, gimli::DW_AT_name)?;
    let mut linkage = attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)?.or(
        attr_string(dwarf, unit, entry, gimli::DW_AT_MIPS_linkage_name)?,
    );
    let mut external = matches!(
        entry.attr_value(gimli::DW_AT_external),
        Some(AttributeValue::Flag(true))
    );

    let mut ref_off = match entry.attr_value(gimli::DW_AT_specification) {
        Some(AttributeValue::UnitRef(o)) => Some(o),
        _ => match entry.attr_value(gimli::DW_AT_abstract_origin) {
            Some(AttributeValue::UnitRef(o)) => Some(o),
            _ => None,
        },
    };

    let mut hops = 0usize;
    while let Some(off) = ref_off {
        if hops > 4 {
            break;
        }
        hops += 1;
        let Ok(ref_entry) = unit.entry(off) else {
            break;
        };
        if name.is_none() {
            name = attr_string(dwarf, unit, &ref_entry, gimli::DW_AT_name)?;
        }
        if linkage.is_none() {
            linkage = attr_string(dwarf, unit, &ref_entry, gimli::DW_AT_linkage_name)?.or(
                attr_string(dwarf, unit, &ref_entry, gimli::DW_AT_MIPS_linkage_name)?,
            );
        }
        if !external {
            external = matches!(
                ref_entry.attr_value(gimli::DW_AT_external),
                Some(AttributeValue::Flag(true))
            );
        }
        ref_off = match ref_entry.attr_value(gimli::DW_AT_specification) {
            Some(AttributeValue::UnitRef(o)) => Some(o),
            _ => match ref_entry.attr_value(gimli::DW_AT_abstract_origin) {
                Some(AttributeValue::UnitRef(o)) => Some(o),
                _ => None,
            },
        };
    }

    Ok((name, linkage, external))
}

fn attr_string(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
    name: gimli::DwAt,
) -> Result<Option<String>> {
    let Some(attr) = entry.attr(name) else {
        return Ok(None);
    };
    let val = attr.value();
    let s = dwarf
        .attr_string(unit, val)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(Some(s.to_string_lossy().into_owned()))
}

fn attr_address(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<Slice<'_>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    match entry.attr_value(name) {
        Some(AttributeValue::Addr(a)) => Ok(Some(a)),
        Some(AttributeValue::DebugAddrIndex(i)) => {
            Ok(Some(dwarf.address(unit, i).map_err(|e| anyhow!("{e}"))?))
        }
        _ => Ok(None),
    }
}
