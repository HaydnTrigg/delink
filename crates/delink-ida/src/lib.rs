//! delink IDA importer.
//!
//! Consumes the JSON produced by [`ida_export.py`](../ida_export.py) (run inside
//! IDA 9.x) and splits the analysed binary into relocatable objects.
//!
//! The JSON carries the architecture, every segment's bytes, every function
//! (boundaries + flags), the full address → name map, and IDA's fixup table.
//! For x86 / x86-64 targets the emitter disassembles each function with
//! iced-x86 (via [`delink_x86`] / [`delink_x86_64`]) to recover instruction
//! relocations — rel32 calls/jumps and RIP-relative references — resolving each
//! target address through the name map to build the correct label.  Absolute
//! pointers (in code or data) come from IDA's fixup table.
//!
//! Like the Mach-O `symtab.json` flow, the split is driven by an editable
//! `idapro.json` mapping each output object filename to a list of function
//! names; see [`idapro_json`].

pub mod emit;
pub mod idapro_json;
pub mod resolver;

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

pub use delink_pe::{BaseRelocKind, PeImage};
pub use resolver::IdaSymbols;

/// Target architecture, as far as the importer cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdaArch {
    X86,
    X86_64,
    /// Anything else — emitted as raw bytes with fixup-table relocations only
    /// (no iced-x86 instruction recovery).
    Other,
}

impl IdaArch {
    fn from_meta(arch: &str) -> Self {
        match arch {
            "x86" => IdaArch::X86,
            "x86_64" => IdaArch::X86_64,
            _ => IdaArch::Other,
        }
    }
}

/// Segment class, derived from IDA's segment type + permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegClass {
    Code,
    Data,
    Const,
    Bss,
    Xtrn,
    Other,
}

impl SegClass {
    fn from_str(s: &str) -> Self {
        match s {
            "CODE" => SegClass::Code,
            "DATA" => SegClass::Data,
            "CONST" => SegClass::Const,
            "BSS" => SegClass::Bss,
            "XTRN" => SegClass::Xtrn,
            _ => SegClass::Other,
        }
    }
}

/// A segment's metadata.  The bytes live in the original input binary, not in
/// the export — read them through [`PeImage`] keyed by RVA.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub class: SegClass,
}

impl Section {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn contains(&self, va: u64) -> bool {
        va >= self.start && va < self.end
    }
}

/// A function discovered by IDA.
#[derive(Debug, Clone)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub thunk: bool,
    pub lib: bool,
    pub is_static: bool,
    pub public: bool,
}

impl Function {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// A named address.
#[derive(Debug, Clone)]
pub struct Name {
    pub addr: u64,
    pub name: String,
    pub public: bool,
    pub weak: bool,
    pub is_func: bool,
}

/// One entry of IDA's fixup table (an absolute address relocation).
#[derive(Debug, Clone)]
pub struct Reloc {
    pub addr: u64,
    pub kind: String,
    /// Width in bytes (4 or 8).
    pub size: u32,
    /// The address the relocation points at.
    pub target: u64,
}

/// The fully decoded model.
pub struct IdaModel {
    pub arch: IdaArch,
    pub procname: String,
    pub bits: u32,
    pub little_endian: bool,
    pub image_base: u64,
    pub filetype: String,
    pub input_file: String,
    pub sections: Vec<Section>,
    pub functions: Vec<Function>,
    pub names: Vec<Name>,
    pub relocations: Vec<Reloc>,
}

impl IdaModel {
    pub fn section_for(&self, va: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(va))
    }
}

// ---------------------------------------------------------------------------
// Raw (serde) schema — kept private; `load` converts to `IdaModel`.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RawModel {
    #[allow(dead_code)]
    delink_ida_version: u32,
    meta: RawMeta,
    segments: Vec<RawSegment>,
    functions: Vec<RawFunction>,
    names: Vec<RawName>,
    relocations: Vec<RawReloc>,
}

#[derive(Deserialize)]
struct RawMeta {
    arch: String,
    procname: String,
    bits: u32,
    endian: String,
    image_base: u64,
    #[allow(dead_code)]
    min_ea: u64,
    #[allow(dead_code)]
    max_ea: u64,
    filetype: String,
    input_file: String,
}

#[derive(Deserialize)]
struct RawSegment {
    name: String,
    start: u64,
    end: u64,
    perm_r: bool,
    perm_w: bool,
    perm_x: bool,
    class: String,
    #[allow(dead_code)]
    #[serde(default)]
    bitness: u32,
}

#[derive(Deserialize)]
struct RawFunction {
    start: u64,
    end: u64,
    name: String,
    thunk: bool,
    lib: bool,
    #[serde(rename = "static")]
    is_static: bool,
    public: bool,
    #[allow(dead_code)]
    thunk_target: Option<u64>,
}

#[derive(Deserialize)]
struct RawName {
    addr: u64,
    name: String,
    public: bool,
    weak: bool,
    is_func: bool,
}

#[derive(Deserialize)]
struct RawReloc {
    addr: u64,
    #[serde(rename = "type")]
    kind: String,
    size: u32,
    target: u64,
}

/// Load and decode an exported `*.delink.json` file.
pub fn load(path: &Path) -> Result<IdaModel> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let raw: RawModel =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;

    let sections = raw
        .segments
        .into_iter()
        .map(|s| Section {
            name: s.name,
            start: s.start,
            end: s.end,
            read: s.perm_r,
            write: s.perm_w,
            exec: s.perm_x,
            class: SegClass::from_str(&s.class),
        })
        .collect();

    let functions = raw
        .functions
        .into_iter()
        .map(|f| Function {
            start: f.start,
            end: f.end,
            name: f.name,
            thunk: f.thunk,
            lib: f.lib,
            is_static: f.is_static,
            public: f.public,
        })
        .collect();

    let names = raw
        .names
        .into_iter()
        .map(|n| Name {
            addr: n.addr,
            name: n.name,
            public: n.public,
            weak: n.weak,
            is_func: n.is_func,
        })
        .collect();

    let relocations = raw
        .relocations
        .into_iter()
        .map(|r| Reloc {
            addr: r.addr,
            kind: r.kind,
            size: r.size,
            target: r.target,
        })
        .collect();

    Ok(IdaModel {
        arch: IdaArch::from_meta(&raw.meta.arch),
        procname: raw.meta.procname,
        bits: raw.meta.bits,
        little_endian: raw.meta.endian != "big",
        image_base: raw.meta.image_base,
        filetype: raw.meta.filetype,
        input_file: raw.meta.input_file,
        sections,
        functions,
        names,
        relocations,
    })
}

/// Load the original input binary (PE) whose bytes the split will carve up.
pub fn load_binary(path: &Path) -> Result<PeImage> {
    let data = std::fs::read(path).with_context(|| format!("read binary {}", path.display()))?;
    delink_pe::load_pe_image(&data).with_context(|| format!("parse PE {}", path.display()))
}

/// The set of absolute-pointer relocations to apply, in IDA-VA space.
///
/// Combines two sources (deduplicated by address):
///   * the relocations IDA exported (its fixup table — the only source for EXEs,
///     whose images carry no `.reloc`), and
///   * the PE base-relocation table from the original binary (present in DLLs),
///     whose targets are read from the binary's own bytes.
///
/// Both are translated into IDA's address space via the image-base delta so they
/// resolve against the same name map.
pub fn combined_relocations(model: &IdaModel, pe: &PeImage) -> Vec<Reloc> {
    use std::collections::BTreeMap;

    let mut by_addr: BTreeMap<u64, Reloc> = BTreeMap::new();

    // 1) IDA fixups — already in IDA VA with resolved targets.
    for r in &model.relocations {
        by_addr.insert(r.addr, r.clone());
    }

    // 2) PE `.reloc` entries — translate RVA → IDA VA, read the target from the binary.
    let ida_base = model.image_base;
    let pe_base = pe.image_base;
    for br in &pe.base_relocations {
        let size: u32 = match br.kind {
            BaseRelocKind::Dir64 => 8,
            BaseRelocKind::HighLow => 4,
            BaseRelocKind::Other(_) => continue,
        };
        let rva = br.va.wrapping_sub(pe_base);
        let addr_ida = ida_base.wrapping_add(rva);
        if by_addr.contains_key(&addr_ida) {
            continue; // already covered by an IDA fixup
        }
        let Some(bytes) = pe.data_at_rva(rva, size as usize) else {
            continue;
        };
        let stored = match size {
            8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
        };
        // The stored value is an absolute VA at the binary's base; rebase to IDA.
        let target_ida = ida_base.wrapping_add(stored.wrapping_sub(pe_base));
        by_addr.insert(
            addr_ida,
            Reloc {
                addr: addr_ida,
                kind: "RELOC".to_string(),
                size,
                target: target_ida,
            },
        );
    }

    by_addr.into_values().collect()
}
