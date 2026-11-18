//! User-editable grouping/config: maps each output object filename to a map of
//! symbol name → definition.
//!
//! ```json
//! {
//!   "Alchemy.dll.obj": {
//!     "??0_ReaderWriterLock@details@Concurrency@@QAE@XZ": {
//!       "address": 268441600,
//!       "size": 42,
//!       "scope": "global"
//!     }
//!   }
//! }
//! ```
//!
//! Each symbol entry carries its IDA virtual address, byte size (of the function
//! or data item), and linkage (`global` = external, `static` = internal), so the
//! config is self-describing and editable without re-reading the model.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IdaModel;

/// Output-filename → (symbol name → definition).
pub type IdaproJson = BTreeMap<String, BTreeMap<String, SymbolDef>>;

/// Linkage / visibility of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// External linkage (exported / globally visible).
    Global,
    /// Internal linkage (file-local).
    Static,
}

impl Scope {
    pub fn from_public(public: bool) -> Self {
        if public {
            Scope::Global
        } else {
            Scope::Static
        }
    }
    pub fn is_global(self) -> bool {
        matches!(self, Scope::Global)
    }
}

/// A single symbol's definition within an output object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolDef {
    /// Virtual address (from IDA).
    pub address: u64,
    /// Size in bytes (function or data item).
    pub size: u64,
    /// Linkage: global (external) or static (internal).
    pub scope: Scope,
    /// Output section. Absent (or the text section's name) means code: the bytes
    /// are disassembled for relocations. Any other name makes a data symbol whose
    /// bytes are copied with absolute relocations from the fixup table; `.bss`
    /// (or `.tbss`) reserves `size` bytes of uninitialized data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Alignment of a data symbol in its section (default 1, so readers that infer
    /// sizes from the next symbol see exact sizes; ignored for code).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub align: Option<u64>,
    /// Hex bytes to emit instead of the binary's bytes at `address`, for data the
    /// binary only holds in another form (a linker-built table, say). The symbol
    /// then gets only the relocations listed in `relocations`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// Relocations for `bytes` (absolute, pointer-sized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocations: Option<Vec<DataReloc>>,
    /// Emit the data without a symbol (the key only names the entry), for
    /// sections the compiler fills without naming anything.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub anonymous: bool,
}

impl SymbolDef {
    /// Whether this entry is code (disassembled into the text section).
    pub fn is_code(&self, text_name: &str) -> bool {
        self.section.as_deref().is_none_or(|s| s == text_name)
    }
}

/// An absolute relocation inside an explicit-`bytes` data symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataReloc {
    /// Offset within the symbol's bytes.
    pub offset: u64,
    /// Target symbol name.
    pub symbol: String,
    /// Added to the target's address.
    #[serde(default)]
    pub addend: i64,
}

/// Build a default grouping: one function per output file (extension `ext`,
/// e.g. `"obj"` for COFF or `"o"` for ELF).
pub fn generate(model: &IdaModel, ext: &str) -> IdaproJson {
    let mut json: IdaproJson = BTreeMap::new();
    for f in &model.functions {
        if f.size() == 0 {
            continue;
        }
        let file = format!("{}.{ext}", sanitize_filename(&f.name));
        json.entry(file).or_default().insert(
            f.name.clone(),
            SymbolDef {
                address: f.start,
                size: f.size(),
                scope: Scope::from_public(f.public),
                section: None,
                align: None,
                bytes: None,
                relocations: None,
                anonymous: false,
            },
        );
    }
    json
}

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = s.trim_start_matches(['.', '_']);
    let truncated = &trimmed[..trimmed.len().min(200)];
    if truncated.is_empty() {
        "unknown".to_string()
    } else {
        truncated.to_string()
    }
}
