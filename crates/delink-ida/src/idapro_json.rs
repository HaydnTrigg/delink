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
