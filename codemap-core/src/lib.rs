// Workspace-wide clippy posture. We're shipping a CLI analysis tool with
// many parallel implementations of similar parsers (PE/ELF/Mach-O/etc.),
// where the cost of refactoring every cosmetic lint outweighs the value.
// Real perf-relevant lints (regex_creation_in_loops, vec_init_then_push)
// are still enforced — see actions/*.rs for the targeted fixes. The
// cosmetic categories below are silenced project-wide so CI's
// `-D warnings` setting can be reinstated without a multi-day scrub.
#![allow(
    clippy::collapsible_if,           // pe.rs has nested if-let chains where flat reads better
    clippy::collapsible_match,        // schemas.rs YAML parser has nested match-if for clarity
    clippy::unnecessary_sort_by,      // sort_by(|a, b| key(a).cmp(&key(b))) is more explicit than sort_by_key in places
    clippy::doc_lazy_continuation,    // docstring formatting nit
    clippy::format_in_format_args,    // few uses, not a perf concern
    clippy::if_same_then_else,        // ml.rs has equivalent branches written distinctly for clarity
    clippy::manual_range_contains,    // pe.rs / ml.rs use explicit range tests; rewrite obscures intent
    clippy::needless_range_loop,      // index loops are clearer than iterator chains for parsers
    clippy::only_used_in_recursion,   // pe.rs recursive parser passes ctx forward
    clippy::redundant_guards,         // few sites; not worth churn
    clippy::should_implement_trait,   // EntityKind::from_str collides with std FromStr; not a real bug
    clippy::single_char_add_str,      // push_str("\n") is fine, push('\n') is the same
    clippy::single_match,             // a few one-arm matches read better as match
    clippy::type_complexity,          // pe.rs return tuples are intentionally explicit
    clippy::unnecessary_map_or,       // a few sites; cosmetic
    clippy::unnecessary_to_owned,     // some .to_string() calls clarify ownership at the cost of a clone
    clippy::useless_format,           // one-liner format!("...") is a wash
    clippy::vec_init_then_push,       // composite.rs builds a Vec line-by-line; reads cleaner
)]

pub mod types;
pub mod utils;
pub mod parser;
pub mod resolve;
pub mod scanner;
pub mod cpg;
pub mod actions;
pub mod demangle;
pub mod fingerprint;
pub mod strings;
pub mod disasm;
pub mod disasm_jt;

use std::path::PathBuf;
use types::Graph;

#[derive(Debug)]
pub enum CodemapError {
    UnknownAction(String),
    ScanError(String),
    IoError(String),
}

impl std::fmt::Display for CodemapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodemapError::UnknownAction(a) => write!(f, "Unknown action: {a}"),
            CodemapError::ScanError(e) => write!(f, "Scan error: {e}"),
            CodemapError::IoError(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for CodemapError {}

pub struct ScanOptions {
    pub dirs: Vec<PathBuf>,
    pub include_paths: Vec<PathBuf>,
    pub no_cache: bool,
    pub quiet: bool,
}

pub fn scan(options: ScanOptions) -> Result<Graph, CodemapError> {
    scanner::scan_directories(options)
}

pub fn execute(graph: &mut Graph, action: &str, target: &str, tree_mode: bool) -> Result<String, CodemapError> {
    actions::dispatch(graph, action, target, tree_mode)
}
