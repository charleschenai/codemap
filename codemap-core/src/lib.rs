pub mod types;
pub mod parser;
pub mod resolve;
pub mod scanner;
pub mod cpg;
pub mod actions;

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

pub struct ScanOptions {
    pub dirs: Vec<PathBuf>,
    pub include_paths: Vec<PathBuf>,
    pub no_cache: bool,
}

pub fn scan(options: ScanOptions) -> Result<Graph, CodemapError> {
    scanner::scan_directories(options)
}

pub fn execute(graph: &mut Graph, action: &str, target: &str, tree_mode: bool) -> Result<String, CodemapError> {
    actions::dispatch(graph, action, target, tree_mode)
}
