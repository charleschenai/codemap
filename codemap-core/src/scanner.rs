use crate::{ScanOptions, CodemapError};
use crate::types::Graph;
use std::collections::HashMap;

pub fn scan_directories(options: ScanOptions) -> Result<Graph, CodemapError> {
    let scan_dir = options.dirs.first()
        .ok_or_else(|| CodemapError::ScanError("No directories specified".into()))?
        .to_string_lossy().to_string();
    Ok(Graph { nodes: HashMap::new(), scan_dir, cpg: None })
}
