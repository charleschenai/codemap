use std::path::PathBuf;

pub struct ResolveContext {
    pub scan_dir: String,
    pub include_paths: Vec<PathBuf>,
    pub tsconfig_paths: std::collections::HashMap<String, String>,
}

impl ResolveContext {
    pub fn new(scan_dir: &str, include_paths: &[PathBuf]) -> Self {
        ResolveContext {
            scan_dir: scan_dir.to_string(),
            include_paths: include_paths.to_vec(),
            tsconfig_paths: std::collections::HashMap::new(),
        }
    }
}

pub fn resolve_import(
    _specifier: &str,
    _from_file: &str,
    _ctx: &mut ResolveContext,
) -> Option<String> {
    None
}
