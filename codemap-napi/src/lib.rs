use napi_derive::napi;
use codemap_core::ScanOptions;
use std::path::PathBuf;
use std::sync::Mutex;
use std::collections::HashMap;

// Store graphs keyed by scan_dir so multiple scans can coexist
static GRAPHS: std::sync::LazyLock<Mutex<HashMap<String, codemap_core::types::Graph>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

#[napi]
pub fn scan(dirs: Vec<String>, include_paths: Option<Vec<String>>, no_cache: Option<bool>) -> napi::Result<u32> {
    let options = ScanOptions {
        dirs: dirs.iter().map(PathBuf::from).collect(),
        include_paths: include_paths.unwrap_or_default().iter().map(PathBuf::from).collect(),
        no_cache: no_cache.unwrap_or(false),
        quiet: true,
    };
    let graph = codemap_core::scan(options)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let files = graph.nodes.len() as u32;
    let key = graph.scan_dir.clone();
    let mut graphs = GRAPHS.lock().unwrap_or_else(|p| p.into_inner());
    graphs.insert(key, graph);
    Ok(files)
}

#[napi]
pub fn execute(scan_dir: String, action: String, target: String, tree_mode: Option<bool>) -> napi::Result<String> {
    let mut graphs = GRAPHS.lock().unwrap_or_else(|p| p.into_inner());
    let graph = graphs.get_mut(&scan_dir)
        .ok_or_else(|| napi::Error::from_reason(format!("No graph loaded for {scan_dir}. Call scan() first.")))?;
    codemap_core::execute(graph, &action, &target, tree_mode.unwrap_or(false))
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[napi]
pub fn clear(scan_dir: Option<String>) {
    let mut graphs = GRAPHS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(dir) = scan_dir {
        graphs.remove(&dir);
    } else {
        graphs.clear();
    }
}
