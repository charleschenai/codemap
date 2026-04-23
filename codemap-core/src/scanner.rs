use crate::parser;
use crate::resolve::{self, ResolveContext};
use crate::types::{BridgeKind, Graph, GraphNode};
use crate::{CodemapError, ScanOptions};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ── Constants ───────────────────────────────────────────────────────

const CACHE_VERSION: u32 = 7;
const MAX_DEPTH: usize = 50;

/// Directories to skip during walk.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "dist", "build", ".codemap", "target"];

/// Supported file extensions (with leading dot).
const SUPPORTED_EXTS: &[&str] = &[
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".rs", ".go", ".java", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    ".cu", ".cuh",
    ".yaml", ".yml", ".cmake",
];

// ── Cache Types ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    mtime: f64,
    imports: Vec<String>,
    urls: Vec<String>,
    exports: Vec<String>,
    lines: usize,
    functions: Vec<crate::types::FunctionInfo>,
    data_flow: Option<crate::types::FileDataFlow>,
    bridges: Vec<crate::types::BridgeInfo>,
}

#[derive(Serialize, Deserialize)]
struct CacheData {
    version: u32,
    files: HashMap<String, CacheEntry>,
}

// ── Cache I/O ───────────────────────────────────────────────────────

fn cache_path(dir: &str) -> PathBuf {
    Path::new(dir).join(".codemap").join("cache.bincode")
}

fn load_cache(dir: &str) -> Option<CacheData> {
    let path = cache_path(dir);
    let bytes = fs::read(&path).ok()?;
    let data: CacheData = bincode::deserialize(&bytes).ok()?;
    if data.version != CACHE_VERSION {
        return None;
    }
    // Validate entries: skip any with path traversal
    let files: HashMap<String, CacheEntry> = data
        .files
        .into_iter()
        .filter(|(id, entry)| {
            !id.contains("..") && !id.starts_with('/')
                && !entry.imports.is_empty() || entry.imports.is_empty() // always pass, just validate arrays exist
        })
        .collect();
    Some(CacheData {
        version: CACHE_VERSION,
        files,
    })
}

fn save_cache(dir: &str, nodes: &HashMap<String, GraphNode>) {
    let cache_dir = Path::new(dir).join(".codemap");
    if !cache_dir.exists() {
        if fs::create_dir_all(&cache_dir).is_err() {
            return;
        }
    }
    let mut files = HashMap::new();
    for (id, node) in nodes {
        let mtime = node.mtime.unwrap_or(0.0);
        if mtime > 0.0 {
            files.insert(
                id.clone(),
                CacheEntry {
                    mtime,
                    imports: node.imports.clone(),
                    urls: node.urls.clone(),
                    exports: node.exports.clone(),
                    lines: node.lines,
                    functions: node.functions.clone(),
                    data_flow: node.data_flow.clone(),
                    bridges: node.bridges.clone(),
                },
            );
        }
    }
    let data = CacheData {
        version: CACHE_VERSION,
        files,
    };
    let encoded = match bincode::serialize(&data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Warning: could not serialize cache: {e}");
            return;
        }
    };
    // Atomic write: write to .tmp, then rename
    let final_path = cache_path(dir);
    let tmp_path = final_path.with_extension("bincode.tmp");
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&encoded)?;
        f.sync_all()?;
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    })();
    if let Err(e) = res {
        eprintln!("Warning: could not write cache: {e}");
        let _ = fs::remove_file(&tmp_path);
    }
}

// ── Directory Walk ──────────────────────────────────────────────────

fn walk_dir(dir: &Path, depth: usize, ext_set: &HashSet<&str>, files: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip special directories
        if SKIP_DIRS.iter().any(|&s| s == name_str.as_ref()) {
            continue;
        }

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        // Skip symlinks entirely
        if ft.is_symlink() {
            continue;
        }

        let path = entry.path();
        if ft.is_dir() {
            walk_dir(&path, depth + 1, ext_set, files);
        } else if ft.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let dotted = format!(".{ext}");
                if ext_set.contains(dotted.as_str()) {
                    files.push(path);
                }
            }
        }
    }
}

// ── File info collected per-file in parallel ────────────────────────

struct ParsedFile {
    id: String,
    node: GraphNode,
}

// ── Bridge Resolution ──────────────────────────────────────────────

/// Resolve cross-language bridge edges: match registrations to calls.
fn resolve_bridge_edges(nodes: &mut HashMap<String, GraphNode>) {
    // Build index: bridge_name → file_id for registrations
    let mut registrations: HashMap<String, Vec<String>> = HashMap::new();
    // Build index: cuda/triton kernel name → file_id
    let mut gpu_kernels: HashMap<String, Vec<String>> = HashMap::new();

    for (id, node) in nodes.iter() {
        for b in &node.bridges {
            if b.kind.is_registration() {
                registrations
                    .entry(b.name.clone())
                    .or_default()
                    .push(id.clone());
            }
            if b.kind.is_gpu() {
                gpu_kernels
                    .entry(b.name.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
    }

    // Collect edges to add (can't mutate while iterating)
    let mut new_edges: Vec<(String, String)> = Vec::new();

    for (id, node) in nodes.iter() {
        for b in &node.bridges {
            if b.kind.is_call() {
                // Find matching registration
                if let Some(reg_files) = registrations.get(&b.name) {
                    for reg_file in reg_files {
                        if reg_file != id {
                            new_edges.push((id.clone(), reg_file.clone()));
                        }
                    }
                }
                // For CUDA launches, also link to kernel declarations
                if b.kind == BridgeKind::CudaLaunch {
                    if let Some(kernel_files) = gpu_kernels.get(&b.name) {
                        for kf in kernel_files {
                            if kf != id {
                                new_edges.push((id.clone(), kf.clone()));
                            }
                        }
                    }
                }
            }
            // For Triton launches, link to kernel declarations
            if b.kind == BridgeKind::TritonLaunch {
                if let Some(kernel_files) = gpu_kernels.get(&b.name) {
                    for kf in kernel_files {
                        if kf != id {
                            new_edges.push((id.clone(), kf.clone()));
                        }
                    }
                }
            }
        }
    }

    // Apply edges
    for (from, to) in &new_edges {
        if let Some(node) = nodes.get_mut(from) {
            if !node.imports.contains(to) {
                node.imports.push(to.clone());
            }
        }
        if let Some(node) = nodes.get_mut(to) {
            if !node.imported_by.contains(from) {
                node.imported_by.push(from.clone());
            }
        }
    }

    if !new_edges.is_empty() {
        eprintln!(
            "Bridge edges: {} cross-language links resolved",
            new_edges.len()
        );
    }
}

// ── Single-directory scan ───────────────────────────────────────────

fn scan_single_dir(
    dir: &Path,
    include_paths: &[PathBuf],
    no_cache: bool,
) -> Result<(HashMap<String, GraphNode>, String), CodemapError> {
    let dir_str = dir.to_string_lossy().to_string();
    let ext_set: HashSet<&str> = SUPPORTED_EXTS.iter().copied().collect();

    // Walk
    let mut all_files: Vec<PathBuf> = Vec::new();
    walk_dir(dir, 0, &ext_set, &mut all_files);
    all_files.sort();

    // Load cache
    let cache = if no_cache { None } else { load_cache(&dir_str) };

    // Separate cache hits from misses
    let mut nodes: HashMap<String, GraphNode> = HashMap::new();
    let mut cache_hits = 0usize;
    let mut miss_files: Vec<PathBuf> = Vec::new();

    for file in &all_files {
        let id = match file.strip_prefix(dir) {
            Ok(rel) => rel.to_string_lossy().to_string().replace('\\', "/"),
            Err(_) => continue,
        };

        // Check cache
        if let Some(ref cache) = cache {
            if let Some(cached) = cache.files.get(&id) {
                if let Ok(meta) = fs::metadata(file) {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs_f64() * 1000.0)
                        .unwrap_or(0.0);
                    if (mtime - cached.mtime).abs() < 1.0 {
                        // Cache hit
                        nodes.insert(
                            id.clone(),
                            GraphNode {
                                id,
                                imports: cached.imports.clone(),
                                imported_by: Vec::new(),
                                urls: cached.urls.clone(),
                                exports: cached.exports.clone(),
                                lines: cached.lines,
                                functions: cached.functions.clone(),
                                data_flow: cached.data_flow.clone(),
                                bridges: cached.bridges.clone(),
                                mtime: Some(mtime),
                            },
                        );
                        cache_hits += 1;
                        continue;
                    }
                }
            }
        }

        miss_files.push(file.clone());
    }

    // Parse cache misses in parallel with rayon
    let ctx = ResolveContext::new(&dir_str, include_paths);
    let parsed: Vec<ParsedFile> = miss_files
        .par_iter()
        .filter_map(|file| {
            let id = file
                .strip_prefix(dir)
                .ok()?
                .to_string_lossy()
                .to_string()
                .replace('\\', "/");

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => return None,
            };

            let mtime = fs::metadata(file)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0);

            let ext = file
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();
            let file_str = file.to_string_lossy().to_string();

            let result = parser::parse_file(&file_str, &content, &ext);

            // Resolve imports
            let mut imports = Vec::new();
            for specifier in &result.imports {
                resolve::resolve_and_add(specifier, &file_str, &ctx, &mut imports);
            }

            let lines = content.lines().count();

            Some(ParsedFile {
                id: id.clone(),
                node: GraphNode {
                    id,
                    imports,
                    imported_by: Vec::new(),
                    urls: result.urls,
                    exports: result.exports,
                    lines,
                    functions: result.functions,
                    data_flow: result.data_flow,
                    bridges: result.bridges,
                    mtime: Some(mtime),
                },
            })
        })
        .collect();

    // Merge parsed results into nodes
    for pf in parsed {
        nodes.insert(pf.id, pf.node);
    }

    // Compute imported_by (reverse edges)
    let ids: Vec<String> = nodes.keys().cloned().collect();
    for id in &ids {
        let imps: Vec<String> = nodes.get(id).map(|n| n.imports.clone()).unwrap_or_default();
        for imp in &imps {
            if let Some(target) = nodes.get_mut(imp) {
                target.imported_by.push(id.clone());
            }
        }
    }

    // Resolve cross-language bridge edges
    resolve_bridge_edges(&mut nodes);

    // Save cache
    save_cache(&dir_str, &nodes);

    // Print cache stats
    if cache_hits > 0 {
        eprintln!("Cache: {}/{} files unchanged", cache_hits, all_files.len());
    }

    Ok((nodes, dir_str))
}

// ── Public entry point ──────────────────────────────────────────────

pub fn scan_directories(options: ScanOptions) -> Result<Graph, CodemapError> {
    let t0 = Instant::now();

    let dirs: Vec<PathBuf> = if options.dirs.is_empty() {
        return Err(CodemapError::ScanError("No directories specified".into()));
    } else {
        options.dirs
    };

    let graph = if dirs.len() == 1 {
        // Single directory scan
        let dir = &dirs[0];
        let (nodes, scan_dir) =
            scan_single_dir(dir, &options.include_paths, options.no_cache)?;
        let elapsed = t0.elapsed().as_millis();
        eprintln!("Scanned {} files in {}ms\n", nodes.len(), elapsed);
        Graph {
            nodes,
            scan_dir,
            cpg: None,
        }
    } else {
        // Multi-repo merge
        let mut merged_nodes: HashMap<String, GraphNode> = HashMap::new();
        let first_dir = dirs[0].to_string_lossy().to_string();

        for dir in &dirs {
            let (sub_nodes, _scan_dir) =
                scan_single_dir(dir, &options.include_paths, options.no_cache)?;

            let repo_name = dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| dir.to_string_lossy().to_string());

            // Collect sub_node keys for "is known" check during import prefixing
            let known_ids: HashSet<String> = sub_nodes.keys().cloned().collect();

            for (id, mut node) in sub_nodes {
                let prefixed_id = format!("{repo_name}/{id}");
                // Prefix imports that resolved to known files in this sub-graph
                node.imports = node
                    .imports
                    .into_iter()
                    .map(|imp| {
                        if known_ids.contains(&imp) {
                            format!("{repo_name}/{imp}")
                        } else {
                            imp
                        }
                    })
                    .collect();
                node.id = prefixed_id.clone();
                node.imported_by = Vec::new();
                merged_nodes.insert(prefixed_id, node);
            }
        }

        // Rebuild imported_by with prefixed IDs
        let ids: Vec<String> = merged_nodes.keys().cloned().collect();
        for id in &ids {
            let imps: Vec<String> = merged_nodes
                .get(id)
                .map(|n| n.imports.clone())
                .unwrap_or_default();
            for imp in &imps {
                if let Some(target) = merged_nodes.get_mut(imp) {
                    target.imported_by.push(id.clone());
                }
            }
        }

        // Cross-repo linking: match unresolved imports by filename
        let all_ids: Vec<String> = merged_nodes.keys().cloned().collect();
        for id in &all_ids {
            let imports = merged_nodes
                .get(id)
                .map(|n| n.imports.clone())
                .unwrap_or_default();
            let unresolved: Vec<String> = imports
                .iter()
                .filter(|imp| !merged_nodes.contains_key(imp.as_str()))
                .cloned()
                .collect();

            for unres in &unresolved {
                let base_name = unres.split('/').last().unwrap_or(unres);
                let mut matched_id: Option<String> = None;
                for other_id in &all_ids {
                    if other_id == id {
                        continue;
                    }
                    if other_id.ends_with(&format!("/{base_name}"))
                        || other_id.ends_with(&format!("/{unres}"))
                    {
                        matched_id = Some(other_id.clone());
                        break;
                    }
                }
                if let Some(match_id) = matched_id {
                    // Replace unresolved import with matched cross-repo file
                    if let Some(node) = merged_nodes.get_mut(id) {
                        if let Some(idx) = node.imports.iter().position(|i| i == unres) {
                            node.imports[idx] = match_id.clone();
                        }
                    }
                    if let Some(target) = merged_nodes.get_mut(&match_id) {
                        target.imported_by.push(id.clone());
                    }
                }
            }
        }

        // Resolve cross-language bridge edges
        resolve_bridge_edges(&mut merged_nodes);

        let elapsed = t0.elapsed().as_millis();
        eprintln!("Scanned {} files in {}ms\n", merged_nodes.len(), elapsed);

        Graph {
            nodes: merged_nodes,
            scan_dir: first_dir,
            cpg: None,
        }
    };

    Ok(graph)
}
