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

// 9: heterogeneous graph (EntityKind + attrs on GraphNode)
// 10: typed_nodes persistence — RE-action mutations cache across CLI runs
const CACHE_VERSION: u32 = 10;
const MAX_DEPTH: usize = 50;

/// Print a warning when a single scan crosses this many supported files.
const FILE_COUNT_WARN: usize = 10_000;

/// Hard cap to prevent OOM. Without this guard, a scan rooted at $HOME
/// or any large parent dir (192K+ files) can balloon to 50 GB heap and
/// trigger a kernel OOM-kill that reaps the entire systemd cgroup —
/// including the user's tmux session.
/// Override with CODEMAP_NO_FILE_LIMIT=1 if you genuinely need to scan more.
const FILE_COUNT_HARD_CAP: usize = 50_000;

/// Directories to skip during walk. These are dependency, build, cache, and
/// IDE/VCS dirs that contain vendored or generated files — never user source
/// code. Walking into them is the documented cause of the OOM-cascade
/// incident 2026-04-29 23:18 UTC: a scan rooted at $HOME descended into
/// every project's `.venv/` (each ~10K vendored Python files), AST-parsed
/// all of them, and ballooned to ~50 GB heap before kernel-OOM-killing the
/// whole tmux scope. Each entry below should pay for its place — reject
/// additions that match real user code paths.
const SKIP_DIRS: &[&str] = &[
    // VCS
    ".git", ".hg", ".svn",
    // Node / JS bundlers / framework caches
    "node_modules", "bower_components", "jspm_packages",
    "dist", "build", "out",
    ".next", ".nuxt", ".svelte-kit", ".vercel", ".turbo",
    ".parcel-cache", ".cache",
    // Python venvs + tooling caches
    ".venv", "venv", "__pycache__",
    ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "site-packages",
    // Rust / Go / Java / Ruby / PHP
    "target", "vendor", ".gradle",
    // Coverage / IDE
    "coverage", ".nyc_output", ".idea", ".vscode",
    // iOS / Cocoapods
    "Pods",
    // codemap's own cache
    ".codemap",
];

/// Supported file extensions (with leading dot).
const SUPPORTED_EXTS: &[&str] = &[
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".rs", ".go", ".java", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    ".cu", ".cuh",
    ".sh", ".bash",
    ".yaml", ".yml", ".cmake",
    ".cs", ".kt", ".kts", ".lua", ".sql",
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

/// Persisted RE-action graph mutations (heterogeneous nodes that aren't
/// tied to a source file). Lets multi-step CLI workflows compose RE
/// actions: first invocation `codemap pe-imports foo.exe` creates the
/// PeBinary/Dll/Symbol nodes, second `codemap meta-path source->endpoint`
/// reads them back and traverses. Without this, each CLI process starts
/// with only source-file nodes regardless of past RE runs.
#[derive(Serialize, Deserialize, Clone)]
struct TypedNodeEntry {
    id: String,
    kind: crate::types::EntityKind,
    imports: Vec<String>,
    imported_by: Vec<String>,
    attrs: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct CacheData {
    version: u32,
    files: HashMap<String, CacheEntry>,
    /// Non-source-file typed nodes registered by RE-action passes. These
    /// persist across CLI invocations so meta-path / pagerank / etc. can
    /// see RE outputs from earlier runs.
    #[serde(default)]
    typed_nodes: Vec<TypedNodeEntry>,
}

// ── Cache I/O ───────────────────────────────────────────────────────

fn cache_path(dir: &str) -> PathBuf {
    Path::new(dir).join(".codemap").join("cache.bincode")
}

fn load_cache(dir: &str) -> Option<CacheData> {
    let path = cache_path(dir);
    let bytes = fs::read(&path).ok()?;
    if bytes.len() > 256 * 1024 * 1024 {
        eprintln!("Warning: cache file too large ({}MB), ignoring", bytes.len() / 1024 / 1024);
        return None;
    }
    let data: CacheData = bincode::deserialize(&bytes).ok()?;
    if data.version != CACHE_VERSION {
        return None;
    }
    // Validate entries: skip any with path traversal
    let files: HashMap<String, CacheEntry> = data
        .files
        .into_iter()
        .filter(|(id, _)| {
            !id.contains("..") && !id.starts_with('/')
        })
        .collect();
    Some(CacheData {
        version: CACHE_VERSION,
        files,
        typed_nodes: data.typed_nodes,
    })
}

/// Promote URLs found by the parser into HttpEndpoint nodes with edges
/// from each source file to its URLs. Method defaults to "GET" since
/// plain URL-string extraction has no method context.
///
/// Filtering — we DON'T want polluting the graph:
/// - URLs with template placeholders (`${...}`, `{{...}}`, `<%...%>`,
///   `:param` style) — they're not literal endpoints.
/// - XML namespace identifiers (w3.org, xmlsoap.org, *.xsd, *.dtd).
///   Common in any HTML/SVG/XML codebase but never real endpoints.
/// - URLs from test files (paths matching `tests?/`, `_test`, `.test.`,
///   `spec`, `__tests__`). Test fixtures are rarely production endpoints.
/// - URLs from minified-JS bundles (heuristic: file's mean line length
///   > 800 chars OR has `.min.` in the path). Bundled deps drown out
///   real endpoints.
/// - URLs with embedded credentials (`@` after `://`). Likely sanitized
///   placeholder — not useful as a graph node.
/// - Loopback / placeholder hosts (localhost, 127.0.0.1, *.example.*,
///   *.test, *.invalid).
fn promote_urls_to_endpoints(nodes: &mut HashMap<String, GraphNode>) {
    let mut new_endpoints: Vec<(String, String, String)> = Vec::new(); // (src_id, ep_id, url)
    let skip_hosts = ["localhost", "127.0.0.1", "0.0.0.0",
        "example.com", "example.org", "example.net"];
    // XML namespace prefixes — any URL starting with these is a namespace
    // identifier, not a real endpoint.
    let xml_namespaces = [
        "http://www.w3.org/", "https://www.w3.org/",
        "http://schemas.xmlsoap.org/", "https://schemas.xmlsoap.org/",
        "http://schemas.microsoft.com/", "https://schemas.microsoft.com/",
        "urn:",
    ];

    fn is_test_file(id: &str) -> bool {
        let lower = id.to_ascii_lowercase();
        lower.contains("/tests/") || lower.contains("/test/")
            || lower.contains("__tests__")
            || lower.contains("/spec/") || lower.contains("/specs/")
            || lower.ends_with("_test.py") || lower.ends_with("_test.go")
            || lower.ends_with(".test.ts") || lower.ends_with(".test.js")
            || lower.ends_with(".spec.ts") || lower.ends_with(".spec.js")
            || lower.contains("/fixtures/") || lower.contains("/fixture/")
    }

    fn is_minified(id: &str, node: &GraphNode) -> bool {
        let lower = id.to_ascii_lowercase();
        if lower.contains(".min.") || lower.ends_with(".min")
            || lower.contains(".bundle.") || lower.contains(".chunk.") {
            return true;
        }
        // Heuristic: extracted URLs / lines ratio. Minified files usually
        // have very few lines but many URL extractions.
        if node.lines > 0 && node.lines < 5 && node.urls.len() > 5 {
            return true;
        }
        false
    }

    fn is_template_url(url: &str) -> bool {
        url.contains("${") || url.contains("{{") || url.contains("<%")
            || url.contains("#{") || url.contains("%(") || url.contains("(?P<")
    }

    fn is_xml_namespace(url: &str, xml_namespaces: &[&str]) -> bool {
        xml_namespaces.iter().any(|p| url.starts_with(p))
            || url.ends_with(".xsd") || url.ends_with(".dtd")
    }

    fn has_credentials(url: &str) -> bool {
        // url like `https://user:pass@host/path` or `https://[redacted]@host/path`
        if let Some(scheme_end) = url.find("://") {
            let after = &url[scheme_end + 3..];
            let host_end = after.find('/').unwrap_or(after.len());
            after[..host_end].contains('@')
        } else { false }
    }

    fn host_of(url: &str) -> &str {
        let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
        let after = &url[scheme_end..];
        let host_end = after.find([':', '/', '?', '#']).unwrap_or(after.len());
        &after[..host_end]
    }

    for (src_id, node) in nodes.iter() {
        if node.kind != crate::types::EntityKind::SourceFile { continue; }
        if is_test_file(src_id) { continue; }
        if is_minified(src_id, node) { continue; }

        for url in &node.urls {
            if !url.starts_with("http://") && !url.starts_with("https://") { continue; }
            if is_template_url(url) { continue; }
            if is_xml_namespace(url, &xml_namespaces) { continue; }
            if has_credentials(url) { continue; }

            let host = host_of(url);
            // Loopback / placeholder hosts
            if skip_hosts.contains(&host) { continue; }
            // Reject pseudo-TLDs that are reserved for test/local use
            if host.ends_with(".test") || host.ends_with(".invalid")
                || host.ends_with(".local") || host.ends_with(".localhost")
                || host.ends_with(".example") {
                continue;
            }

            let ep_id = format!("ep:GET:{url}");
            new_endpoints.push((src_id.clone(), ep_id, url.clone()));
        }
    }

    for (src_id, ep_id, url) in new_endpoints {
        // Skip if this id is already claimed by an RE action (it might
        // have a richer method like POST). Don't downgrade.
        if nodes.contains_key(&ep_id) { continue; }
        let mut attrs = HashMap::new();
        attrs.insert("method".to_string(), "GET".to_string());
        attrs.insert("url".to_string(), url.clone());
        attrs.insert("source".to_string(), "scanner-url-promotion".to_string());
        nodes.insert(ep_id.clone(), GraphNode {
            id: ep_id.clone(),
            imports: Vec::new(),
            imported_by: vec![src_id.clone()],
            urls: Vec::new(),
            exports: Vec::new(),
            lines: 0,
            functions: Vec::new(),
            data_flow: None,
            bridges: Vec::new(),
            kind: crate::types::EntityKind::HttpEndpoint,
            attrs,
            mtime: None,
        });
        // Add forward edge from source file to endpoint
        if let Some(src_node) = nodes.get_mut(&src_id) {
            if !src_node.imports.iter().any(|i| i == &ep_id) {
                src_node.imports.push(ep_id);
            }
        }
    }
}

/// Auto-classify non-source files into typed nodes by extension. Called
/// during scan walk: when we see foo.exe / bar.gguf / schema.proto / etc.
/// we don't deep-parse, but we do register a typed node so graph queries
/// can see them without requiring the user to manually run pe-imports /
/// gguf-info / proto-schema. Pairing this with the URL-promotion pass
/// means a vanilla `codemap structure` produces a meaningful
/// heterogeneous graph out of the box on most repos.
fn auto_classify_typed_files(dir: &Path, nodes: &mut HashMap<String, GraphNode>) {
    use crate::types::EntityKind;

    fn classify(ext: &str) -> Option<(EntityKind, &'static str)> {
        Some(match ext {
            // PE — Windows binaries (and .NET assemblies, which are PE files)
            "exe" | "dll" | "sys" => (EntityKind::PeBinary, "pe"),
            // ELF — Linux binaries / shared objects
            "so" => (EntityKind::ElfBinary, "elf"),
            // Mach-O — macOS binaries / shared libraries
            "dylib" => (EntityKind::MachoBinary, "macho"),
            // JVM
            "class" | "jar" => (EntityKind::JavaClass, "java"),
            // WebAssembly
            "wasm" => (EntityKind::WasmModule, "wasm"),
            // ML model formats
            "gguf"        => (EntityKind::MlModel, "gguf"),
            "safetensors" => (EntityKind::MlModel, "safetensors"),
            "onnx"        => (EntityKind::MlModel, "onnx"),
            "pyc"         => (EntityKind::MlModel, "pyc"),
            "fatbin" | "cubin" => (EntityKind::MlModel, "cuda"),
            // Schema sources
            "proto" => (EntityKind::ProtoMessage, "proto"),
            "tf"    => (EntityKind::TerraformResource, "terraform"),
            // Clarion / dBASE schemas
            "clw" | "txa" | "txd" => (EntityKind::SchemaTable, "clarion"),
            "dbf"                 => (EntityKind::SchemaTable, "dbf"),
            _ => return None,
        })
    }

    fn walk(dir: &Path, depth: usize, nodes: &mut HashMap<String, GraphNode>, scan_root: &Path) {
        if depth > MAX_DEPTH { return; }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e, Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') && name_str != ".codemap" { continue; }
            if SKIP_DIRS.iter().any(|d| *d == name_str.as_ref()) { continue; }

            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                walk(&path, depth + 1, nodes, scan_root);
                continue;
            }
            if !ft.is_file() { continue; }

            let Some(ext) = path.extension().and_then(|e| e.to_str()) else { continue };
            let Some((kind, category)) = classify(&ext.to_ascii_lowercase()) else { continue };

            // Use the path relative to scan_root so the id matches what
            // RE actions would produce when run later (avoids duplicate
            // nodes in the cache).
            let rel = path.strip_prefix(scan_root).unwrap_or(&path);
            let path_str = rel.to_string_lossy().to_string();
            // Pick the right id-prefix per kind so it matches what the
            // explicit RE actions register (consistency = no dup nodes
            // when a user runs e.g. pe-imports later).
            let id = match kind {
                EntityKind::PeBinary       => format!("pe:{path_str}"),
                EntityKind::ElfBinary      => format!("elf:{path_str}"),
                EntityKind::MachoBinary    => format!("macho:{path_str}"),
                EntityKind::JavaClass      => format!("java:{path_str}"),
                EntityKind::WasmModule     => format!("wasm:{path_str}"),
                EntityKind::MlModel        => format!("model:{path_str}"),
                EntityKind::ProtoMessage   => format!("schema:proto:{path_str}"),
                EntityKind::TerraformResource => format!("schema:terraform:{path_str}"),
                EntityKind::SchemaTable    => format!("schema:{category}:{path_str}"),
                _ => format!("file:{path_str}"),
            };
            // Don't clobber existing entries (RE-action mutations may
            // already have richer attrs)
            if nodes.contains_key(&id) { continue; }

            let mut attrs = HashMap::new();
            attrs.insert("path".to_string(), path_str.clone());
            attrs.insert("category".to_string(), category.to_string());
            attrs.insert("auto_classified".to_string(), "true".to_string());
            if let Ok(meta) = entry.metadata() {
                attrs.insert("size".to_string(), meta.len().to_string());
            }
            nodes.insert(id.clone(), GraphNode {
                id,
                imports: Vec::new(),
                imported_by: Vec::new(),
                urls: Vec::new(),
                exports: Vec::new(),
                lines: 0,
                functions: Vec::new(),
                data_flow: None,
                bridges: Vec::new(),
                kind,
                attrs,
                mtime: None,
            });
        }
    }
    walk(dir, 0, nodes, dir);
}

/// Public hook: persist any RE-action mutations on `graph` back to cache
/// after dispatch completes. Source-file entries are preserved (we only
/// rewrite the typed_nodes section). Called once per CLI invocation by
/// actions::dispatch so RE actions accumulate state across processes.
pub fn persist_typed_nodes(graph: &crate::types::Graph) {
    if graph.scan_dir.is_empty() { return; }
    save_cache(&graph.scan_dir, &graph.nodes);
}

fn save_cache(dir: &str, nodes: &HashMap<String, GraphNode>) {
    let cache_dir = Path::new(dir).join(".codemap");
    if !cache_dir.exists()
        && fs::create_dir_all(&cache_dir).is_err() {
            return;
        }
    let mut files = HashMap::new();
    let mut typed_nodes: Vec<TypedNodeEntry> = Vec::new();
    for (id, node) in nodes {
        let mtime = node.mtime.unwrap_or(0.0);
        if node.kind == crate::types::EntityKind::SourceFile && mtime > 0.0 {
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
        } else if node.kind != crate::types::EntityKind::SourceFile {
            // RE-action nodes (PeBinary, SchemaTable, HttpEndpoint, etc.)
            // persist independently of mtime — they're not file-backed.
            typed_nodes.push(TypedNodeEntry {
                id: id.clone(),
                kind: node.kind,
                imports: node.imports.clone(),
                imported_by: node.imported_by.clone(),
                attrs: node.attrs.clone(),
            });
        }
    }
    let data = CacheData {
        version: CACHE_VERSION,
        files,
        typed_nodes,
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

fn walk_dir(
    dir: &Path,
    depth: usize,
    ext_set: &HashSet<&str>,
    files: &mut Vec<PathBuf>,
    file_cap: usize,
) -> bool {
    // Returns false when the cap has been hit so callers can short-circuit.
    if depth > MAX_DEPTH {
        return true;
    }
    if files.len() >= file_cap {
        return false;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return true,
    };
    for entry in entries.flatten() {
        if files.len() >= file_cap {
            return false;
        }
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
            if !walk_dir(&path, depth + 1, ext_set, files, file_cap) {
                return false;
            }
        } else if ft.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let dotted = format!(".{ext}");
                if ext_set.contains(dotted.as_str()) {
                    files.push(path);
                }
            }
        }
    }
    true
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
    quiet: bool,
) -> Result<(HashMap<String, GraphNode>, String), CodemapError> {
    let dir_str = dir.to_string_lossy().to_string();
    let ext_set: HashSet<&str> = SUPPORTED_EXTS.iter().copied().collect();

    // Walk with a hard cap to prevent OOM on accidental $HOME-rooted scans.
    // Override via env var CODEMAP_NO_FILE_LIMIT=1 (uses usize::MAX).
    let allow_unlimited = std::env::var("CODEMAP_NO_FILE_LIMIT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let file_cap = if allow_unlimited { usize::MAX } else { FILE_COUNT_HARD_CAP };

    let mut all_files: Vec<PathBuf> = Vec::new();
    let walk_completed = walk_dir(dir, 0, &ext_set, &mut all_files, file_cap);

    if !walk_completed && !allow_unlimited {
        return Err(CodemapError::ScanError(format!(
            "Scan of {} hit the safety cap of {} supported files (likely a $HOME or other large \
             parent dir). codemap previously OOM-killed itself reaping a user's tmux session in \
             this scenario. Pass --dir <smaller_path> to scope the scan, or set \
             CODEMAP_NO_FILE_LIMIT=1 to override (use only with plenty of free RAM).",
            dir_str, FILE_COUNT_HARD_CAP
        )));
    }

    if !quiet && all_files.len() >= FILE_COUNT_WARN {
        eprintln!(
            "Warning: scanning {} files in {} — this may consume significant memory. \
             Consider scoping with --dir if you only need a subset.",
            all_files.len(),
            dir_str
        );
    }

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
                                kind: crate::types::EntityKind::SourceFile,
                                attrs: std::collections::HashMap::new(),
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

    // Propagate quiet flag to parser
    parser::set_quiet(quiet);

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

            // Skip files larger than 10MB
            let meta = match fs::metadata(file) {
                Ok(m) => m,
                Err(_) => return None,
            };
            if meta.len() > 10_000_000 {
                return None;
            }

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => return None,
            };

            let mtime = meta
                .modified()
                .ok()
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
                    kind: crate::types::EntityKind::SourceFile,
                    attrs: std::collections::HashMap::new(),
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

    // Promote URL extractions from each source file to typed HttpEndpoint
    // nodes with file→endpoint edges. The parser already extracts URLs
    // into `node.urls`; this step makes them participate in the
    // heterogeneous graph so `meta-path source->endpoint` and
    // `pagerank --type endpoint` work on any codebase without needing
    // to run a web-RE action first. URLs without an HTTP method default
    // to GET — refined later if a HAR / JS-extract pass overlaps.
    promote_urls_to_endpoints(&mut nodes);

    // Auto-classify non-source files (binaries / ML models / schema
    // sources). Pairs with URL promotion to make `codemap structure`
    // alone produce a useful heterogeneous graph on real repos —
    // pagerank --type pe / model / proto etc. just work.
    auto_classify_typed_files(dir, &mut nodes);

    // Hydrate typed (non-source) nodes from cache. These were registered
    // by past RE-action invocations (pe-imports, web-blueprint, schema
    // actions, etc.) and persist across CLI processes so multi-step
    // workflows can chain RE passes into meta-path queries.
    if let Some(ref c) = cache {
        for tn in &c.typed_nodes {
            // Skip if a real source-file node already claims this id
            if nodes.contains_key(&tn.id) { continue; }
            nodes.insert(tn.id.clone(), GraphNode {
                id: tn.id.clone(),
                imports: tn.imports.clone(),
                imported_by: tn.imported_by.clone(),
                urls: Vec::new(),
                exports: Vec::new(),
                lines: 0,
                functions: Vec::new(),
                data_flow: None,
                bridges: Vec::new(),
                kind: tn.kind,
                attrs: tn.attrs.clone(),
                mtime: None,
            });
        }
    }

    // Save cache (source files only — RE-action mutations save themselves
    // after each action via Graph::persist_typed_nodes; see actions/mod.rs)
    save_cache(&dir_str, &nodes);

    // Print cache stats
    if cache_hits > 0 && !quiet {
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

    let quiet = options.quiet;
    let graph = if dirs.len() == 1 {
        // Single directory scan
        let dir = &dirs[0];
        let (nodes, scan_dir) =
            scan_single_dir(dir, &options.include_paths, options.no_cache, quiet)?;
        let elapsed = t0.elapsed().as_millis();
        if !quiet { eprintln!("Scanned {} files in {}ms\n", nodes.len(), elapsed); }
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
                scan_single_dir(dir, &options.include_paths, options.no_cache, quiet)?;

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
        // Build stem map for O(1) lookups instead of O(n) linear scans
        let all_ids: Vec<String> = merged_nodes.keys().cloned().collect();
        let mut stem_map: HashMap<String, Vec<String>> = HashMap::new();
        for id in &all_ids {
            // Index by filename stem (last path component)
            if let Some(stem) = id.rsplit('/').next() {
                stem_map.entry(stem.to_string()).or_default().push(id.clone());
            }
        }

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
                let base_name = unres.split('/').next_back().unwrap_or(unres);
                let mut matches: Vec<String> = Vec::new();

                // Look up candidates by stem (O(1) instead of O(n))
                if let Some(candidates) = stem_map.get(base_name) {
                    for cand in candidates {
                        if cand == id { continue; }
                        if cand.ends_with(&format!("/{base_name}"))
                            || cand.ends_with(&format!("/{unres}"))
                        {
                            matches.push(cand.clone());
                        }
                    }
                }

                // Only link if exactly one match (skip ambiguous)
                if matches.len() != 1 {
                    continue;
                }
                if let Some(match_id) = matches.into_iter().next() {
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
        if !quiet { eprintln!("Scanned {} files in {}ms\n", merged_nodes.len(), elapsed); }

        Graph {
            nodes: merged_nodes,
            scan_dir: first_dir,
            cpg: None,
        }
    };

    Ok(graph)
}
