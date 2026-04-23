use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Resolve Context ─────────────────────────────────────────────────

pub struct ResolveContext {
    pub scan_dir: String,
    pub include_paths: Vec<PathBuf>,
    pub tsconfig_paths: HashMap<String, String>,
}

impl ResolveContext {
    pub fn new(scan_dir: &str, include_paths: &[PathBuf]) -> Self {
        let mut ctx = ResolveContext {
            scan_dir: scan_dir.to_string(),
            include_paths: include_paths.to_vec(),
            tsconfig_paths: HashMap::new(),
        };
        ctx.load_tsconfig_paths();
        ctx
    }

    /// Walk up from scan_dir (up to 5 levels) to find tsconfig.json and load path aliases.
    fn load_tsconfig_paths(&mut self) {
        let mut search_dir = PathBuf::from(&self.scan_dir);
        for _ in 0..5 {
            let tsconfig_path = search_dir.join("tsconfig.json");
            if let Ok(content) = std::fs::read_to_string(&tsconfig_path) {
                if let Ok(tsconfig) = serde_json::from_str::<serde_json::Value>(&content) {
                    let base_url = tsconfig
                        .get("compilerOptions")
                        .and_then(|c| c.get("baseUrl"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(".");
                    let base = search_dir.join(base_url);
                    if let Some(paths) = tsconfig
                        .get("compilerOptions")
                        .and_then(|c| c.get("paths"))
                        .and_then(|v| v.as_object())
                    {
                        for (alias, targets) in paths {
                            let prefix = alias.trim_end_matches('*').to_string();
                            if let Some(first_target) = targets.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()) {
                                let target = first_target.trim_end_matches('*');
                                let resolved = base.join(target);
                                self.tsconfig_paths.insert(
                                    prefix,
                                    resolved.to_string_lossy().to_string(),
                                );
                            }
                        }
                    }
                    break;
                }
            }
            let parent = search_dir.parent().map(|p| p.to_path_buf());
            match parent {
                Some(p) if p != search_dir => search_dir = p,
                _ => break,
            }
        }
    }
}

// ── Supported extensions for extension probing ──────────────────────

const JS_TS_EXTENSIONS: &[&str] = &[
    ".ts", ".tsx", ".js", ".jsx", ".mjs",
    "/index.ts", "/index.tsx", "/index.js",
];

const C_CPP_EXTS: &[&str] = &[
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".cu", ".cuh",
];

const RUST_EXTS: &[&str] = &[".rs", "/mod.rs"];

// ── Public API ──────────────────────────────────────────────────────

/// Resolve a single import specifier from `from_file` and push the resolved ID
/// (relative to `scan_dir`) into `node_imports`.
pub fn resolve_and_add(
    specifier: &str,
    from_file: &str,
    ctx: &ResolveContext,
    node_imports: &mut Vec<String>,
) {
    let scan_dir = Path::new(&ctx.scan_dir);
    let from_ext = Path::new(from_file)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    // ── Rust module resolution ─────────────────────────────────────
    // Must come before generic relative import handler so .rs files
    // don't fall through to JS/TS extension probing.
    if from_ext == ".rs" {
        // ./module imports from mod declarations
        if specifier.starts_with("./") {
            let mod_name = &specifier[2..];
            let from_dir = Path::new(from_file).parent().unwrap_or(Path::new(""));

            for ext in RUST_EXTS {
                let candidate = from_dir.join(format!("{mod_name}{ext}"));
                if candidate.exists() {
                    if let Ok(rel) = candidate.strip_prefix(scan_dir) {
                        node_imports.push(normalize_path(&rel.to_string_lossy()));
                        return;
                    }
                }
            }
            return;
        }

        // crate:: imports → resolve relative to crate root (scan_dir)
        if specifier.starts_with("crate::") {
            let rest = &specifier[7..]; // strip "crate::"
            // Clean up tree-sitter artifacts like "{Foo, Bar}"
            let module = rest.split("::{").next().unwrap_or(rest);
            let module = module.split("::").next().unwrap_or(module);

            for ext in RUST_EXTS {
                let candidate = scan_dir.join(format!("{module}{ext}"));
                if candidate.exists() {
                    if let Ok(rel) = candidate.strip_prefix(scan_dir) {
                        node_imports.push(normalize_path(&rel.to_string_lossy()));
                        return;
                    }
                }
            }
            return;
        }

        // self:: and super:: — resolve relative to current module or parent, not separate files
        if specifier.starts_with("self::") || specifier.starts_with("super::") {
            return;
        }

        // External crates (std::, serde::, rayon::, etc.) — skip, don't store as imports
        if !specifier.contains('/') {
            return;
        }
    }

    // ── 1. Relative imports ─────────────────────────────────────────
    if specifier.starts_with('.') {
        let from_dir = Path::new(from_file).parent().unwrap_or(Path::new(""));
        let resolved = from_dir.join(specifier);

        // Try exact match and JS→TS swaps
        let resolved_str = resolved.to_string_lossy().to_string();
        let mut candidates = vec![resolved_str.clone()];
        if resolved_str.ends_with(".js") {
            candidates.push(resolved_str[..resolved_str.len() - 3].to_string() + ".ts");
            candidates.push(resolved_str[..resolved_str.len() - 3].to_string() + ".tsx");
        }
        if resolved_str.ends_with(".jsx") {
            candidates.push(resolved_str[..resolved_str.len() - 4].to_string() + ".tsx");
        }
        if resolved_str.ends_with(".mjs") {
            candidates.push(resolved_str[..resolved_str.len() - 4].to_string() + ".mts");
        }

        for cand in &candidates {
            if Path::new(cand).exists() {
                if let Ok(rel) = Path::new(cand).strip_prefix(scan_dir) {
                    node_imports.push(normalize_path(&rel.to_string_lossy()));
                    return;
                }
            }
        }

        // Try adding extensions
        for ext in JS_TS_EXTENSIONS {
            let candidate = format!("{}{}", resolved_str, ext);
            if Path::new(&candidate).exists() {
                if let Ok(rel) = Path::new(&candidate).strip_prefix(scan_dir) {
                    node_imports.push(normalize_path(&rel.to_string_lossy()));
                    return;
                }
            }
        }
        return;
    }

    // ── 2. TSConfig path aliases ────────────────────────────────────
    let mut is_alias = false;
    for prefix in ctx.tsconfig_paths.keys() {
        if specifier.starts_with(prefix.as_str()) {
            is_alias = true;
            break;
        }
    }

    if is_alias {
        for (prefix, target) in &ctx.tsconfig_paths {
            if specifier.starts_with(prefix.as_str()) {
                let rest = &specifier[prefix.len()..];
                let resolved = Path::new(target).join(rest);
                let resolved_str = resolved.to_string_lossy().to_string();

                let mut candidates = vec![resolved_str.clone()];
                if resolved_str.ends_with(".js") {
                    candidates.push(resolved_str[..resolved_str.len() - 3].to_string() + ".ts");
                    candidates.push(resolved_str[..resolved_str.len() - 3].to_string() + ".tsx");
                }
                if resolved_str.ends_with(".jsx") {
                    candidates.push(resolved_str[..resolved_str.len() - 4].to_string() + ".tsx");
                }
                // Also try appending extensions
                for ext in &[".ts", ".tsx", ".js", "/index.ts", "/index.js"] {
                    candidates.push(format!("{}{}", resolved_str, ext));
                }

                for cand in &candidates {
                    if Path::new(cand).exists() {
                        if let Ok(rel) = Path::new(cand).strip_prefix(scan_dir) {
                            node_imports.push(normalize_path(&rel.to_string_lossy()));
                            return;
                        }
                    }
                }
            }
        }
    }

    // ── 3. C/C++ #include resolution ────────────────────────────────
    if C_CPP_EXTS.contains(&from_ext.as_str()) {
        let from_dir = Path::new(from_file).parent().unwrap_or(Path::new(""));
        let search_dirs: Vec<&Path> = ctx
            .include_paths
            .iter()
            .map(|p| p.as_path())
            .chain(std::iter::once(scan_dir))
            .chain(std::iter::once(from_dir))
            .collect();

        for search_dir_path in &search_dirs {
            let candidate = search_dir_path.join(specifier);
            if candidate.exists() {
                if let Ok(rel) = candidate.strip_prefix(scan_dir) {
                    node_imports.push(normalize_path(&rel.to_string_lossy()));
                    return;
                }
            }
        }
    }

    // ── 4. Bare specifier — store package name only ─────────────────
    let parts: Vec<&str> = specifier.split('/').collect();
    let pkg = if specifier.starts_with('@') && parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts[0].to_string()
    };
    node_imports.push(pkg);
}

/// Normalize path separators to forward slash (for Windows compat) and
/// collapse any ".." or "." segments.
fn normalize_path(p: &str) -> String {
    p.replace('\\', "/")
}
