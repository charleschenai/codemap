use std::collections::{HashMap, HashSet, BTreeMap};
use std::path::Path;
use std::sync::LazyLock;
use regex::Regex;
use crate::types::Graph;

// Hoisted out of `parse_cargo_toml` — Regex::new in a hot loop is a real
// perf hit. Cargo.toml inline-table parser; matched per dep entry.
static CARGO_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"version\s*=\s*"([^"]+)""#).unwrap()
});

// ── Skip patterns for secret scanning ──────────────────────────────

fn should_skip_file(path: &str) -> bool {
    let skip_names = [
        "package-lock.json", "yarn.lock", "Cargo.lock", "go.sum",
        "pnpm-lock.yaml", "composer.lock", "Gemfile.lock", "poetry.lock",
    ];
    let basename = path.rsplit('/').next().unwrap_or(path);
    if skip_names.contains(&basename) {
        return true;
    }
    if basename.ends_with(".min.js") || basename.ends_with(".min.css") {
        return true;
    }
    // Skip test fixtures
    if path.contains("__fixtures__") || path.contains("/fixtures/")
        || path.contains("/testdata/") || path.contains("__snapshots__")
    {
        return true;
    }
    false
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 4 {
        "****".to_string()
    } else {
        format!("{}***", &s[..4])
    }
}

// ── 1. secret_scan ─────────────────────────────────────────────────

struct SecretPattern {
    name: &'static str,
    severity: &'static str,
    regex: Regex,
}

struct Finding {
    file: String,
    line: usize,
    pattern_name: String,
    severity: String,
    preview: String,
}

pub fn secret_scan(graph: &Graph, _target: &str) -> String {
    let patterns = vec![
        SecretPattern {
            name: "AWS Access Key",
            severity: "critical",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        SecretPattern {
            name: "AWS Secret Key",
            severity: "critical",
            regex: Regex::new(r#"(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#).unwrap(),
        },
        SecretPattern {
            name: "Private Key",
            severity: "critical",
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
        },
        SecretPattern {
            name: "GitHub PAT",
            severity: "high",
            regex: Regex::new(r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}").unwrap(),
        },
        SecretPattern {
            name: "Generic API Key",
            severity: "high",
            regex: Regex::new(r#"(?i)(api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token)\s*[=:]\s*['"][0-9a-zA-Z\-_.]{16,}['"]"#).unwrap(),
        },
        SecretPattern {
            name: "Password",
            severity: "high",
            regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]"#).unwrap(),
        },
        SecretPattern {
            name: "Generic Secret/Token",
            severity: "high",
            regex: Regex::new(r#"(?i)(secret|token|credential)\s*[=:]\s*['"][^'"]{8,}['"]"#).unwrap(),
        },
        SecretPattern {
            name: "JWT Token",
            severity: "high",
            regex: Regex::new(r"eyJ[0-9a-zA-Z_\-]{10,}\.[0-9a-zA-Z_\-]{10,}\.[0-9a-zA-Z_\-]{10,}").unwrap(),
        },
        SecretPattern {
            name: "Connection String",
            severity: "medium",
            regex: Regex::new(r#"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'"]+\b"#).unwrap(),
        },
        SecretPattern {
            name: "IP with Port",
            severity: "medium",
            regex: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b").unwrap(),
        },
    ];

    let mut findings: Vec<Finding> = Vec::new();

    for file_id in graph.nodes.keys() {
        if should_skip_file(file_id) {
            continue;
        }
        let path = Path::new(&graph.scan_dir).join(file_id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (line_num, line) in content.lines().enumerate() {
            // Skip comment-only lines that look like documentation/examples
            let trimmed = line.trim();
            if trimmed.starts_with("//") && trimmed.contains("example") {
                continue;
            }

            for pat in &patterns {
                if let Some(m) = pat.regex.find(line) {
                    let matched = m.as_str();
                    let preview = mask_secret(matched);
                    findings.push(Finding {
                        file: file_id.clone(),
                        line: line_num + 1,
                        pattern_name: pat.name.to_string(),
                        severity: pat.severity.to_string(),
                        preview,
                    });
                }
            }
        }
    }

    if findings.is_empty() {
        return "=== Secret Scan ===\nNo hardcoded secrets detected.".to_string();
    }

    // Group by severity
    let mut critical: Vec<&Finding> = Vec::new();
    let mut high: Vec<&Finding> = Vec::new();
    let mut medium: Vec<&Finding> = Vec::new();

    for f in &findings {
        match f.severity.as_str() {
            "critical" => critical.push(f),
            "high" => high.push(f),
            "medium" => medium.push(f),
            _ => medium.push(f),
        }
    }

    let mut lines = vec![
        format!("=== Secret Scan ({} findings) ===", findings.len()),
        format!("  critical: {}  high: {}  medium: {}", critical.len(), high.len(), medium.len()),
        String::new(),
    ];

    if !critical.is_empty() {
        lines.push("CRITICAL:".to_string());
        for f in &critical {
            lines.push(format!("  {} [{}] {}:{} -> {}", "\u{1f534}", f.pattern_name, f.file, f.line, f.preview));
        }
        lines.push(String::new());
    }

    if !high.is_empty() {
        lines.push("HIGH:".to_string());
        for f in &high {
            lines.push(format!("  {} [{}] {}:{} -> {}", "\u{1f7e0}", f.pattern_name, f.file, f.line, f.preview));
        }
        lines.push(String::new());
    }

    if !medium.is_empty() {
        lines.push("MEDIUM:".to_string());
        for f in &medium {
            lines.push(format!("  {} [{}] {}:{} -> {}", "\u{1f7e1}", f.pattern_name, f.file, f.line, f.preview));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

// ── 2. dep_tree ────────────────────────────────────────────────────

struct DepEntry {
    name: String,
    version: String,
    group: String,
}

fn parse_package_json(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return deps,
    };

    for group_name in &["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(obj) = parsed.get(group_name).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                deps.push(DepEntry {
                    name: name.clone(),
                    version: version.as_str().unwrap_or("*").to_string(),
                    group: group_name.to_string(),
                });
            }
        }
    }
    deps
}

fn parse_cargo_toml(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut current_group = String::new();
    let groups = ["[dependencies]", "[dev-dependencies]", "[build-dependencies]"];

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            current_group = trimmed.to_string();
            continue;
        }
        if !groups.iter().any(|g| current_group.starts_with(&g[..g.len()-1])) {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // name = "version" or name = { version = "..." }
        if let Some(eq_pos) = trimmed.find('=') {
            let name = trimmed[..eq_pos].trim().to_string();
            let rest = trimmed[eq_pos + 1..].trim();
            let version = if rest.starts_with('"') {
                rest.trim_matches('"').to_string()
            } else if rest.starts_with('{') {
                // Parse inline table for version (regex hoisted to module-
                // level LazyLock — see CARGO_VERSION_RE)
                CARGO_VERSION_RE.captures(rest)
                    .map(|c| c[1].to_string())
                    .unwrap_or_else(|| "*".to_string())
            } else {
                rest.to_string()
            };
            let group = current_group
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            deps.push(DepEntry { name, version, group });
        }
    }
    deps
}

fn parse_requirements_txt(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let re = Regex::new(r"^([a-zA-Z0-9_-]+)\s*([=<>!~]+\s*\S+)?").unwrap();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if let Some(caps) = re.captures(trimmed) {
            let name = caps[1].to_string();
            let version = caps.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            deps.push(DepEntry { name, version, group: "dependencies".to_string() });
        }
    }
    deps
}

fn parse_go_mod(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut in_require = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }
        if trimmed.starts_with("require ") && !trimmed.contains('(') {
            // single-line require
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                deps.push(DepEntry {
                    name: parts[1].to_string(),
                    version: parts[2].to_string(),
                    group: "require".to_string(),
                });
            }
            continue;
        }
        if in_require {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && !parts[0].starts_with("//") {
                deps.push(DepEntry {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    group: "require".to_string(),
                });
            }
        }
    }
    deps
}

fn parse_pyproject_toml(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    let re = Regex::new(r#"^\s*"([a-zA-Z0-9_-]+)\s*([=<>!~]+\s*\S+)?""#).unwrap();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "dependencies = [" || trimmed.starts_with("dependencies = [") {
            in_deps = true;
            continue;
        }
        if in_deps && trimmed == "]" {
            in_deps = false;
            continue;
        }
        if in_deps {
            if let Some(caps) = re.captures(trimmed) {
                let name = caps[1].to_string();
                let version = caps.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                deps.push(DepEntry { name, version, group: "dependencies".to_string() });
            }
        }
    }
    deps
}

fn parse_pom_xml(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let dep_re = Regex::new(r"<dependency>[\s\S]*?<groupId>([^<]+)</groupId>[\s\S]*?<artifactId>([^<]+)</artifactId>(?:[\s\S]*?<version>([^<]+)</version>)?[\s\S]*?</dependency>").unwrap();
    let scope_re = Regex::new(r"<scope>([^<]+)</scope>").unwrap();
    for caps in dep_re.captures_iter(content) {
        let group_id = caps[1].to_string();
        let artifact_id = caps[2].to_string();
        let version = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
        let full_match = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        let scope = scope_re.captures(full_match)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "compile".to_string());
        deps.push(DepEntry {
            name: format!("{}:{}", group_id, artifact_id),
            version,
            group: scope,
        });
    }
    deps
}

fn parse_gemfile(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let re = Regex::new(r#"gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?"#).unwrap();
    let group_re = Regex::new(r"group\s+:(\w+)").unwrap();
    let mut current_group = "default".to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(gcaps) = group_re.captures(trimmed) {
            current_group = gcaps[1].to_string();
            continue;
        }
        if trimmed == "end" {
            current_group = "default".to_string();
            continue;
        }
        if let Some(caps) = re.captures(trimmed) {
            let name = caps[1].to_string();
            let version = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
            deps.push(DepEntry { name, version, group: current_group.clone() });
        }
    }
    deps
}

fn parse_pipfile(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut current_group = String::new();
    let sections = ["[packages]", "[dev-packages]"];

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            current_group = trimmed.to_string();
            continue;
        }
        if !sections.iter().any(|s| current_group == *s) {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let name = trimmed[..eq_pos].trim().to_string();
            let version = trimmed[eq_pos + 1..].trim().trim_matches('"').to_string();
            let group = current_group.trim_matches('[').trim_matches(']').to_string();
            deps.push(DepEntry { name, version, group });
        }
    }
    deps
}

fn parse_manifest(filename: &str, content: &str) -> Vec<DepEntry> {
    let basename = filename.rsplit('/').next().unwrap_or(filename);
    match basename {
        "package.json" => parse_package_json(content),
        "Cargo.toml" => parse_cargo_toml(content),
        "requirements.txt" => parse_requirements_txt(content),
        "go.mod" => parse_go_mod(content),
        "pyproject.toml" => parse_pyproject_toml(content),
        "pom.xml" => parse_pom_xml(content),
        "Gemfile" => parse_gemfile(content),
        "Pipfile" => parse_pipfile(content),
        _ => Vec::new(),
    }
}

fn is_manifest(filename: &str) -> bool {
    let basename = filename.rsplit('/').next().unwrap_or(filename);
    matches!(basename,
        "package.json" | "Cargo.toml" | "requirements.txt" | "go.mod"
        | "pyproject.toml" | "pom.xml" | "Gemfile" | "Pipfile"
    )
}

pub fn dep_tree(graph: &Graph, target: &str) -> String {
    let mut manifest_deps: BTreeMap<String, Vec<DepEntry>> = BTreeMap::new();

    for file_id in graph.nodes.keys() {
        if !is_manifest(file_id) {
            continue;
        }
        if !target.is_empty() && !file_id.contains(target) && file_id != target {
            continue;
        }
        let path = Path::new(&graph.scan_dir).join(file_id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let deps = parse_manifest(file_id, &content);
        if !deps.is_empty() {
            manifest_deps.insert(file_id.clone(), deps);
        }
    }

    if manifest_deps.is_empty() {
        return if target.is_empty() {
            "=== Dependency Tree ===\nNo package manifests found.".to_string()
        } else {
            format!("=== Dependency Tree ===\nNo manifest matching '{}' found.", target)
        };
    }

    let total_manifests = manifest_deps.len();
    let total_deps: usize = manifest_deps.values().map(|v| v.len()).sum();

    let mut lines = vec![
        format!("=== Dependency Tree ({} manifests, {} deps) ===", total_manifests, total_deps),
        String::new(),
    ];

    for (manifest, deps) in &manifest_deps {
        lines.push(format!("{} ({} deps):", manifest, deps.len()));

        // Group by dep group
        let mut by_group: BTreeMap<&str, Vec<&DepEntry>> = BTreeMap::new();
        for dep in deps {
            by_group.entry(&dep.group).or_default().push(dep);
        }

        for (group, group_deps) in &by_group {
            lines.push(format!("  [{}]", group));
            for dep in group_deps {
                if dep.version.is_empty() {
                    lines.push(format!("    {}", dep.name));
                } else {
                    lines.push(format!("    {} @ {}", dep.name, dep.version));
                }
            }
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

// ── 3. dead_deps ───────────────────────────────────────────────────

pub fn dead_deps(graph: &Graph, _target: &str) -> String {
    // Step 1: Parse all manifests to get declared dependencies
    let mut declared: HashMap<String, (String, String)> = HashMap::new(); // name -> (manifest, group)

    for file_id in graph.nodes.keys() {
        if !is_manifest(file_id) {
            continue;
        }
        let path = Path::new(&graph.scan_dir).join(file_id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let deps = parse_manifest(file_id, &content);
        for dep in deps {
            declared.insert(dep.name.clone(), (file_id.clone(), dep.group.clone()));
        }
    }

    if declared.is_empty() {
        return "=== Dead Dependencies ===\nNo package manifests found.".to_string();
    }

    // Step 2: Collect all import strings from graph nodes
    let mut all_imports: HashSet<String> = HashSet::new();
    for node in graph.nodes.values() {
        for imp in &node.imports {
            all_imports.insert(imp.clone());
            // Also add base package name (e.g., "@scope/pkg/foo" -> "@scope/pkg")
            if imp.starts_with('@') {
                if let Some(slash2) = imp.find('/').and_then(|first| imp[first+1..].find('/').map(|s| first + 1 + s)) {
                    all_imports.insert(imp[..slash2].to_string());
                }
            } else if let Some(slash) = imp.find('/') {
                all_imports.insert(imp[..slash].to_string());
            }
        }
    }

    // Also scan source code for import statements
    let import_re = Regex::new(r#"(?:import|require|from|use|extern crate)\s+['"(]?([a-zA-Z0-9_@/.-]+)"#).unwrap();
    for file_id in graph.nodes.keys() {
        if is_manifest(file_id) {
            continue;
        }
        let path = Path::new(&graph.scan_dir).join(file_id);
        if let Ok(content) = std::fs::read_to_string(&path) {
            for caps in import_re.captures_iter(&content) {
                let import_name = caps[1].to_string();
                all_imports.insert(import_name.clone());
                // Normalize: "some_crate::module" -> "some_crate"
                if let Some(colon) = import_name.find("::") {
                    all_imports.insert(import_name[..colon].to_string());
                }
                if let Some(dot) = import_name.find('.') {
                    all_imports.insert(import_name[..dot].to_string());
                }
            }
        }
    }

    // Step 3: Check each declared dep against imports
    let mut dead: Vec<(String, String, String)> = Vec::new(); // (name, manifest, group)

    for (dep_name, (manifest, group)) in &declared {
        // Normalize crate names: Cargo uses hyphens, Rust uses underscores
        let dep_underscore = dep_name.replace('-', "_");
        let dep_lower = dep_name.to_lowercase();

        let is_used = all_imports.iter().any(|imp| {
            let imp_lower = imp.to_lowercase();
            // Direct match
            imp_lower == dep_lower
                || imp_lower == dep_underscore.to_lowercase()
                // Import starts with package name
                || imp_lower.starts_with(&format!("{}/", dep_lower))
                || imp_lower.starts_with(&format!("{}::", dep_underscore.to_lowercase()))
                || imp_lower.starts_with(&format!("{}.", dep_lower))
                // Package name appears in import
                || imp.contains(dep_name.as_str())
                || imp.contains(dep_underscore.as_str())
        });

        if !is_used {
            dead.push((dep_name.clone(), manifest.clone(), group.clone()));
        }
    }

    dead.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    if dead.is_empty() {
        return format!(
            "=== Dead Dependencies ===\nAll {} declared dependencies appear to be used.",
            declared.len()
        );
    }

    let mut lines = vec![
        format!("=== Dead Dependencies ({}/{} potentially unused) ===", dead.len(), declared.len()),
        String::new(),
    ];

    let mut by_manifest: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for (name, manifest, group) in &dead {
        by_manifest.entry(manifest.as_str()).or_default().push((name.as_str(), group.as_str()));
    }

    for (manifest, deps) in &by_manifest {
        lines.push(format!("{}:", manifest));
        for (name, group) in deps {
            lines.push(format!("  [{}] {} - no imports found", group, name));
        }
        lines.push(String::new());
    }

    lines.push("Note: Some deps may be used at runtime, via macros, or build scripts.".to_string());

    lines.join("\n")
}

// ── 4. api_surface ─────────────────────────────────────────────────

struct ApiEntry {
    file: String,
    name: String,
    params: String,
    line: usize,
    kind: &'static str, // "export", "route", "resolver", "cli"
}

pub fn api_surface(graph: &Graph, target: &str) -> String {
    let mut entries: Vec<ApiEntry> = Vec::new();

    // Route patterns
    let route_patterns = [
        // Python: Flask/FastAPI
        (Regex::new(r#"@(?:app|router|api)\.(get|post|put|delete|patch|head|options)\s*\(\s*['"]([^'"]+)['"]"#).unwrap(), "route"),
        // Python: Flask @app.route
        (Regex::new(r#"@(?:app|bp|blueprint)\.route\s*\(\s*['"]([^'"]+)['"]"#).unwrap(), "route"),
        // Express: router.get('/path', ...)
        (Regex::new(r#"(?:router|app)\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]"#).unwrap(), "route"),
        // CLI: @click.command, argparse, clap
        (Regex::new(r#"@(?:click\.command|cli\.command)\s*\(\s*(?:['"]([^'"]+)['"])?"#).unwrap(), "cli"),
    ];

    let graphql_re = Regex::new(r"(?:Query|Mutation|Subscription)\s*[:{]").unwrap();
    let resolver_fn_re = Regex::new(r"(?:def|function|fn|func|async fn)\s+(\w+)").unwrap();

    for (file_id, node) in &graph.nodes {
        if !target.is_empty() && !file_id.contains(target) && file_id != target {
            continue;
        }

        // Collect exported functions from graph data
        for func in &node.functions {
            if func.is_exported {
                let params = func.parameters.as_ref()
                    .map(|p| p.join(", "))
                    .unwrap_or_default();
                entries.push(ApiEntry {
                    file: file_id.clone(),
                    name: func.name.clone(),
                    params,
                    line: func.start_line,
                    kind: "export",
                });
            }
        }

        // Scan source for routes and CLI commands
        let path = Path::new(&graph.scan_dir).join(file_id);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let content_lines: Vec<&str> = content.lines().collect();

            for (line_num, line) in content_lines.iter().enumerate() {
                let trimmed = line.trim();

                // Check route patterns
                for (re, kind) in &route_patterns {
                    if let Some(caps) = re.captures(trimmed) {
                        let route_path = caps.get(2).or(caps.get(1))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| trimmed.to_string());
                        // Find the function name on the next few lines
                        let fn_name = content_lines.iter().skip(line_num + 1).take(3)
                            .find_map(|next_line| {
                                resolver_fn_re.captures(next_line).map(|c| c[1].to_string())
                            })
                            .unwrap_or_else(|| route_path.clone());
                        entries.push(ApiEntry {
                            file: file_id.clone(),
                            name: format!("{} -> {}", route_path, fn_name),
                            params: String::new(),
                            line: line_num + 1,
                            kind,
                        });
                    }
                }

                // GraphQL resolvers
                if graphql_re.is_match(trimmed) {
                    // Look for resolver functions in the following lines
                    for next in content_lines.iter().skip(line_num + 1).take(20) {
                        if let Some(caps) = resolver_fn_re.captures(next) {
                            entries.push(ApiEntry {
                                file: file_id.clone(),
                                name: caps[1].to_string(),
                                params: String::new(),
                                line: line_num + 1,
                                kind: "resolver",
                            });
                        }
                        if next.trim() == "}" || next.trim().starts_with("type ") {
                            break;
                        }
                    }
                }
            }
        }
    }

    if entries.is_empty() {
        return if target.is_empty() {
            "=== API Surface ===\nNo public API surface detected.".to_string()
        } else {
            format!("=== API Surface ===\nNo public API found matching '{}'.", target)
        };
    }

    // Deduplicate: prefer routes/resolvers over plain exports
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut deduped: Vec<&ApiEntry> = Vec::new();
    // Sort: routes first, then exports
    let priority = |kind: &str| -> u8 {
        match kind { "route" => 0, "resolver" => 1, "cli" => 2, _ => 3 }
    };
    entries.sort_by(|a, b| priority(a.kind).cmp(&priority(b.kind)));

    for entry in &entries {
        let key = (entry.file.clone(), entry.name.clone());
        if seen.insert(key) {
            deduped.push(entry);
        }
    }

    // Group by file
    let mut by_file: BTreeMap<&str, Vec<&ApiEntry>> = BTreeMap::new();
    for entry in &deduped {
        by_file.entry(&entry.file).or_default().push(entry);
    }

    let export_count = deduped.iter().filter(|e| e.kind == "export").count();
    let route_count = deduped.iter().filter(|e| e.kind == "route").count();
    let resolver_count = deduped.iter().filter(|e| e.kind == "resolver").count();
    let cli_count = deduped.iter().filter(|e| e.kind == "cli").count();

    let mut lines = vec![
        format!("=== API Surface ({} entries across {} files) ===", deduped.len(), by_file.len()),
    ];

    let mut summary_parts = Vec::new();
    if export_count > 0 { summary_parts.push(format!("exports: {}", export_count)); }
    if route_count > 0 { summary_parts.push(format!("routes: {}", route_count)); }
    if resolver_count > 0 { summary_parts.push(format!("resolvers: {}", resolver_count)); }
    if cli_count > 0 { summary_parts.push(format!("cli: {}", cli_count)); }
    if !summary_parts.is_empty() {
        lines.push(format!("  {}", summary_parts.join("  ")));
    }
    lines.push(String::new());

    for (file, file_entries) in &by_file {
        lines.push(format!("{}:", file));
        for entry in file_entries {
            let tag = match entry.kind {
                "route" => "[ROUTE]",
                "resolver" => "[GQL]",
                "cli" => "[CLI]",
                _ => "[PUB]",
            };
            if entry.params.is_empty() {
                lines.push(format!("  {} {} (L{})", tag, entry.name, entry.line));
            } else {
                lines.push(format!("  {} {}({}) (L{})", tag, entry.name, entry.params, entry.line));
            }
        }
        lines.push(String::new());
    }

    lines.join("\n")
}
