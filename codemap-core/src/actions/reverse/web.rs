use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use regex::Regex;
use std::sync::LazyLock;
use crate::types::{Graph, EntityKind};

use super::common::*;

/// Heterogeneous-graph helper: register an HTTP endpoint as a typed node.
/// Edges from SourceFile/JsBundle/HAR to the endpoint give us cross-domain
/// queries — e.g. `meta-path SourceFile->HttpEndpoint` traces every code
/// file that ultimately produces an API call.
///
/// `source` is matched against existing scanned source-file IDs. If a
/// source-file node already exists with the same id (the common case
/// when a JS file is both scanned and js-api-extracted), edge from it
/// directly. Otherwise create a new SourceFile node tagged with the
/// path as-is — this lets non-source artifacts (HAR captures, HTML
/// pages outside the scan root) still anchor edges.
fn register_endpoint(graph: &mut Graph, source: &str, method: &str, url: &str) {
    let ep_id = format!("ep:{method}:{url}");
    graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
        ("method", method),
        ("url", url),
        ("first_seen", source),
    ]);
    let src_id = source_node_id(graph, source);
    graph.ensure_typed_node(&src_id, EntityKind::SourceFile, &[("path", source)]);
    graph.add_edge(&src_id, &ep_id);
}

/// Helper: register an HTML form as a WebForm with edges to the source page.
fn register_form(graph: &mut Graph, source: &str, action: &str, method: &str) {
    if action.is_empty() { return; }
    let form_id = format!("form:{method}:{action}");
    graph.ensure_typed_node(&form_id, EntityKind::WebForm, &[
        ("action", action),
        ("method", method),
        ("page", source),
    ]);
    let src_id = source_node_id(graph, source);
    graph.ensure_typed_node(&src_id, EntityKind::SourceFile, &[("path", source)]);
    graph.add_edge(&src_id, &form_id);
}

/// Resolve a `source` path to the canonical node id used by the scanner.
/// The scanner registers source files by their path relative to scan_dir
/// (e.g. "src/api_client.py"); RE actions take an absolute or different
/// relative path. This helper checks if any of: bare source, basename,
/// or stripped-prefix variants matches a scanned node and returns that
/// id. Falls back to "file:<source>" for non-source artifacts (HAR,
/// HTML files outside the scan root) so they still anchor edges.
fn source_node_id(graph: &Graph, source: &str) -> String {
    // Direct hit — most common case once IDs align
    if graph.nodes.contains_key(source) {
        return source.to_string();
    }
    // Try with scan_dir stripped (RE action passed an absolute path)
    if !graph.scan_dir.is_empty() {
        if let Some(rel) = source.strip_prefix(&graph.scan_dir) {
            let rel = rel.trim_start_matches('/');
            if graph.nodes.contains_key(rel) {
                return rel.to_string();
            }
        }
    }
    // Suffix match — covers cases where RE sees a basename and scanner
    // saw a longer relative path (or vice versa)
    let basename = source.rsplit('/').next().unwrap_or(source);
    for id in graph.nodes.keys() {
        if id.ends_with(source) || id.ends_with(&format!("/{basename}")) {
            return id.clone();
        }
    }
    // Fallback: non-source artifact (HAR / HTML capture / external file)
    format!("file:{source}")
}

// ── 1. web_api ────────────────────────────────────────────────────

pub fn web_api(graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => return format!("Invalid JSON in HAR file: {e}"),
    };

    let entries = match json.get("log").and_then(|l| l.get("entries")).and_then(|e| e.as_array()) {
        Some(e) => e,
        None => return "No log.entries found in HAR file.".to_string(),
    };

    if entries.is_empty() {
        return "No entries in HAR file.".to_string();
    }

    // Collect endpoint data
    let mut endpoints: HashMap<(String, String), HarEndpoint> = HashMap::new();
    let mut static_assets: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    let mut auth_headers: BTreeSet<String> = BTreeSet::new();
    let mut base_urls: HashMap<String, usize> = HashMap::new();
    let mut total_requests = 0usize;

    let static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ];

    for entry in entries {
        let request = match entry.get("request") {
            Some(r) => r,
            None => continue,
        };
        let response = match entry.get("response") {
            Some(r) => r,
            None => continue,
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_uppercase();
        let url_str = match request.get("url").and_then(|u| u.as_str()) {
            Some(u) => u,
            None => continue,
        };

        total_requests += 1;

        // Parse URL manually
        let (base_url, path_str, _query) = parse_url_simple(url_str);
        if !base_url.is_empty() {
            *base_urls.entry(base_url.clone()).or_insert(0) += 1;
        }

        // Check for auth headers
        if let Some(headers) = request.get("headers").and_then(|h| h.as_array()) {
            for header in headers {
                let name = header.get("name").and_then(|n| n.as_str()).unwrap_or("").to_ascii_lowercase();
                if name == "authorization" {
                    let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if val.to_ascii_lowercase().starts_with("bearer") {
                        auth_headers.insert("Bearer token in Authorization header".to_string());
                    } else if val.to_ascii_lowercase().starts_with("basic") {
                        auth_headers.insert("Basic auth in Authorization header".to_string());
                    } else {
                        auth_headers.insert("Authorization header".to_string());
                    }
                } else if name == "x-api-key" {
                    auth_headers.insert("X-API-Key header".to_string());
                } else if name == "cookie" {
                    let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if val.contains("session") || val.contains("token") || val.contains("auth") {
                        auth_headers.insert("Session cookie".to_string());
                    }
                }
            }
        }

        // Check if this is a static asset
        let path_lower = path_str.to_ascii_lowercase();
        let is_static = static_extensions.iter().any(|ext| path_lower.ends_with(ext));

        if is_static {
            let ext = if let Some(dot_pos) = path_lower.rfind('.') {
                path_lower[dot_pos..].to_string()
            } else {
                ".other".to_string()
            };
            let size = response.get("content")
                .and_then(|c| c.get("size"))
                .and_then(|s| s.as_u64())
                .unwrap_or(0) as usize;
            static_assets.entry(ext).or_default().push((path_str.clone(), size));
            continue;
        }

        // Normalize path: replace numeric segments and UUIDs with {id}
        let normalized = normalize_api_path(&path_str);

        let key = (method.clone(), normalized.clone());
        let ep = endpoints.entry(key).or_insert_with(|| HarEndpoint {
            method: method.clone(),
            path: normalized,
            query_params: BTreeSet::new(),
            body_fields: BTreeSet::new(),
            status_codes: BTreeSet::new(),
            content_types: BTreeSet::new(),
            total_time: 0.0,
            call_count: 0,
        });

        ep.call_count += 1;

        // Query parameters
        if let Some(qs) = request.get("queryString").and_then(|q| q.as_array()) {
            for param in qs {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    ep.query_params.insert(name.to_string());
                }
            }
        }

        // Request body fields (JSON only, first level)
        if let Some(post_data) = request.get("postData") {
            let mime = post_data.get("mimeType").and_then(|m| m.as_str()).unwrap_or("");
            if mime.contains("json") {
                if let Some(text) = post_data.get("text").and_then(|t| t.as_str()) {
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(text) {
                        if let Some(obj) = body.as_object() {
                            for key in obj.keys() {
                                ep.body_fields.insert(key.clone());
                            }
                        }
                    }
                }
            }
        }

        // Response status
        let status = response.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
        if status > 0 {
            ep.status_codes.insert(status);
        }

        // Response content type
        if let Some(content) = response.get("content") {
            if let Some(mime) = content.get("mimeType").and_then(|m| m.as_str()) {
                let clean_mime = mime.split(';').next().unwrap_or(mime).trim().to_string();
                if !clean_mime.is_empty() {
                    ep.content_types.insert(clean_mime);
                }
            }
        }

        // Response time
        let time = entry.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
        ep.total_time += time;
    }

    if endpoints.is_empty() && static_assets.is_empty() {
        return "No API endpoints or static assets found in HAR file.".to_string();
    }

    // Pass: register every parsed endpoint so other passes (web_blueprint,
    // js_api_extract) can deduplicate against the same nodes, and
    // graph-theory actions can find the central endpoints.
    for ep in endpoints.values() {
        register_endpoint(graph, target, &ep.method, &ep.path);
    }

    // Determine primary base URL
    let primary_base = base_urls.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(url, _)| url.clone())
        .unwrap_or_default();

    // Sort endpoints by path then method
    let mut sorted_eps: Vec<&HarEndpoint> = endpoints.values().collect();
    sorted_eps.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    // Build output
    let mut out = String::new();
    out.push_str("=== Web API Analysis ===\n\n");

    let filename = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| target.to_string());
    out.push_str(&format!("Source: {filename}\n"));
    if !primary_base.is_empty() {
        out.push_str(&format!("Base URL: {primary_base}\n"));
    }
    out.push_str(&format!("Endpoints: {}\n", endpoints.len()));
    out.push_str(&format!("Total requests: {total_requests}\n\n"));

    // Endpoint details
    for ep in &sorted_eps {
        let avg_ms = if ep.call_count > 0 { ep.total_time / ep.call_count as f64 } else { 0.0 };
        out.push_str(&format!("── {} {} ({} calls, avg {:.0}ms) ──\n", ep.method, ep.path, ep.call_count, avg_ms));

        if !ep.query_params.is_empty() {
            let params: Vec<&str> = ep.query_params.iter().map(|s| s.as_str()).collect();
            out.push_str(&format!("  Query params: {}\n", params.join(", ")));
        }

        if !ep.body_fields.is_empty() {
            let fields: Vec<&str> = ep.body_fields.iter().map(|s| s.as_str()).collect();
            out.push_str(&format!("  Body fields: {}\n", fields.join(", ")));
        }

        if !ep.status_codes.is_empty() {
            let status_parts: Vec<String> = ep.status_codes.iter().map(|s| {
                let ct: Vec<&str> = ep.content_types.iter().map(|c| c.as_str()).collect();
                if ct.is_empty() {
                    format!("{s}")
                } else {
                    format!("{s} ({})", ct.join(", "))
                }
            }).collect();
            out.push_str(&format!("  Response: {}\n", status_parts.join(", ")));
        }

        out.push('\n');
    }

    // API Summary
    out.push_str("=== API Summary ===\n");

    // Infer resources from paths
    let mut resources: HashMap<String, [bool; 4]> = HashMap::new(); // [create, read, update, delete]
    for ep in &sorted_eps {
        let segments: Vec<&str> = ep.path.split('/').filter(|s| !s.is_empty() && *s != "{id}").collect();
        if let Some(resource) = segments.last() {
            let resource = resource.to_string();
            let crud = resources.entry(resource).or_insert([false; 4]);
            match ep.method.as_str() {
                "POST" => crud[0] = true,
                "GET" => crud[1] = true,
                "PUT" | "PATCH" => crud[2] = true,
                "DELETE" => crud[3] = true,
                _ => {}
            }
        }
    }

    if !resources.is_empty() {
        let mut res_names: Vec<&String> = resources.keys().collect();
        res_names.sort();
        out.push_str(&format!("  Resources: {}\n", res_names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    if !auth_headers.is_empty() {
        for auth in &auth_headers {
            out.push_str(&format!("  Auth pattern: {auth}\n"));
        }
    }

    if !resources.is_empty() {
        out.push_str("  CRUD coverage:\n");
        let mut res_vec: Vec<(&String, &[bool; 4])> = resources.iter().collect();
        res_vec.sort_by_key(|(name, _)| name.to_ascii_lowercase());
        let max_name_len = res_vec.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (name, crud) in &res_vec {
            let c = if crud[0] { "\u{2713}" } else { "\u{2717}" };
            let r = if crud[1] { "\u{2713}" } else { "\u{2717}" };
            let u = if crud[2] { "\u{2713}" } else { "\u{2717}" };
            let d = if crud[3] { "\u{2713}" } else { "\u{2717}" };
            out.push_str(&format!("    {:width$}  CREATE {}  READ {}  UPDATE {}  DELETE {}\n",
                name, c, r, u, d, width = max_name_len));
        }
    }
    out.push('\n');

    // Static assets summary
    if !static_assets.is_empty() {
        out.push_str("=== Static Assets ===\n");

        let asset_categories: &[(&str, &[&str])] = &[
            ("JavaScript", &[".js"]),
            ("CSS", &[".css"]),
            ("Images", &[".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico"]),
            ("Fonts", &[".woff", ".woff2", ".ttf", ".eot"]),
        ];

        for (label, exts) in asset_categories {
            let mut count = 0usize;
            let mut total_size = 0usize;
            for ext in *exts {
                if let Some(assets) = static_assets.get(&ext.to_string()) {
                    count += assets.len();
                    total_size += assets.iter().map(|(_, s)| s).sum::<usize>();
                }
            }
            if count > 0 {
                out.push_str(&format!("  {label}: {count} files ({})\n", format_file_size(total_size)));
            }
        }

        // Other static assets
        let known_exts: BTreeSet<&str> = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".eot"].iter().copied().collect();
        let mut other_count = 0usize;
        let mut other_size = 0usize;
        for (ext, assets) in &static_assets {
            if !known_exts.contains(ext.as_str()) {
                other_count += assets.len();
                other_size += assets.iter().map(|(_, s)| s).sum::<usize>();
            }
        }
        if other_count > 0 {
            out.push_str(&format!("  Other: {other_count} files ({})\n", format_file_size(other_size)));
        }
    }

    out
}

struct HarEndpoint {
    method: String,
    path: String,
    query_params: BTreeSet<String>,
    body_fields: BTreeSet<String>,
    status_codes: BTreeSet<u16>,
    content_types: BTreeSet<String>,
    total_time: f64,
    call_count: usize,
}

fn parse_url_simple(url: &str) -> (String, String, String) {
    // Returns (base_url, path, query)
    let (scheme_host, rest) = if let Some(pos) = url.find("://") {
        let after_scheme = &url[pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            let base = &url[..pos + 3 + slash_pos];
            let rest = &after_scheme[slash_pos..];
            (base.to_string(), rest.to_string())
        } else {
            (url.to_string(), "/".to_string())
        }
    } else {
        (String::new(), url.to_string())
    };

    // Split path and query
    let (path, query) = if let Some(q_pos) = rest.find('?') {
        (rest[..q_pos].to_string(), rest[q_pos + 1..].to_string())
    } else {
        (rest, String::new())
    };

    (scheme_host, path, query)
}

fn normalize_api_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments.iter().map(|seg| {
        if seg.is_empty() {
            String::new()
        } else if is_id_segment(seg) {
            "{id}".to_string()
        } else {
            seg.to_string()
        }
    }).collect();
    normalized.join("/")
}

fn is_id_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }

    // All digits
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // UUID-like: hex chars and dashes, 32+ chars (e.g. 550e8400-e29b-41d4-a716-446655440000)
    if seg.len() >= 32 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }

    false
}

// ── 2. web_dom ────────────────────────────────────────────────────

pub fn web_dom(graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let filename = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| target.to_string());

    // Count total elements by tag
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    let total_elements = count_html_tags(&content, &mut tag_counts);

    // Extract forms
    let forms = extract_forms(&content);

    // Pass: register every form action as a WebForm node with edge to the
    // page that contains it. After this you can `pagerank --type form` to
    // find the most-used form action endpoints.
    for form in &forms {
        register_form(graph, target, &form.action, &form.method);
    }

    // Extract tables
    let tables = extract_tables(&content);

    // Extract navigation
    let navs = extract_navs(&content);

    // Extract buttons
    let buttons = extract_buttons(&content);

    // Extract click handlers
    let click_count = count_click_handlers(&content);

    // Extract modals/dialogs
    let modal_count = count_component_patterns(&content, &["modal", "dialog", "popup", "overlay"]);

    // Extract script sources
    let scripts = extract_script_srcs(&content);

    // Extract iframes
    let iframes = extract_iframes(&content);

    // Extract API references from inline JS
    let api_refs = extract_inline_api_refs(&content);

    // Extract data attributes
    let data_attrs = extract_data_attributes(&content);

    // Extract links
    let links = extract_links(&content);

    // Build output
    let mut out = String::new();
    out.push_str("=== Web DOM Analysis ===\n\n");
    out.push_str(&format!("File: {filename}\n"));
    out.push_str(&format!("Total elements: {total_elements}\n\n"));

    // Forms
    if !forms.is_empty() {
        out.push_str(&format!("── Forms ({}) ──\n", forms.len()));
        for form in &forms {
            let id_or_class = if !form.id.is_empty() {
                format!("#{}", form.id)
            } else if !form.class.is_empty() {
                format!(".{}", form.class)
            } else {
                "(unnamed)".to_string()
            };

            let method_action = if !form.action.is_empty() {
                format!("{} {}", form.method.to_uppercase(), form.action)
            } else {
                form.method.to_uppercase()
            };
            out.push_str(&format!("  {} ({})\n", id_or_class, method_action));

            for field in &form.fields {
                let mut desc = format!("    {}: {}", field.name, field.field_type);
                if field.required {
                    desc.push_str(" (required)");
                }
                if !field.placeholder.is_empty() {
                    desc.push_str(&format!(" (placeholder: \"{}\")", field.placeholder));
                }
                out.push_str(&format!("{desc}\n"));
            }
            out.push('\n');
        }
    }

    // Tables
    if !tables.is_empty() {
        out.push_str(&format!("── Tables ({}) ──\n", tables.len()));
        for table in &tables {
            let id_or_class = if !table.id.is_empty() {
                format!("#{}", table.id)
            } else if !table.class.is_empty() {
                format!(".{}", table.class)
            } else {
                "(unnamed)".to_string()
            };
            if !table.headers.is_empty() {
                out.push_str(&format!("  {}: {}\n", id_or_class, table.headers.join(", ")));
            } else {
                out.push_str(&format!("  {} (no headers)\n", id_or_class));
            }
        }
        out.push('\n');
    }

    // Navigation
    if !navs.is_empty() {
        out.push_str("── Navigation ──\n");
        for nav in &navs {
            let nav_id = if !nav.class.is_empty() {
                format!("<nav class=\"{}\">", nav.class)
            } else if !nav.id.is_empty() {
                format!("<nav id=\"{}\">", nav.id)
            } else {
                "<nav>".to_string()
            };
            out.push_str(&format!("  {nav_id}\n"));
            for (text, href) in &nav.links {
                out.push_str(&format!("    {text} -> {href}\n"));
            }
        }
        out.push('\n');
    }

    // Interactive elements
    let button_count = buttons.len();
    if button_count > 0 || click_count > 0 || modal_count > 0 {
        out.push_str("── Interactive Elements ──\n");
        if button_count > 0 {
            out.push_str(&format!("  Buttons: {button_count}\n"));
        }
        if click_count > 0 {
            out.push_str(&format!("  Click handlers: {click_count}\n"));
        }
        if modal_count > 0 {
            out.push_str(&format!("  Modals/Dialogs: {modal_count}\n"));
        }
        out.push('\n');
    }

    // Scripts
    if !scripts.is_empty() {
        out.push_str("── Scripts ──\n");
        for src in &scripts {
            out.push_str(&format!("  {src}\n"));
        }
        out.push('\n');
    }

    // Iframes
    if !iframes.is_empty() {
        out.push_str(&format!("── Iframes ({}) ──\n", iframes.len()));
        for src in &iframes {
            out.push_str(&format!("  {src}\n"));
        }
        out.push('\n');
    }

    // API references from inline JS
    if !api_refs.is_empty() {
        out.push_str("── API References (from inline JS) ──\n");
        for ref_str in &api_refs {
            out.push_str(&format!("  {ref_str}\n"));
        }
        out.push('\n');
    }

    // Data attributes
    if !data_attrs.is_empty() {
        out.push_str(&format!("── Data Attributes ({}) ──\n", data_attrs.len()));
        for attr in data_attrs.iter().take(50) {
            out.push_str(&format!("  {attr}\n"));
        }
        out.push('\n');
    }

    // Links summary
    if !links.is_empty() {
        let internal: Vec<&(String, String)> = links.iter().filter(|(_, href)| !href.starts_with("http://") && !href.starts_with("https://") && !href.starts_with("//")).collect();
        let external: Vec<&(String, String)> = links.iter().filter(|(_, href)| href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//")).collect();
        out.push_str(&format!("── Links ({} internal, {} external) ──\n", internal.len(), external.len()));
        for (text, href) in internal.iter().take(30) {
            if !text.is_empty() {
                out.push_str(&format!("  {text} -> {href}\n"));
            } else {
                out.push_str(&format!("  {href}\n"));
            }
        }
        if internal.len() > 30 {
            out.push_str(&format!("  ... and {} more\n", internal.len() - 30));
        }
        out.push('\n');
    }

    out
}

struct HtmlForm {
    id: String,
    class: String,
    action: String,
    method: String,
    fields: Vec<HtmlFormField>,
}

struct HtmlFormField {
    name: String,
    field_type: String,
    required: bool,
    placeholder: String,
}

struct HtmlTable {
    id: String,
    class: String,
    headers: Vec<String>,
}

struct HtmlNav {
    id: String,
    class: String,
    links: Vec<(String, String)>, // (text, href)
}

fn count_html_tags(content: &str, tag_counts: &mut HashMap<String, usize>) -> usize {
    let mut total = 0usize;
    let mut i = 0;
    let bytes = content.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() && bytes[i + 1] != b'/' && bytes[i + 1] != b'!' {
            // Find tag name
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b' ' && bytes[end] != b'>' && bytes[end] != b'/' && bytes[end] != b'\n' {
                end += 1;
            }
            if end > start {
                let tag = content[start..end].to_ascii_lowercase();
                if tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && tag.len() <= 20 {
                    *tag_counts.entry(tag).or_insert(0) += 1;
                    total += 1;
                }
            }
        }
        i += 1;
    }

    total
}

fn extract_forms(content: &str) -> Vec<HtmlForm> {
    let mut forms = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(form_start) = lower[search_from..].find("<form") {
        let abs_start = search_from + form_start;
        let form_tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 5; continue; }
        };

        let form_tag = &content[abs_start..=form_tag_end];

        let id = extract_attr_value(form_tag, "id");
        let class = extract_attr_value(form_tag, "class");
        let action = extract_attr_value(form_tag, "action");
        let method = extract_attr_value(form_tag, "method");
        let method = if method.is_empty() { "GET".to_string() } else { method };

        // No closing </form> means a malformed tag — stop scanning rather than
        // pretend the rest of the document is the form body (which would also
        // make `search_from = form_end + 1` exceed `lower.len()` next iteration).
        let Some(form_end_off) = lower[form_tag_end..].find("</form") else { break };
        let form_end = form_tag_end + form_end_off;
        let form_body = &content[form_tag_end..form_end];

        let fields = extract_form_fields(form_body);

        forms.push(HtmlForm {
            id,
            class,
            action,
            method,
            fields,
        });

        search_from = form_end + 1;
    }

    forms
}

fn extract_form_fields(body: &str) -> Vec<HtmlFormField> {
    let mut fields = Vec::new();
    let lower = body.to_ascii_lowercase();

    // Find <input> elements
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<input") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let field_type = extract_attr_value(tag, "type");
        let field_type = if field_type.is_empty() { "text".to_string() } else { field_type };
        let placeholder = extract_attr_value(tag, "placeholder");
        let required = tag.to_ascii_lowercase().contains("required");

        if !name.is_empty() || !field_type.is_empty() {
            fields.push(HtmlFormField {
                name: if name.is_empty() { "(unnamed)".to_string() } else { name },
                field_type,
                required,
                placeholder,
            });
        }
        pos = tag_end + 1;
    }

    // Find <select> elements
    pos = 0;
    while let Some(start) = lower[pos..].find("<select") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let required = tag.to_ascii_lowercase().contains("required");

        fields.push(HtmlFormField {
            name: if name.is_empty() { "(unnamed)".to_string() } else { name },
            field_type: "select".to_string(),
            required,
            placeholder: String::new(),
        });
        pos = tag_end + 1;
    }

    // Find <textarea> elements
    pos = 0;
    while let Some(start) = lower[pos..].find("<textarea") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let placeholder = extract_attr_value(tag, "placeholder");
        let required = tag.to_ascii_lowercase().contains("required");

        fields.push(HtmlFormField {
            name: if name.is_empty() { "(unnamed)".to_string() } else { name },
            field_type: "textarea".to_string(),
            required,
            placeholder,
        });
        pos = tag_end + 1;
    }

    fields
}

fn extract_attr_value(tag: &str, attr: &str) -> String {
    let lower = tag.to_ascii_lowercase();
    // Try: attr="value" or attr='value'
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        if let Some(start) = lower.find(&pattern) {
            let val_start = start + pattern.len();
            if val_start < tag.len() {
                if let Some(end) = tag[val_start..].find(quote) {
                    return tag[val_start..val_start + end].to_string();
                }
            }
        }
    }
    // Try: attr=value (no quotes, up to space or >)
    let pattern = format!("{attr}=");
    if let Some(start) = lower.find(&pattern) {
        let val_start = start + pattern.len();
        if val_start < tag.len() {
            let rest = &tag[val_start..];
            let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
            let val = &rest[..end];
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    String::new()
}

fn extract_tables(content: &str) -> Vec<HtmlTable> {
    let mut tables = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(table_start) = lower[search_from..].find("<table") {
        let abs_start = search_from + table_start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 6; continue; }
        };

        let table_tag = &content[abs_start..=tag_end];
        let id = extract_attr_value(table_tag, "id");
        let class = extract_attr_value(table_tag, "class");

        // No closing </table> means a malformed tag — stop scanning.
        let Some(table_end_off) = lower[tag_end..].find("</table") else { break };
        let table_end = tag_end + table_end_off;
        let table_body = &content[tag_end..table_end];

        // Extract <th> headers
        let mut headers = Vec::new();
        let table_lower = table_body.to_ascii_lowercase();
        let mut th_pos = 0;
        while th_pos < table_lower.len() {
            let Some(th_start) = table_lower[th_pos..].find("<th") else { break };
            let abs_th = th_pos + th_start;
            let th_tag_end = match table_lower[abs_th..].find('>') {
                Some(e) => abs_th + e + 1,
                None => break,
            };
            let Some(th_close_off) = table_lower[th_tag_end..].find("</th") else { break };
            let th_close = th_tag_end + th_close_off;
            let header_text = strip_html_tags(&table_body[th_tag_end..th_close]).trim().to_string();
            if !header_text.is_empty() {
                headers.push(header_text);
            }
            th_pos = th_close + 1;
        }

        tables.push(HtmlTable { id, class, headers });

        search_from = table_end + 1;
    }

    tables
}

fn strip_html_tags(s: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(c);
        }
    }
    result
}

fn extract_navs(content: &str) -> Vec<HtmlNav> {
    let mut navs = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(nav_start) = lower[search_from..].find("<nav") {
        let abs_start = search_from + nav_start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 4; continue; }
        };

        let nav_tag = &content[abs_start..=tag_end];
        let id = extract_attr_value(nav_tag, "id");
        let class = extract_attr_value(nav_tag, "class");

        // No closing </nav> means a malformed tag — stop scanning.
        let Some(nav_end_off) = lower[tag_end..].find("</nav") else { break };
        let nav_end = tag_end + nav_end_off;
        let nav_body = &content[tag_end..nav_end];

        let links = extract_links(nav_body);

        navs.push(HtmlNav { id, class, links });

        search_from = nav_end + 1;
    }

    navs
}

fn extract_buttons(content: &str) -> Vec<String> {
    let mut buttons = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut pos = 0;

    while pos < lower.len() {
        let Some(start) = lower[pos..].find("<button") else { break };
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e + 1,
            None => break,
        };
        // No closing </button> means a malformed tag — stop scanning rather than
        // pretend the rest of the document is the button body.
        let Some(close_off) = lower[tag_end..].find("</button") else { break };
        let close = tag_end + close_off;
        let text = strip_html_tags(&content[tag_end..close]).trim().to_string();
        if !text.is_empty() {
            buttons.push(text);
        }
        pos = close + 1;
    }

    buttons
}

fn count_click_handlers(content: &str) -> usize {
    let lower = content.to_ascii_lowercase();
    let patterns = ["onclick=", "@click=", "v-on:click=", "(click)="];
    patterns.iter().map(|p| lower.matches(p).count()).sum()
}

fn count_component_patterns(content: &str, patterns: &[&str]) -> usize {
    let lower = content.to_ascii_lowercase();
    let mut count = 0usize;
    for pat in patterns {
        // Look for class="...modal..." or id="...modal..." etc.
        let class_pat = "class=\"".to_string();
        let mut pos = 0;
        while let Some(start) = lower[pos..].find(&class_pat) {
            let abs_start = pos + start + class_pat.len();
            if let Some(end) = lower[abs_start..].find('"') {
                let class_val = &lower[abs_start..abs_start + end];
                if class_val.contains(pat) {
                    count += 1;
                }
            }
            pos = abs_start + 1;
        }
    }
    count
}

fn extract_script_srcs(content: &str) -> Vec<String> {
    let mut srcs = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<script") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &content[abs_start..=tag_end];
        let src = extract_attr_value(tag, "src");
        if !src.is_empty() {
            srcs.push(src);
        }
        pos = tag_end + 1;
    }

    srcs
}

fn extract_iframes(content: &str) -> Vec<String> {
    let mut iframes = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<iframe") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &content[abs_start..=tag_end];
        let src = extract_attr_value(tag, "src");
        if !src.is_empty() {
            iframes.push(src);
        } else {
            iframes.push("(no src)".to_string());
        }
        pos = tag_end + 1;
    }

    iframes
}

fn extract_inline_api_refs(content: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();

    // Look for fetch('...'), fetch("..."), axios.get('...'), axios.post('...'), etc.
    let patterns = [
        "fetch(", "fetch (", "axios.get(", "axios.post(", "axios.put(",
        "axios.delete(", "axios.patch(", "axios(",
        "XMLHttpRequest", ".open(",
    ];

    for line in content.lines() {
        let trimmed = line.trim();
        for pat in &patterns {
            if let Some(pos) = trimmed.find(pat) {
                // Try to extract the URL argument
                let after = &trimmed[pos + pat.len()..];
                if let Some(url) = extract_string_arg(after) {
                    if url.starts_with('/') || url.starts_with("http") {
                        refs.insert(format!("{}{}", &pat[..pat.len().saturating_sub(1)].trim_end_matches('.'), format!("('{url}')")));
                    }
                }
            }
        }
    }

    refs
}

fn extract_string_arg(s: &str) -> Option<String> {
    let trimmed = s.trim();
    for quote in ['"', '\'', '`'] {
        if trimmed.starts_with(quote) {
            let rest = &trimmed[1..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn extract_data_attributes(content: &str) -> BTreeSet<String> {
    let mut attrs = BTreeSet::new();
    // Simple regex-like scan for data-xxx= patterns
    let bytes = content.as_bytes();
    let prefix = b"data-";

    let mut i = 0;
    while i + prefix.len() < bytes.len() {
        if bytes[i..].starts_with(prefix) {
            // Check it's preceded by space (part of an HTML attribute)
            if i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\n' || bytes[i - 1] == b'\t') {
                let start = i;
                let mut end = i + prefix.len();
                while end < bytes.len() && bytes[end] != b'=' && bytes[end] != b' ' && bytes[end] != b'>' && bytes[end] != b'\n' {
                    end += 1;
                }
                let attr = &content[start..end];
                if attr.len() > 5 && attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    attrs.insert(attr.to_string());
                }
            }
        }
        i += 1;
    }

    attrs
}

fn extract_links(content: &str) -> Vec<(String, String)> {
    let mut links = Vec::new();
    let lower = content.to_ascii_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<a ") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e + 1,
            None => break,
        };
        let tag = &content[abs_start..tag_end];
        let href = extract_attr_value(tag, "href");

        // Get link text (up to </a>)
        let close = lower[tag_end..].find("</a").map(|e| tag_end + e).unwrap_or(content.len().min(tag_end + 200));
        let text = strip_html_tags(&content[tag_end..close]).trim().to_string();
        let text = if text.len() > 60 { format!("{}...", &text[..57]) } else { text };

        if !href.is_empty() && href != "#" {
            links.push((text, href));
        }
        pos = tag_end;
    }

    links
}

// ── 3. web_sitemap ────────────────────────────────────────────────

pub fn web_sitemap(graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("Path not found: {target}");
    }

    // Collect HTML files
    let html_files = if path.is_dir() {
        collect_html_files(path)
    } else {
        vec![path.to_path_buf()]
    };

    if html_files.is_empty() {
        return "No HTML files found.".to_string();
    }

    // Parse each file
    let mut pages: HashMap<String, SitemapPage> = HashMap::new();

    for file in &html_files {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Derive a page path from the file path relative to root
        let page_path = if path.is_dir() {
            file.strip_prefix(path)
                .map(|p| {
                    let s = p.to_string_lossy().to_string();
                    let s = s.replace('\\', "/");
                    // index.html -> /
                    if s == "index.html" || s == "index.htm" {
                        "/".to_string()
                    } else {
                        let s = s.trim_end_matches("/index.html").trim_end_matches("/index.htm");
                        format!("/{s}")
                    }
                })
                .unwrap_or_else(|_| file.to_string_lossy().to_string())
        } else {
            file.file_name().map(|f| format!("/{}", f.to_string_lossy())).unwrap_or_else(|| "/".to_string())
        };

        // Extract title
        let title = extract_title(&content);

        // Extract all links
        let links = extract_links(&content);

        // Extract form actions
        let forms = extract_forms(&content);
        let form_urls: Vec<String> = forms.iter()
            .filter(|f| !f.action.is_empty())
            .map(|f| f.action.clone())
            .collect();

        // Separate internal vs external links
        let mut internal_links: Vec<String> = Vec::new();
        let mut external_links: Vec<String> = Vec::new();

        for (_, href) in &links {
            let href = href.split('#').next().unwrap_or(href).to_string();
            let href = href.split('?').next().unwrap_or(&href).to_string();
            if href.is_empty() || href == "/" && page_path == "/" {
                continue;
            }
            if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
                external_links.push(href);
            } else if href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("javascript:") {
                continue;
            } else {
                internal_links.push(href);
            }
        }

        for url in &form_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                internal_links.push(url.clone());
            }
        }

        internal_links.sort();
        internal_links.dedup();
        external_links.sort();
        external_links.dedup();

        pages.insert(page_path, SitemapPage {
            title,
            internal_links,
            external_links,
        });
    }

    if pages.is_empty() {
        return "No pages parsed.".to_string();
    }

    // Pass: register every page as a SourceFile (HTML *is* source) and
    // every internal link as an edge. Now `pagerank` over these nodes
    // surfaces the most-linked-to pages — equivalent to old-school SEO
    // PageRank on a static site, but reusing the same graph algorithms
    // codemap already ships.
    for (page_path, page) in &pages {
        let pid = format!("page:{page_path}");
        graph.ensure_typed_node(&pid, EntityKind::SourceFile, &[
            ("path", page_path), ("title", &page.title),
        ]);
    }
    for (page_path, page) in &pages {
        let from = format!("page:{page_path}");
        for link in &page.internal_links {
            let to = format!("page:{link}");
            // Only add edge if both endpoints exist (target page may be
            // outside the scanned dir).
            if pages.contains_key(link) {
                graph.add_edge(&from, &to);
            }
        }
    }

    // Count incoming links for each page
    let mut incoming_count: HashMap<String, usize> = HashMap::new();
    for page in pages.values() {
        for link in &page.internal_links {
            *incoming_count.entry(link.clone()).or_insert(0) += 1;
        }
    }

    let total_internal: usize = pages.values().map(|p| p.internal_links.len()).sum();
    let total_external: usize = pages.values().map(|p| p.external_links.len()).sum();

    // Build output
    let mut out = String::new();
    out.push_str("=== Web Sitemap ===\n\n");
    out.push_str(&format!("Pages: {}\n", pages.len()));
    out.push_str(&format!("Internal links: {total_internal}\n"));
    out.push_str(&format!("External links: {total_external}\n\n"));

    // Site structure: build tree from paths
    out.push_str("── Site Structure ──\n");
    let mut sorted_pages: Vec<(&String, &SitemapPage)> = pages.iter().collect();
    sorted_pages.sort_by_key(|(path, _)| path.to_ascii_lowercase());

    for (page_path, page) in &sorted_pages {
        let depth = page_path.matches('/').count().saturating_sub(1);
        let indent = "  ".repeat(depth + 1);
        let title_str = if !page.title.is_empty() {
            format!(" ({})", page.title)
        } else {
            String::new()
        };
        out.push_str(&format!("{indent}{page_path}{title_str} -> {} links\n", page.internal_links.len()));
    }
    out.push('\n');

    // Hub pages (most outgoing links)
    let mut hubs: Vec<(&String, usize)> = pages.iter()
        .map(|(path, page)| (path, page.internal_links.len()))
        .filter(|(_, count)| *count > 0)
        .collect();
    hubs.sort_by(|a, b| b.1.cmp(&a.1));

    if !hubs.is_empty() {
        out.push_str("── Hub Pages (most links) ──\n");
        for (path, count) in hubs.iter().take(10) {
            out.push_str(&format!("  {path}: {count} outgoing links\n"));
        }
        out.push('\n');
    }

    // Entry points (no incoming internal links)
    let entry_points: Vec<&String> = pages.keys()
        .filter(|path| incoming_count.get(*path).copied().unwrap_or(0) == 0)
        .collect();

    if !entry_points.is_empty() {
        out.push_str("── Entry Points (no incoming links) ──\n");
        for path in &entry_points {
            out.push_str(&format!("  {path}\n"));
        }
        out.push('\n');
    }

    // Dead ends (no outgoing internal links)
    let dead_ends: Vec<&String> = pages.iter()
        .filter(|(_, page)| page.internal_links.is_empty())
        .map(|(path, _)| path)
        .collect();

    if !dead_ends.is_empty() {
        out.push_str("── Dead Ends (no outgoing internal links) ──\n");
        for path in &dead_ends {
            out.push_str(&format!("  {path}\n"));
        }
        out.push('\n');
    }

    // External links summary
    let mut ext_domains: HashMap<String, usize> = HashMap::new();
    for page in pages.values() {
        for link in &page.external_links {
            let domain = extract_domain_from_url(link);
            if !domain.is_empty() {
                *ext_domains.entry(domain).or_insert(0) += 1;
            }
        }
    }

    if !ext_domains.is_empty() {
        out.push_str("── External Links ──\n");
        let mut ext_sorted: Vec<(&String, &usize)> = ext_domains.iter().collect();
        ext_sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (domain, count) in ext_sorted.iter().take(20) {
            out.push_str(&format!("  {domain}: {count} references\n"));
        }
        out.push('\n');
    }

    out
}

struct SitemapPage {
    title: String,
    internal_links: Vec<String>,
    external_links: Vec<String>,
}

fn collect_html_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_html_files(&path));
            } else if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_ascii_lowercase();
                if ext == "html" || ext == "htm" {
                    files.push(path);
                }
            }
        }
    }
    files
}

fn extract_title(content: &str) -> String {
    let lower = content.to_ascii_lowercase();
    if let Some(start) = lower.find("<title") {
        if let Some(tag_end) = lower[start..].find('>') {
            let after = start + tag_end + 1;
            if let Some(close) = lower[after..].find("</title") {
                let title = content[after..after + close].trim().to_string();
                return strip_html_tags(&title);
            }
        }
    }
    String::new()
}

fn extract_domain_from_url(url: &str) -> String {
    let url = url.trim_start_matches("//");
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    after_scheme.split('/').next().unwrap_or("").to_string()
}

// ── 4. web_blueprint ────────────────────────────────────────────────

pub fn web_blueprint(graph: &mut Graph, target: &str) -> String {
    let parts: Vec<&str> = target.splitn(2, ' ').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return "Usage: web-blueprint <har_file> [html_dir]".to_string();
    }

    let har_path = Path::new(parts[0]);
    let html_dir = parts.get(1).map(|s| Path::new(*s));

    if !har_path.exists() {
        return format!("HAR file not found: {}", parts[0]);
    }

    // Parse HAR file
    let har_content = match fs::read_to_string(har_path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading HAR file: {e}"),
    };

    let json: serde_json::Value = match serde_json::from_str(&har_content) {
        Ok(v) => v,
        Err(e) => return format!("Invalid JSON in HAR file: {e}"),
    };

    let entries = match json.get("log").and_then(|l| l.get("entries")).and_then(|e| e.as_array()) {
        Some(e) => e,
        None => return "No log.entries found in HAR file.".to_string(),
    };

    if entries.is_empty() {
        return "No entries in HAR file.".to_string();
    }

    // Collect data from HAR
    let mut endpoints: BTreeMap<(String, String), BlueprintEndpoint> = BTreeMap::new();
    let mut auth_method: Option<String> = None;
    let mut login_endpoint: Option<String> = None;
    let mut login_fields: Vec<String> = Vec::new();
    let mut token_header: Option<String> = None;
    let mut session_cookie: Option<String> = None;
    let mut rate_limit_header: Option<String> = None;
    let mut rate_remaining: bool = false;
    let mut total_time: f64 = 0.0;
    let mut total_requests: usize = 0;
    let mut pagination_params: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut static_js: Vec<(String, usize)> = Vec::new();
    let mut static_css: Vec<(String, usize)> = Vec::new();
    let mut cdn_domains: BTreeSet<String> = BTreeSet::new();
    let mut base_urls: HashMap<String, usize> = HashMap::new();

    let static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ];

    for entry in entries {
        let request = match entry.get("request") {
            Some(r) => r,
            None => continue,
        };
        let response = match entry.get("response") {
            Some(r) => r,
            None => continue,
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_uppercase();
        let url_str = match request.get("url").and_then(|u| u.as_str()) {
            Some(u) => u,
            None => continue,
        };

        total_requests += 1;
        let time = entry.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
        total_time += time;

        let (base_url, path_str, _query) = parse_url_simple(url_str);
        if !base_url.is_empty() {
            *base_urls.entry(base_url.clone()).or_insert(0) += 1;
        }

        // Check for auth headers in request
        if let Some(headers) = request.get("headers").and_then(|h| h.as_array()) {
            for header in headers {
                let name = header.get("name").and_then(|n| n.as_str()).unwrap_or("").to_ascii_lowercase();
                let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if name == "authorization" {
                    if val.to_ascii_lowercase().starts_with("bearer") {
                        auth_method = Some("Bearer Token".to_string());
                        token_header = Some("Authorization: Bearer <token>".to_string());
                    } else if val.to_ascii_lowercase().starts_with("basic") {
                        auth_method = Some("Basic Auth".to_string());
                        token_header = Some("Authorization: Basic <credentials>".to_string());
                    }
                } else if name == "x-api-key" {
                    auth_method = Some("API Key".to_string());
                    token_header = Some("X-API-Key: <key>".to_string());
                } else if name == "cookie" {
                    if val.contains("session") {
                        session_cookie = Some("session_id".to_string());
                    } else if val.contains("token") {
                        session_cookie = Some("token".to_string());
                    } else if val.contains("auth") {
                        session_cookie = Some("auth".to_string());
                    }
                }
            }
        }

        // Check for rate limit headers in response
        if let Some(headers) = response.get("headers").and_then(|h| h.as_array()) {
            for header in headers {
                let name = header.get("name").and_then(|n| n.as_str()).unwrap_or("").to_ascii_lowercase();
                let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if name == "x-ratelimit-limit" {
                    rate_limit_header = Some(format!("X-RateLimit-Limit: {val}"));
                } else if name == "x-ratelimit-remaining" {
                    rate_remaining = true;
                }
                // Detect Set-Cookie for session
                if name == "set-cookie" {
                    let cookie_lower = val.to_ascii_lowercase();
                    if (cookie_lower.contains("session") || cookie_lower.contains("token") || cookie_lower.contains("auth"))
                        && session_cookie.is_none() {
                            let cookie_name = val.split('=').next().unwrap_or("session").to_string();
                            session_cookie = Some(cookie_name);
                        }
                }
            }
        }

        // Static asset tracking
        let path_lower = path_str.to_ascii_lowercase();
        let is_static = static_extensions.iter().any(|ext| path_lower.ends_with(ext));

        if is_static {
            let size = response.get("content")
                .and_then(|c| c.get("size"))
                .and_then(|s| s.as_u64())
                .unwrap_or(0) as usize;

            if path_lower.ends_with(".js") {
                static_js.push((path_str.clone(), size));
            } else if path_lower.ends_with(".css") {
                static_css.push((path_str.clone(), size));
            }

            // Detect CDN domains
            let domain = extract_domain_from_url(url_str);
            let primary_domain = base_urls.iter()
                .max_by_key(|(_, c)| *c)
                .map(|(u, _)| extract_domain_from_url(u))
                .unwrap_or_default();
            if !domain.is_empty() && domain != primary_domain {
                cdn_domains.insert(domain);
            }

            continue;
        }

        // Normalize path
        let normalized = normalize_api_path(&path_str);

        // Detect login endpoint
        if method == "POST" {
            let path_l = normalized.to_ascii_lowercase();
            if path_l.contains("login") || path_l.contains("auth") || path_l.contains("signin") || path_l.contains("sign-in") {
                login_endpoint = Some(format!("POST {normalized}"));
                // Extract login fields from body
                if let Some(post_data) = request.get("postData") {
                    let mime = post_data.get("mimeType").and_then(|m| m.as_str()).unwrap_or("");
                    if mime.contains("json") {
                        if let Some(text_val) = post_data.get("text").and_then(|t| t.as_str()) {
                            if let Ok(body) = serde_json::from_str::<serde_json::Value>(text_val) {
                                if let Some(obj) = body.as_object() {
                                    login_fields = obj.keys().cloned().collect();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build endpoint entry
        let key = (method.clone(), normalized.clone());
        let ep = endpoints.entry(key).or_insert_with(|| BlueprintEndpoint {
            method: method.clone(),
            path: normalized.clone(),
            query_params: BTreeSet::new(),
            body_fields: BTreeSet::new(),
        });

        // Query parameters
        if let Some(qs) = request.get("queryString").and_then(|q| q.as_array()) {
            for param in qs {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    ep.query_params.insert(name.to_string());
                    // Track pagination params
                    let name_lower = name.to_ascii_lowercase();
                    if name_lower == "page" || name_lower == "offset" || name_lower == "cursor" || name_lower == "limit" || name_lower == "skip" {
                        let value = param.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        pagination_params.entry(name.to_string()).or_default().push(value);
                    }
                }
            }
        }

        // Body fields
        if let Some(post_data) = request.get("postData") {
            let mime = post_data.get("mimeType").and_then(|m| m.as_str()).unwrap_or("");
            if mime.contains("json") {
                if let Some(text_val) = post_data.get("text").and_then(|t| t.as_str()) {
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(text_val) {
                        if let Some(obj) = body.as_object() {
                            for key in obj.keys() {
                                ep.body_fields.insert(key.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse HTML files if html_dir provided
    let mut html_tables: Vec<BlueprintTable> = Vec::new();
    let mut html_forms: Vec<BlueprintForm> = Vec::new();
    let mut pagination_selectors: Vec<String> = Vec::new();

    if let Some(dir) = html_dir {
        if dir.exists() {
            let html_files = if dir.is_dir() {
                collect_html_files(dir)
            } else {
                vec![dir.to_path_buf()]
            };

            for file in &html_files {
                let content = match fs::read_to_string(file) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                // Extract tables
                let tables = extract_tables(&content);
                for table in tables {
                    if !table.headers.is_empty() {
                        let class_str = if !table.class.is_empty() {
                            table.class.clone()
                        } else if !table.id.is_empty() {
                            table.id.clone()
                        } else {
                            "table".to_string()
                        };
                        let selector = if !table.class.is_empty() {
                            format!("table.{} tr td", table.class.split_whitespace().next().unwrap_or(&table.class))
                        } else if !table.id.is_empty() {
                            format!("table#{} tr td", table.id)
                        } else {
                            "table tr td".to_string()
                        };
                        html_tables.push(BlueprintTable {
                            name: class_str,
                            columns: table.headers,
                            selector,
                        });
                    }
                }

                // Extract forms and map to API endpoints
                let forms = extract_forms(&content);
                for form in forms {
                    let id_or_class = if !form.id.is_empty() {
                        format!("#{}", form.id)
                    } else if !form.class.is_empty() {
                        format!(".{}", form.class)
                    } else {
                        "(unnamed)".to_string()
                    };
                    let action_str = if !form.action.is_empty() {
                        format!("{} {}", form.method.to_uppercase(), form.action)
                    } else {
                        form.method.to_uppercase()
                    };
                    let fields: Vec<(String, String)> = form.fields.iter()
                        .map(|f| {
                            let selector = if !f.name.is_empty() && f.name != "(unnamed)" {
                                format!("{}[name=\"{}\"]", f.field_type, f.name)
                            } else {
                                f.field_type.clone()
                            };
                            (f.name.clone(), selector)
                        })
                        .collect();
                    html_forms.push(BlueprintForm {
                        id: id_or_class,
                        action: action_str,
                        fields,
                    });
                }

                // Detect pagination selectors
                let lower = content.to_ascii_lowercase();
                let pag_patterns = ["next-page", "load-more", "pagination", "pager", "page-link"];
                for pat in &pag_patterns {
                    if lower.contains(pat) {
                        // Try to find the element
                        if pat.contains("next") {
                            pagination_selectors.push(format!("a.{pat}, button.{pat}"));
                        } else {
                            pagination_selectors.push(format!(".{pat}"));
                        }
                    }
                }
            }
        }
    }

    // Determine primary base URL
    let primary_base = base_urls.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(url, _)| url.clone())
        .unwrap_or_default();

    let har_filename = har_path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| parts[0].to_string());
    let html_dir_str = html_dir.map(|d| d.to_string_lossy().to_string()).unwrap_or_default();

    // Build output
    let mut out = String::new();
    out.push_str("=== Scraper Blueprint ===\n\n");

    // Target
    if !primary_base.is_empty() {
        out.push_str(&format!("Target: {primary_base}\n"));
    }
    let generated = if html_dir_str.is_empty() {
        har_filename.clone()
    } else {
        format!("{har_filename} + {html_dir_str}")
    };
    out.push_str(&format!("Generated from: {generated}\n\n"));

    // Auth Recipe
    if auth_method.is_some() || login_endpoint.is_some() || session_cookie.is_some() {
        out.push_str("\u{2500}\u{2500} Auth Recipe \u{2500}\u{2500}\n");
        if let Some(ref method) = auth_method {
            out.push_str(&format!("  Method: {method}\n"));
        }
        if let Some(ref login) = login_endpoint {
            out.push_str(&format!("  Login: {login}\n"));
            if !login_fields.is_empty() {
                out.push_str(&format!("    Fields: {}\n", login_fields.join(", ")));
            }
        }
        if let Some(ref th) = token_header {
            out.push_str(&format!("  Token header: {th}\n"));
        }
        if let Some(ref cookie) = session_cookie {
            out.push_str(&format!("  Cookie: {cookie}\n"));
        }
        out.push('\n');
    }

    // API Endpoints
    if !endpoints.is_empty() {
        // Pass: register every blueprint endpoint into the heterogeneous
        // graph. web_blueprint is the most comprehensive web action — its
        // endpoint list combines HAR + HTML form actions, so the resulting
        // HttpEndpoint nodes are a superset of what web_api alone produces.
        for ep in endpoints.values() {
            register_endpoint(graph, target, &ep.method, &ep.path);
        }

        out.push_str(&format!("\u{2500}\u{2500} API Endpoints ({}) \u{2500}\u{2500}\n", endpoints.len()));
        for ep in endpoints.values() {
            let params_str = if !ep.query_params.is_empty() {
                let p: Vec<&str> = ep.query_params.iter().map(|s| s.as_str()).collect();
                format!(" \u{2192} params: {}", p.join(", "))
            } else if !ep.body_fields.is_empty() {
                let f: Vec<&str> = ep.body_fields.iter().map(|s| s.as_str()).collect();
                format!(" \u{2192} body: {}", f.join(", "))
            } else {
                String::new()
            };
            out.push_str(&format!("  {:6} {}{}\n", ep.method, ep.path, params_str));
        }
        out.push('\n');
    }

    // Data Tables (from HTML)
    if !html_tables.is_empty() {
        out.push_str(&"\u{2500}\u{2500} Data Tables (from HTML) \u{2500}\u{2500}\n".to_string());
        for table in &html_tables {
            out.push_str(&format!("  .{}\n", table.name));
            out.push_str(&format!("    Columns: {}\n", table.columns.join(", ")));
            out.push_str(&format!("    Selector: {}\n", table.selector));
            out.push('\n');
        }
    }

    // Forms
    if !html_forms.is_empty() {
        out.push_str("\u{2500}\u{2500} Forms \u{2500}\u{2500}\n");
        for form in &html_forms {
            out.push_str(&format!("  {} \u{2192} {}\n", form.id, form.action));
            for (name, selector) in &form.fields {
                out.push_str(&format!("    {name}: {selector}\n"));
            }
            out.push('\n');
        }
    }

    // Pagination
    if !pagination_params.is_empty() || !pagination_selectors.is_empty() {
        out.push_str("\u{2500}\u{2500} Pagination \u{2500}\u{2500}\n");
        for (param, values) in &pagination_params {
            let mut numeric_values: Vec<i64> = values.iter()
                .filter_map(|v| v.parse::<i64>().ok())
                .collect();
            numeric_values.sort();
            numeric_values.dedup();
            if numeric_values.len() >= 2 {
                let min = numeric_values.first().unwrap();
                let max = numeric_values.last().unwrap();
                out.push_str(&format!("  Pattern: ?{param}=N (seen pages {min}-{max})\n"));
            } else if !values.is_empty() {
                out.push_str(&format!("  Pattern: ?{param}=...\n"));
            }
        }
        pagination_selectors.sort();
        pagination_selectors.dedup();
        if !pagination_selectors.is_empty() {
            out.push_str(&format!("  Next: {}\n", pagination_selectors.join(", ")));
        }
        out.push('\n');
    }

    // Rate Limits
    if rate_limit_header.is_some() || rate_remaining {
        out.push_str("\u{2500}\u{2500} Rate Limits \u{2500}\u{2500}\n");
        if let Some(ref rl) = rate_limit_header {
            out.push_str(&format!("  {rl}\n"));
        }
        if rate_remaining {
            out.push_str("  X-RateLimit-Remaining: varies\n");
        }
        if total_requests > 0 {
            let avg_ms = total_time / total_requests as f64;
            out.push_str(&format!("  Avg response time: {avg_ms:.0}ms\n"));
        }
        out.push('\n');
    }

    // Static Assets
    if !static_js.is_empty() || !static_css.is_empty() || !cdn_domains.is_empty() {
        out.push_str("\u{2500}\u{2500} Static Assets \u{2500}\u{2500}\n");
        if !static_js.is_empty() {
            let total_size: usize = static_js.iter().map(|(_, s)| s).sum();
            out.push_str(&format!("  JS: {} files ({})\n", static_js.len(), format_file_size(total_size)));
        }
        if !static_css.is_empty() {
            out.push_str(&format!("  CSS: {} files\n", static_css.len()));
        }
        for domain in &cdn_domains {
            out.push_str(&format!("  CDN: {domain}\n"));
        }
        out.push('\n');
    }

    out
}

struct BlueprintEndpoint {
    method: String,
    path: String,
    query_params: BTreeSet<String>,
    body_fields: BTreeSet<String>,
}

struct BlueprintTable {
    name: String,
    columns: Vec<String>,
    selector: String,
}

struct BlueprintForm {
    id: String,
    action: String,
    fields: Vec<(String, String)>,
}

// ── 5. js_api_extract ────────────────────────────────────────────────

static JS_FETCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"fetch\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap()
});
static JS_FETCH_TEMPLATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"fetch\s*\(\s*`([^`]+)`"#).unwrap()
});
static JS_AXIOS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap()
});
static JS_XHR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\.open\s*\(\s*['"`](GET|POST|PUT|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]"#).unwrap()
});
static JS_BASE_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(api|API|endpoint|ENDPOINT|baseUrl|BASE_URL|apiUrl|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]"#).unwrap()
});
static JS_URL_PROP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"url:\s*['"`]([^'"`]+)['"`]"#).unwrap()
});
static JS_HEADERS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"headers\s*[:=]\s*\{([^}]+)\}"#).unwrap()
});
static JS_CONTENT_TYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]Content-Type['"]\s*:\s*['"`]([^'"`]+)['"`]"#).unwrap()
});

pub fn js_api_extract(graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("Path not found: {target}");
    }

    let js_files: Vec<std::path::PathBuf> = if path.is_dir() {
        collect_js_files(path)
    } else {
        vec![path.to_path_buf()]
    };

    if js_files.is_empty() {
        return "No JavaScript files found.".to_string();
    }

    let mut all_api_calls: Vec<(String, String, String)> = Vec::new(); // (method, url, file)
    let mut base_urls: BTreeMap<String, String> = BTreeMap::new();
    let mut headers: BTreeSet<String> = BTreeSet::new();
    let mut per_file_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut auth_patterns: BTreeSet<String> = BTreeSet::new();

    for file in &js_files {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let filename = file.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        let mut file_count = 0usize;

        // fetch('url')
        for caps in JS_FETCH_RE.captures_iter(&content) {
            let url = caps[1].to_string();
            all_api_calls.push(("".to_string(), url, filename.clone()));
            file_count += 1;
        }

        // fetch(`template`)
        for caps in JS_FETCH_TEMPLATE_RE.captures_iter(&content) {
            let url = caps[1].to_string();
            // Pre-fix code did `url.replace("${", "${")` — a no-op left
            // over from a planned interpolation rewrite. Just use as-is.
            all_api_calls.push(("".to_string(), url, filename.clone()));
            file_count += 1;
        }

        // axios.get/post/etc('url')
        for caps in JS_AXIOS_RE.captures_iter(&content) {
            let method = caps[1].to_uppercase();
            let url = caps[2].to_string();
            all_api_calls.push((method, url, filename.clone()));
            file_count += 1;
        }

        // .open('METHOD', 'url')
        for caps in JS_XHR_RE.captures_iter(&content) {
            let method = caps[1].to_string();
            let url = caps[2].to_string();
            all_api_calls.push((method, url, filename.clone()));
            file_count += 1;
        }

        // Base URL constants
        for caps in JS_BASE_URL_RE.captures_iter(&content) {
            let var_name = caps[1].to_string();
            let url = caps[2].to_string();
            base_urls.insert(var_name, url);
        }

        // url: 'value' in config objects
        for caps in JS_URL_PROP_RE.captures_iter(&content) {
            let url = caps[1].to_string();
            if url.starts_with('/') || url.starts_with("http") {
                all_api_calls.push(("".to_string(), url, filename.clone()));
                file_count += 1;
            }
        }

        // Header definitions
        for caps in JS_HEADERS_RE.captures_iter(&content) {
            let header_block = &caps[1];
            // Extract individual headers
            for ct_caps in JS_CONTENT_TYPE_RE.captures_iter(header_block) {
                headers.insert(format!("Content-Type: {}", &ct_caps[1]));
            }
            // Look for auth patterns
            let header_lower = header_block.to_ascii_lowercase();
            if header_lower.contains("bearer") {
                auth_patterns.insert("Bearer token authentication".to_string());
                headers.insert("Authorization: Bearer ${token}".to_string());
            }
            if header_lower.contains("api-key") || header_lower.contains("apikey") || header_lower.contains("api_key") {
                auth_patterns.insert("API key authentication".to_string());
                headers.insert("X-API-Key: ${apiKey}".to_string());
            }
        }

        // Also look for standalone Content-Type headers
        for caps in JS_CONTENT_TYPE_RE.captures_iter(&content) {
            headers.insert(format!("Content-Type: {}", &caps[1]));
        }

        if file_count > 0 {
            per_file_counts.insert(filename, file_count);
        }
    }

    // Deduplicate API calls
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unique_calls: Vec<(String, String)> = Vec::new();
    for (method, url, _) in &all_api_calls {
        let key = (method.clone(), url.clone());
        if seen.insert(key) {
            unique_calls.push((method.clone(), url.clone()));
        }
    }

    // Pass: register every JS-extracted endpoint plus an edge from each
    // calling JS file to its endpoints. Crucial for `meta-path
    // SourceFile->HttpEndpoint` queries — finds every JS bundle that
    // produces an API call without needing a HAR capture.
    for (method, url, file) in &all_api_calls {
        let m = if method.is_empty() { "GET" } else { method.as_str() };
        register_endpoint(graph, file, m, url);
    }

    // Build output
    let mut out = String::new();
    out.push_str("=== JS API Extraction ===\n\n");
    out.push_str(&format!("Files scanned: {}\n", js_files.len()));
    out.push_str(&format!("API calls found: {}\n", unique_calls.len()));
    out.push_str(&format!("Base URLs: {}\n\n", base_urls.len()));

    // Base URLs
    if !base_urls.is_empty() {
        out.push_str("\u{2500}\u{2500} Base URLs \u{2500}\u{2500}\n");
        for (name, url) in &base_urls {
            out.push_str(&format!("  {name} = \"{url}\"\n"));
        }
        out.push('\n');
    }

    // API Calls
    if !unique_calls.is_empty() {
        out.push_str("\u{2500}\u{2500} API Calls \u{2500}\u{2500}\n");
        for (method, url) in &unique_calls {
            if method.is_empty() {
                out.push_str(&format!("  {url}\n"));
            } else {
                out.push_str(&format!("  {:6} {url}\n", method));
            }
        }
        out.push('\n');
    }

    // Headers
    if !headers.is_empty() {
        out.push_str("\u{2500}\u{2500} Headers \u{2500}\u{2500}\n");
        for h in &headers {
            out.push_str(&format!("  {h}\n"));
        }
        out.push('\n');
    }

    // Per File
    if per_file_counts.len() > 1 {
        out.push_str("\u{2500}\u{2500} Per File \u{2500}\u{2500}\n");
        let mut sorted: Vec<(&String, &usize)> = per_file_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (file, count) in sorted {
            out.push_str(&format!("  {file}: {count} API calls\n"));
        }
        out.push('\n');
    }

    out
}

fn collect_js_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_js_files(&path));
            } else if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_ascii_lowercase();
                if ext == "js" || ext == "mjs" || ext == "cjs" || ext == "jsx" {
                    files.push(path);
                }
            }
        }
    }
    files
}
