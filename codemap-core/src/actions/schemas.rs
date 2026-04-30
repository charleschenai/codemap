use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use crate::types::{Graph, EntityKind};

/// Heterogeneous-graph helper: register a schema-source file with the
/// appropriate entity kind. Used by all five schema actions to attach their
/// parsed structures to a single source node, so cross-action queries
/// ("which proto messages does this OpenAPI path correspond to?") become
/// meta-path traversals over typed edges.
fn ensure_schema_source(graph: &mut Graph, target: &str, kind: &str) {
    let id = format!("schema:{kind}:{target}");
    graph.ensure_typed_node(&id, EntityKind::SourceFile, &[
        ("path", target), ("schema_kind", kind),
    ]);
}

// ═══════════════════════════════════════════════════════════════════════
//  1. proto_schema — Parse .proto (Protocol Buffer / gRPC) files
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
struct ProtoMessage {
    name: String,
    fields: Vec<ProtoField>,
}

#[derive(Debug)]
struct ProtoField {
    label: String,   // optional/required/repeated or ""
    typ: String,
    name: String,
    number: String,
}

#[derive(Debug)]
struct ProtoEnum {
    name: String,
    values: Vec<String>,
}

#[derive(Debug)]
struct ProtoRpc {
    name: String,
    request: String,
    response: String,
    client_streaming: bool,
    server_streaming: bool,
}

#[derive(Debug)]
struct ProtoService {
    name: String,
    rpcs: Vec<ProtoRpc>,
}

#[derive(Debug)]
struct ProtoFile {
    path: String,
    package: String,
    imports: Vec<String>,
    messages: Vec<ProtoMessage>,
    enums: Vec<ProtoEnum>,
    services: Vec<ProtoService>,
}

fn collect_proto_files(target: &str) -> Vec<String> {
    let path = Path::new(target);
    if path.is_file() {
        return vec![target.to_string()];
    }
    if path.is_dir() {
        let mut files = Vec::new();
        collect_proto_dir(path, &mut files);
        files.sort();
        return files;
    }
    Vec::new()
}

fn collect_proto_dir(dir: &Path, out: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_proto_dir(&p, out);
            } else if p.extension().is_some_and(|e| e == "proto") {
                out.push(p.to_string_lossy().to_string());
            }
        }
    }
}

fn parse_proto_file(path: &str) -> Option<ProtoFile> {
    let content = fs::read_to_string(path).ok()?;
    let mut pf = ProtoFile {
        path: path.to_string(),
        package: String::new(),
        imports: Vec::new(),
        messages: Vec::new(),
        enums: Vec::new(),
        services: Vec::new(),
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Package
        if trimmed.starts_with("package ") {
            pf.package = trimmed
                .trim_start_matches("package ")
                .trim_end_matches(';')
                .trim()
                .to_string();
        }

        // Import
        if trimmed.starts_with("import ") {
            let imp = trimmed
                .trim_start_matches("import ")
                .trim_start_matches("public ")
                .trim_end_matches(';')
                .trim()
                .trim_matches('"')
                .to_string();
            pf.imports.push(imp);
        }

        // Message
        if trimmed.starts_with("message ") && trimmed.contains('{') {
            let name = trimmed
                .trim_start_matches("message ")
                .split('{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let mut fields = Vec::new();
            let mut depth = 1i32;
            i += 1;
            while i < lines.len() && depth > 0 {
                let line = lines[i].trim();
                if line.contains('{') {
                    depth += line.matches('{').count() as i32;
                }
                if line.contains('}') {
                    depth -= line.matches('}').count() as i32;
                }
                if depth == 1 && !line.is_empty() && !line.starts_with("//")
                    && !line.starts_with("option ")
                    && !line.starts_with("reserved ")
                    && !line.starts_with("oneof ")
                    && !line.starts_with("message ")
                    && !line.starts_with("enum ")
                    && !line.starts_with("map<")
                    && line.contains('=')
                    && !line.starts_with('}')
                {
                    if let Some(field) = parse_proto_field(line) {
                        fields.push(field);
                    }
                }
                // Handle map fields at depth 1
                if depth == 1 && line.starts_with("map<") && line.contains('=') {
                    if let Some(field) = parse_proto_field(line) {
                        fields.push(field);
                    }
                }
                i += 1;
            }
            pf.messages.push(ProtoMessage { name, fields });
            continue;
        }

        // Enum
        if trimmed.starts_with("enum ") && trimmed.contains('{') {
            let name = trimmed
                .trim_start_matches("enum ")
                .split('{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let mut values = Vec::new();
            let mut depth = 1i32;
            i += 1;
            while i < lines.len() && depth > 0 {
                let line = lines[i].trim();
                if line.contains('{') { depth += line.matches('{').count() as i32; }
                if line.contains('}') { depth -= line.matches('}').count() as i32; }
                if depth == 1 && line.contains('=') && !line.starts_with("//") && !line.starts_with("option ") {
                    let val_name = line.split('=').next().unwrap_or("").trim().to_string();
                    if !val_name.is_empty() {
                        values.push(val_name);
                    }
                }
                i += 1;
            }
            pf.enums.push(ProtoEnum { name, values });
            continue;
        }

        // Service
        if trimmed.starts_with("service ") && trimmed.contains('{') {
            let name = trimmed
                .trim_start_matches("service ")
                .split('{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let mut rpcs = Vec::new();
            let mut depth = 1i32;
            i += 1;
            while i < lines.len() && depth > 0 {
                let line = lines[i].trim();
                if line.contains('{') { depth += line.matches('{').count() as i32; }
                if line.contains('}') { depth -= line.matches('}').count() as i32; }
                if line.starts_with("rpc ") {
                    if let Some(rpc) = parse_proto_rpc(line) {
                        rpcs.push(rpc);
                    }
                }
                i += 1;
            }
            pf.services.push(ProtoService { name, rpcs });
            continue;
        }

        i += 1;
    }

    Some(pf)
}

fn parse_proto_field(line: &str) -> Option<ProtoField> {
    let clean = line.trim().trim_end_matches(';').trim();
    // Remove inline comments
    let clean = clean.split("//").next().unwrap_or(clean).trim();

    let parts: Vec<&str> = clean.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // Find the '=' to get the field number
    let eq_idx = parts.iter().position(|p| *p == "=")?;
    let number = parts.get(eq_idx + 1).unwrap_or(&"?").to_string();

    if parts[0] == "repeated" || parts[0] == "optional" || parts[0] == "required" {
        // label type name = number
        Some(ProtoField {
            label: parts[0].to_string(),
            typ: parts[1].to_string(),
            name: parts[2].to_string(),
            number,
        })
    } else if parts[0].starts_with("map<") {
        // map<K,V> name = number
        // Reconstruct the map type
        let mut map_type = String::new();
        let mut j = 0;
        while j < eq_idx - 1 {
            if !map_type.is_empty() { map_type.push(' '); }
            map_type.push_str(parts[j]);
            j += 1;
        }
        let name = parts[eq_idx - 1].to_string();
        Some(ProtoField {
            label: String::new(),
            typ: map_type,
            name,
            number,
        })
    } else {
        // type name = number
        Some(ProtoField {
            label: String::new(),
            typ: parts[0].to_string(),
            name: parts[1].to_string(),
            number,
        })
    }
}

fn parse_proto_rpc(line: &str) -> Option<ProtoRpc> {
    // rpc MethodName (RequestType) returns (ResponseType) { ... }
    let clean = line.trim();
    let after_rpc = clean.strip_prefix("rpc ")?.trim();

    let paren_start = after_rpc.find('(')?;
    let name = after_rpc[..paren_start].trim().to_string();

    let rest = &after_rpc[paren_start..];

    // Extract request type
    let req_start = rest.find('(')? + 1;
    let req_end = rest.find(')')?;
    let req_raw = rest[req_start..req_end].trim();
    let client_streaming = req_raw.starts_with("stream ");
    let request = req_raw.trim_start_matches("stream ").trim().to_string();

    // Find 'returns'
    let after_first_paren = &rest[req_end + 1..];
    let returns_idx = after_first_paren.find("returns")?;
    let after_returns = &after_first_paren[returns_idx + 7..];

    // Extract response type
    let resp_start = after_returns.find('(')? + 1;
    let resp_end = after_returns.find(')')?;
    let resp_raw = after_returns[resp_start..resp_end].trim();
    let server_streaming = resp_raw.starts_with("stream ");
    let response = resp_raw.trim_start_matches("stream ").trim().to_string();

    Some(ProtoRpc {
        name,
        request,
        response,
        client_streaming,
        server_streaming,
    })
}

pub fn proto_schema(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap proto-schema <file.proto | directory>".to_string();
    }

    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    ensure_schema_source(graph, target, "proto");

    let files = collect_proto_files(target);
    if files.is_empty() {
        return format!("No .proto files found in: {target}");
    }

    let mut parsed: Vec<ProtoFile> = files.iter().filter_map(|f| parse_proto_file(f)).collect();
    parsed.sort_by(|a, b| a.path.cmp(&b.path));

    // Pass: register every parsed message + enum + service as typed nodes.
    // Edges: each message gets an edge from its containing .proto source;
    // when a field's type matches another message in the same file, add a
    // message → message edge so meta-paths can traverse type compositions.
    for pf in &parsed {
        let pf_id = format!("schema:proto:{}", pf.path);
        for msg in &pf.messages {
            let msg_id = format!("proto:{}::{}", pf.path, msg.name);
            graph.ensure_typed_node(&msg_id, EntityKind::ProtoMessage, &[
                ("name", &msg.name),
                ("file", &pf.path),
                ("package", &pf.package),
                ("field_count", &msg.fields.len().to_string()),
            ]);
            graph.add_edge(&pf_id, &msg_id);
        }
        // Field-type composition edges within the same file
        let local_msgs: std::collections::HashSet<&str> = pf.messages.iter()
            .map(|m| m.name.as_str()).collect();
        for msg in &pf.messages {
            let from = format!("proto:{}::{}", pf.path, msg.name);
            for field in &msg.fields {
                if local_msgs.contains(field.typ.as_str()) {
                    let to = format!("proto:{}::{}", pf.path, field.typ);
                    graph.add_edge(&from, &to);
                }
            }
        }
    }

    let total_messages: usize = parsed.iter().map(|f| f.messages.len()).sum();
    let total_enums: usize = parsed.iter().map(|f| f.enums.len()).sum();
    let total_services: usize = parsed.iter().map(|f| f.services.len()).sum();
    let total_rpcs: usize = parsed.iter().map(|f| f.services.iter().map(|s| s.rpcs.len()).sum::<usize>()).sum();

    let mut out = String::new();
    out.push_str("=== Protocol Buffer Schema ===\n\n");
    out.push_str(&format!("Files: {}\n", parsed.len()));
    out.push_str(&format!("Messages: {total_messages}\n"));
    out.push_str(&format!("Enums: {total_enums}\n"));
    out.push_str(&format!("Services: {total_services}\n"));
    out.push_str(&format!("RPCs: {total_rpcs}\n"));
    out.push('\n');

    for pf in &parsed {
        out.push_str(&format!("── {} ──\n", pf.path));
        if !pf.package.is_empty() {
            out.push_str(&format!("  package: {}\n", pf.package));
        }
        if !pf.imports.is_empty() {
            out.push_str("  imports:\n");
            for imp in &pf.imports {
                out.push_str(&format!("    {imp}\n"));
            }
        }

        // Messages
        for msg in &pf.messages {
            out.push_str(&format!("\n  message {} {{\n", msg.name));
            for field in &msg.fields {
                let label = if field.label.is_empty() { String::new() } else { format!("{} ", field.label) };
                out.push_str(&format!("    {}{} {} = {};\n", label, field.typ, field.name, field.number));
            }
            out.push_str("  }\n");
        }

        // Enums
        for en in &pf.enums {
            out.push_str(&format!("\n  enum {} {{\n", en.name));
            for val in &en.values {
                out.push_str(&format!("    {val}\n"));
            }
            out.push_str("  }\n");
        }

        // Services
        for svc in &pf.services {
            out.push_str(&format!("\n  service {} {{\n", svc.name));
            for rpc in &svc.rpcs {
                let cs = if rpc.client_streaming { "stream " } else { "" };
                let ss = if rpc.server_streaming { "stream " } else { "" };
                out.push_str(&format!(
                    "    rpc {}({}{}) returns ({}{})\n",
                    rpc.name, cs, rpc.request, ss, rpc.response
                ));
            }
            out.push_str("  }\n");
        }

        out.push('\n');
    }

    out
}

// ═══════════════════════════════════════════════════════════════════════
//  2. openapi_schema — Parse OpenAPI/Swagger JSON or YAML spec files
// ═══════════════════════════════════════════════════════════════════════

pub fn openapi_schema(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap openapi-schema <spec.json | spec.yaml>".to_string();
    }

    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    ensure_schema_source(graph, target, "openapi");

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "json" {
        parse_openapi_json(&content, graph, target)
    } else if ext == "yaml" || ext == "yml" {
        parse_openapi_yaml(&content, graph, target)
    } else {
        // Try JSON first, then YAML-like
        if content.trim_start().starts_with('{') {
            parse_openapi_json(&content, graph, target)
        } else {
            parse_openapi_yaml(&content, graph, target)
        }
    }
}

/// Heterogeneous-graph helper: register an OpenAPI path operation as both
/// an OpenApiPath node (spec-level) and an HttpEndpoint (runtime-level).
/// They share an edge from the schema source. Why both kinds? Spec paths
/// are the design intent; HttpEndpoint nodes are the operational reality.
/// Filtering by either kind serves different queries — `--type oapi` for
/// "what does my spec say should exist", `--type endpoint` for "what's
/// actually being called" (after web-blueprint or js-api-extract pass).
fn register_openapi_path(graph: &mut Graph, source: &str, method: &str, path: &str, op_id: &str) {
    let oapi_id = format!("oapi:{method} {path}");
    graph.ensure_typed_node(&oapi_id, EntityKind::OpenApiPath, &[
        ("method", method), ("path", path), ("operation_id", op_id),
    ]);
    // Also register as an HttpEndpoint so the same node participates in
    // meta-paths against runtime-extracted endpoints.
    let ep_id = format!("ep:{method}:{path}");
    graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
        ("method", method), ("url", path), ("source", "openapi-schema"),
    ]);
    let src_id = format!("schema:openapi:{source}");
    graph.add_edge(&src_id, &oapi_id);
    graph.add_edge(&oapi_id, &ep_id);
}

fn parse_openapi_json(content: &str, graph: &mut Graph, source: &str) -> String {
    let val: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return format!("Error parsing JSON: {e}"),
    };

    let mut out = String::new();
    out.push_str("=== OpenAPI Schema ===\n\n");

    // Info
    if let Some(info) = val.get("info") {
        let title = info.get("title").and_then(|v| v.as_str()).unwrap_or("(untitled)");
        let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        out.push_str(&format!("Title: {title}\n"));
        out.push_str(&format!("Version: {version}\n"));
        if let Some(desc) = info.get("description").and_then(|v| v.as_str()) {
            let short = if desc.len() > 120 { &desc[..120] } else { desc };
            out.push_str(&format!("Description: {short}\n"));
        }
    }

    // OpenAPI version
    if let Some(oa) = val.get("openapi").and_then(|v| v.as_str()) {
        out.push_str(&format!("OpenAPI: {oa}\n"));
    } else if let Some(sw) = val.get("swagger").and_then(|v| v.as_str()) {
        out.push_str(&format!("Swagger: {sw}\n"));
    }

    // Servers
    if let Some(servers) = val.get("servers").and_then(|v| v.as_array()) {
        out.push_str("\nServers:\n");
        for s in servers {
            if let Some(url) = s.get("url").and_then(|v| v.as_str()) {
                let desc = s.get("description").and_then(|v| v.as_str()).unwrap_or("");
                if desc.is_empty() {
                    out.push_str(&format!("  {url}\n"));
                } else {
                    out.push_str(&format!("  {url} ({desc})\n"));
                }
            }
        }
    }

    // Paths
    if let Some(paths) = val.get("paths").and_then(|v| v.as_object()) {
        let mut method_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut endpoint_list: Vec<(String, String, String)> = Vec::new(); // (method, path, opId)

        for (path_str, methods) in paths {
            if let Some(obj) = methods.as_object() {
                for (method, details) in obj {
                    let m = method.to_uppercase();
                    if matches!(m.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS") {
                        *method_counts.entry(m.clone()).or_insert(0) += 1;
                        let op_id = details
                            .get("operationId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        endpoint_list.push((m, path_str.clone(), op_id));
                    }
                }
            }
        }

        // Pass: register every spec path as an OpenApiPath + HttpEndpoint.
        for (m, p, op) in &endpoint_list {
            register_openapi_path(graph, source, m, p, op);
        }

        out.push_str(&format!("\nEndpoints: {}\n", endpoint_list.len()));
        out.push_str("Method distribution:\n");
        for (method, count) in &method_counts {
            out.push_str(&format!("  {method}: {count}\n"));
        }

        out.push_str("\nPaths:\n");
        for (method, path_str, op_id) in &endpoint_list {
            if op_id.is_empty() {
                out.push_str(&format!("  {method:7} {path_str}\n"));
            } else {
                out.push_str(&format!("  {method:7} {path_str}  [{op_id}]\n"));
            }
        }
    }

    // Security definitions
    if let Some(sec) = val.get("securityDefinitions").and_then(|v| v.as_object())
        .or_else(|| val.get("components").and_then(|c| c.get("securitySchemes")).and_then(|v| v.as_object()))
    {
        out.push_str("\nAuth schemes:\n");
        for (name, def) in sec {
            let typ = def.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            let scheme = def.get("scheme").and_then(|v| v.as_str()).unwrap_or("");
            if scheme.is_empty() {
                out.push_str(&format!("  {name}: {typ}\n"));
            } else {
                out.push_str(&format!("  {name}: {typ} ({scheme})\n"));
            }
        }
    }

    // Schemas (component definitions)
    if let Some(schemas) = val.get("definitions").and_then(|v| v.as_object())
        .or_else(|| val.get("components").and_then(|c| c.get("schemas")).and_then(|v| v.as_object()))
    {
        let mut schema_names: Vec<&String> = schemas.keys().collect();
        schema_names.sort();
        out.push_str(&format!("\nSchemas ({}):\n", schema_names.len()));
        for name in schema_names {
            let sch = &schemas[name];
            let typ = sch.get("type").and_then(|v| v.as_str()).unwrap_or("object");
            let prop_count = sch.get("properties").and_then(|v| v.as_object()).map(|o| o.len()).unwrap_or(0);
            if prop_count > 0 {
                out.push_str(&format!("  {name} ({typ}, {prop_count} props)\n"));
            } else {
                out.push_str(&format!("  {name} ({typ})\n"));
            }
        }
    }

    // Tags
    if let Some(tags) = val.get("tags").and_then(|v| v.as_array()) {
        out.push_str("\nTags:\n");
        for t in tags {
            if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
                if desc.is_empty() {
                    out.push_str(&format!("  {name}\n"));
                } else {
                    let short = if desc.len() > 80 { &desc[..80] } else { desc };
                    out.push_str(&format!("  {name}: {short}\n"));
                }
            }
        }
    }

    out
}

fn parse_openapi_yaml(content: &str, graph: &mut Graph, source: &str) -> String {
    // Basic YAML key-value parsing for OpenAPI — not a full YAML parser
    let lines: Vec<&str> = content.lines().collect();
    let mut out = String::new();
    out.push_str("=== OpenAPI Schema (YAML) ===\n\n");

    // Extract top-level info
    let mut in_info = false;
    let mut in_servers = false;
    let mut in_paths = false;
    let mut in_tags = false;
    let mut in_security_defs = false;
    let mut in_schemas = false;

    let mut title = String::new();
    let mut version = String::new();
    let mut openapi_ver = String::new();
    let mut servers: Vec<String> = Vec::new();
    let mut endpoints: Vec<(String, String)> = Vec::new(); // (method path)
    let mut method_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut current_path = String::new();
    let mut tags: Vec<String> = Vec::new();
    let mut auth_schemes: Vec<String> = Vec::new();
    let mut schema_names: Vec<String> = Vec::new();
    let mut path_indent = 0usize;

    for line in &lines {
        let stripped = line.trim_end();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let trimmed = stripped.trim();

        // Top-level keys (indent 0)
        if indent == 0 {
            in_info = false;
            in_servers = false;
            in_paths = false;
            in_tags = false;
            in_security_defs = false;
            in_schemas = false;

            if trimmed.starts_with("openapi:") {
                openapi_ver = yaml_value(trimmed);
            } else if trimmed.starts_with("swagger:") {
                openapi_ver = format!("Swagger {}", yaml_value(trimmed));
            } else if trimmed == "info:" {
                in_info = true;
            } else if trimmed == "servers:" {
                in_servers = true;
            } else if trimmed == "paths:" {
                in_paths = true;
            } else if trimmed == "tags:" {
                in_tags = true;
            } else if trimmed == "securityDefinitions:" || trimmed == "components:" {
                // We'll catch sub-keys below
                if trimmed == "securityDefinitions:" {
                    in_security_defs = true;
                }
            }
            continue;
        }

        // info block (indent >= 2)
        if in_info && indent >= 2 {
            if trimmed.starts_with("title:") {
                title = yaml_value(trimmed);
            } else if trimmed.starts_with("version:") {
                version = yaml_value(trimmed);
            }
            continue;
        }

        // servers block
        if in_servers && indent >= 2 {
            if trimmed.starts_with("- url:") {
                servers.push(yaml_value(trimmed.trim_start_matches("- ")));
            }
            continue;
        }

        // paths block
        if in_paths {
            // Path key (e.g. "  /api/users:")
            if indent == 2 && trimmed.ends_with(':') && trimmed.starts_with('/') {
                current_path = trimmed.trim_end_matches(':').to_string();
                path_indent = indent;
                continue;
            }
            // Method under a path (e.g. "    get:")
            if indent == 4 && !current_path.is_empty() && trimmed.ends_with(':') {
                let method = trimmed.trim_end_matches(':').to_uppercase();
                if matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS") {
                    *method_counts.entry(method.clone()).or_insert(0) += 1;
                    endpoints.push((method, current_path.clone()));
                }
            }
            // Reset path context at indent 0 or when back at path level
            if indent <= path_indent && indent > 0 && !trimmed.starts_with('/') && indent == 2 {
                // New top-level key under paths but not a path — might be wrong, ignore
            }
            continue;
        }

        // tags block
        if in_tags && indent >= 2 {
            if trimmed.starts_with("- name:") {
                tags.push(yaml_value(trimmed.trim_start_matches("- ")));
            }
            continue;
        }

        // securityDefinitions / components.securitySchemes
        if in_security_defs && indent >= 2 {
            if indent == 2 && trimmed.ends_with(':') && !trimmed.contains(' ') {
                auth_schemes.push(trimmed.trim_end_matches(':').to_string());
            }
            continue;
        }

        // Handle components sub-keys
        if indent == 2 && trimmed == "securitySchemes:" {
            in_security_defs = true;
            in_schemas = false;
            continue;
        }
        if indent == 2 && trimmed == "schemas:" {
            in_schemas = true;
            in_security_defs = false;
            continue;
        }

        // schemas under components
        if in_schemas && indent == 4 && trimmed.ends_with(':') && !trimmed.contains(' ') {
            schema_names.push(trimmed.trim_end_matches(':').to_string());
            continue;
        }

        // definitions (swagger 2.0)
        if indent == 0 && trimmed == "definitions:" {
            in_schemas = true;
            continue;
        }
        if in_schemas && indent == 2 && trimmed.ends_with(':') && !trimmed.contains(' ') {
            schema_names.push(trimmed.trim_end_matches(':').to_string());
            continue;
        }
    }

    // Build output
    if !title.is_empty() {
        out.push_str(&format!("Title: {title}\n"));
    }
    if !version.is_empty() {
        out.push_str(&format!("Version: {version}\n"));
    }
    if !openapi_ver.is_empty() {
        out.push_str(&format!("OpenAPI: {openapi_ver}\n"));
    }

    if !servers.is_empty() {
        out.push_str("\nServers:\n");
        for s in &servers {
            out.push_str(&format!("  {s}\n"));
        }
    }

    if !endpoints.is_empty() {
        // Pass: register every YAML-parsed path. operationId not extracted
        // by the YAML parser (parse is line-based, not full AST), so empty.
        for (m, p) in &endpoints {
            register_openapi_path(graph, source, m, p, "");
        }
        out.push_str(&format!("\nEndpoints: {}\n", endpoints.len()));
        out.push_str("Method distribution:\n");
        for (method, count) in &method_counts {
            out.push_str(&format!("  {method}: {count}\n"));
        }
        out.push_str("\nPaths:\n");
        for (method, path_str) in &endpoints {
            out.push_str(&format!("  {method:7} {path_str}\n"));
        }
    }

    if !auth_schemes.is_empty() {
        out.push_str("\nAuth schemes:\n");
        for s in &auth_schemes {
            out.push_str(&format!("  {s}\n"));
        }
    }

    if !schema_names.is_empty() {
        schema_names.sort();
        out.push_str(&format!("\nSchemas ({}):\n", schema_names.len()));
        for s in &schema_names {
            out.push_str(&format!("  {s}\n"));
        }
    }

    if !tags.is_empty() {
        out.push_str("\nTags:\n");
        for t in &tags {
            out.push_str(&format!("  {t}\n"));
        }
    }

    out
}

fn yaml_value(line: &str) -> String {
    if let Some(idx) = line.find(':') {
        let val = line[idx + 1..].trim();
        val.trim_matches('"').trim_matches('\'').to_string()
    } else {
        String::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  3. graphql_schema — Parse .graphql schema files
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
struct GqlType {
    kind: String, // type, input, enum, interface, union, scalar
    name: String,
    fields: Vec<String>,
    implements: Vec<String>,
}

#[derive(Debug)]
struct GqlDirective {
    name: String,
    args: Vec<String>,
}

#[derive(Debug)]
struct GqlFile {
    path: String,
    types: Vec<GqlType>,
    directives: Vec<GqlDirective>,
}

fn collect_graphql_files(target: &str) -> Vec<String> {
    let path = Path::new(target);
    if path.is_file() {
        return vec![target.to_string()];
    }
    if path.is_dir() {
        let mut files = Vec::new();
        collect_graphql_dir(path, &mut files);
        files.sort();
        return files;
    }
    Vec::new()
}

fn collect_graphql_dir(dir: &Path, out: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_graphql_dir(&p, out);
            } else if p.extension().is_some_and(|e| e == "graphql" || e == "gql") {
                out.push(p.to_string_lossy().to_string());
            }
        }
    }
}

fn parse_graphql_file(path: &str) -> Option<GqlFile> {
    let content = fs::read_to_string(path).ok()?;
    let mut gf = GqlFile {
        path: path.to_string(),
        types: Vec::new(),
        directives: Vec::new(),
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        // Scalar declaration
        if trimmed.starts_with("scalar ") {
            let name = trimmed.trim_start_matches("scalar ").split_whitespace().next().unwrap_or("").to_string();
            if !name.is_empty() {
                gf.types.push(GqlType {
                    kind: "scalar".to_string(),
                    name,
                    fields: Vec::new(),
                    implements: Vec::new(),
                });
            }
            i += 1;
            continue;
        }

        // Union declaration
        if trimmed.starts_with("union ") && trimmed.contains('=') {
            let after_union = trimmed.trim_start_matches("union ").trim();
            let parts: Vec<&str> = after_union.splitn(2, '=').collect();
            let name = parts[0].trim().to_string();
            let members = if parts.len() > 1 {
                parts[1].split('|').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
            } else {
                Vec::new()
            };
            gf.types.push(GqlType {
                kind: "union".to_string(),
                name,
                fields: members,
                implements: Vec::new(),
            });
            i += 1;
            continue;
        }

        // Directive declaration
        if trimmed.starts_with("directive @") {
            let after_at = trimmed.trim_start_matches("directive @");
            let name = after_at.split(|c: char| c == '(' || c.is_whitespace()).next().unwrap_or("").to_string();
            // Collect args if on same line
            let mut args = Vec::new();
            if let Some(paren_start) = trimmed.find('(') {
                let paren_content = &trimmed[paren_start..];
                // Simple extraction of argument names
                for part in paren_content.split(',') {
                    let part = part.trim().trim_start_matches('(').trim_end_matches(')');
                    if let Some(arg_name) = part.split(':').next() {
                        let arg_name = arg_name.trim();
                        if !arg_name.is_empty() {
                            args.push(arg_name.to_string());
                        }
                    }
                }
            }
            gf.directives.push(GqlDirective { name, args });
            i += 1;
            continue;
        }

        // Block types: type, input, enum, interface, extend type
        let block_kind = if trimmed.starts_with("type ") {
            Some("type")
        } else if trimmed.starts_with("input ") {
            Some("input")
        } else if trimmed.starts_with("enum ") {
            Some("enum")
        } else if trimmed.starts_with("interface ") {
            Some("interface")
        } else if trimmed.starts_with("extend type ") {
            Some("extend type")
        } else {
            None
        };

        if let Some(kind) = block_kind {
            let after_kind = trimmed.strip_prefix(kind).unwrap_or("").trim();
            // Extract name and implements
            let name_part = after_kind.split('{').next().unwrap_or("").trim();
            let mut implements = Vec::new();
            let name;

            if name_part.contains("implements") {
                let parts: Vec<&str> = name_part.splitn(2, "implements").collect();
                name = parts[0].trim().to_string();
                if parts.len() > 1 {
                    implements = parts[1]
                        .split('&')
                        .flat_map(|s| s.split(','))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            } else {
                name = name_part.split_whitespace().next().unwrap_or("").to_string();
            }

            // Determine real kind for Query/Mutation/Subscription
            let display_kind = if kind == "type" {
                match name.as_str() {
                    "Query" => "query",
                    "Mutation" => "mutation",
                    "Subscription" => "subscription",
                    _ => "type",
                }
            } else {
                kind
            };

            // Collect fields inside { }
            let mut fields = Vec::new();
            if trimmed.contains('{') {
                let mut depth = 1i32;
                i += 1;
                while i < lines.len() && depth > 0 {
                    let line = lines[i].trim();
                    if line.contains('{') { depth += line.matches('{').count() as i32; }
                    if line.contains('}') { depth -= line.matches('}').count() as i32; }
                    if depth >= 1 && !line.is_empty() && !line.starts_with('#') && !line.starts_with('}') {
                        // Clean up the field line
                        let field_line = line.split('#').next().unwrap_or(line).trim();
                        if !field_line.is_empty() {
                            fields.push(field_line.to_string());
                        }
                    }
                    i += 1;
                }
            } else {
                i += 1;
                // Brace might be on next line
                if i < lines.len() && lines[i].trim() == "{" {
                    let mut depth = 1i32;
                    i += 1;
                    while i < lines.len() && depth > 0 {
                        let line = lines[i].trim();
                        if line.contains('{') { depth += line.matches('{').count() as i32; }
                        if line.contains('}') { depth -= line.matches('}').count() as i32; }
                        if depth >= 1 && !line.is_empty() && !line.starts_with('#') && !line.starts_with('}') {
                            let field_line = line.split('#').next().unwrap_or(line).trim();
                            if !field_line.is_empty() {
                                fields.push(field_line.to_string());
                            }
                        }
                        i += 1;
                    }
                }
            }

            gf.types.push(GqlType {
                kind: display_kind.to_string(),
                name,
                fields,
                implements,
            });
            continue;
        }

        i += 1;
    }

    Some(gf)
}

pub fn graphql_schema(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap graphql-schema <file.graphql | directory>".to_string();
    }

    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    ensure_schema_source(graph, target, "graphql");

    let files = collect_graphql_files(target);
    if files.is_empty() {
        return format!("No .graphql/.gql files found in: {target}");
    }

    let mut parsed: Vec<GqlFile> = files.iter().filter_map(|f| parse_graphql_file(f)).collect();
    parsed.sort_by(|a, b| a.path.cmp(&b.path));

    // Pass: register every GraphQL type as a typed node, with edges from
    // schema source and `implements` edges to interfaces.
    for gf in &parsed {
        let pf_id = format!("schema:graphql:{}", gf.path);
        for t in &gf.types {
            let type_id = format!("gql:{}::{}", gf.path, t.name);
            graph.ensure_typed_node(&type_id, EntityKind::GraphqlType, &[
                ("name", &t.name),
                ("kind", &t.kind),
                ("file", &gf.path),
                ("field_count", &t.fields.len().to_string()),
            ]);
            graph.add_edge(&pf_id, &type_id);
            // implements: T → InterfaceType edges
            for interface in &t.implements {
                let to = format!("gql:{}::{}", gf.path, interface);
                graph.add_edge(&type_id, &to);
            }
        }
    }

    // Aggregate stats
    let mut type_count = 0usize;
    let mut input_count = 0usize;
    let mut enum_count = 0usize;
    let mut interface_count = 0usize;
    let mut union_count = 0usize;
    let mut scalar_count = 0usize;
    let mut query_count = 0usize;
    let mut mutation_count = 0usize;
    let mut subscription_count = 0usize;
    let mut directive_count = 0usize;

    for gf in &parsed {
        for t in &gf.types {
            match t.kind.as_str() {
                "type" | "extend type" => type_count += 1,
                "input" => input_count += 1,
                "enum" => enum_count += 1,
                "interface" => interface_count += 1,
                "union" => union_count += 1,
                "scalar" => scalar_count += 1,
                "query" => query_count += t.fields.len(),
                "mutation" => mutation_count += t.fields.len(),
                "subscription" => subscription_count += t.fields.len(),
                _ => {}
            }
        }
        directive_count += gf.directives.len();
    }

    let mut out = String::new();
    out.push_str("=== GraphQL Schema ===\n\n");
    out.push_str(&format!("Files: {}\n", parsed.len()));
    out.push_str(&format!("Types: {type_count}\n"));
    out.push_str(&format!("Inputs: {input_count}\n"));
    out.push_str(&format!("Enums: {enum_count}\n"));
    out.push_str(&format!("Interfaces: {interface_count}\n"));
    out.push_str(&format!("Unions: {union_count}\n"));
    out.push_str(&format!("Scalars: {scalar_count}\n"));
    out.push_str(&format!("Queries: {query_count}\n"));
    out.push_str(&format!("Mutations: {mutation_count}\n"));
    out.push_str(&format!("Subscriptions: {subscription_count}\n"));
    if directive_count > 0 {
        out.push_str(&format!("Directives: {directive_count}\n"));
    }

    for gf in &parsed {
        if parsed.len() > 1 {
            out.push_str(&format!("\n── {} ──\n", gf.path));
        } else {
            out.push('\n');
        }

        for t in &gf.types {
            match t.kind.as_str() {
                "scalar" => {
                    out.push_str(&format!("scalar {}\n", t.name));
                }
                "union" => {
                    out.push_str(&format!("union {} = {}\n", t.name, t.fields.join(" | ")));
                }
                _ => {
                    let impl_str = if t.implements.is_empty() {
                        String::new()
                    } else {
                        format!(" implements {}", t.implements.join(" & "))
                    };
                    out.push_str(&format!("{} {}{} {{\n", t.kind, t.name, impl_str));
                    for field in &t.fields {
                        out.push_str(&format!("  {field}\n"));
                    }
                    out.push_str("}\n");
                }
            }
        }

        for d in &gf.directives {
            if d.args.is_empty() {
                out.push_str(&format!("directive @{}\n", d.name));
            } else {
                out.push_str(&format!("directive @{}({})\n", d.name, d.args.join(", ")));
            }
        }
    }

    out
}

// ═══════════════════════════════════════════════════════════════════════
//  4. docker_map — Parse docker-compose.yml files
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Default)]
struct DockerService {
    name: String,
    image: String,
    build: String,
    ports: Vec<String>,
    volumes: Vec<String>,
    environment: Vec<String>,
    depends_on: Vec<String>,
    networks: Vec<String>,
    command: String,
}

pub fn docker_map(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap docker-map <docker-compose.yml>".to_string();
    }

    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    ensure_schema_source(graph, target, "docker");

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let services = parse_docker_compose(&content);

    if services.is_empty() {
        return "No services found in docker-compose file.".to_string();
    }

    // Collect all exposed ports
    let mut all_ports: Vec<(String, String)> = Vec::new(); // (service, port)
    let mut all_volumes: BTreeSet<String> = BTreeSet::new();
    let mut dep_edges: Vec<(String, String)> = Vec::new(); // (from, to)

    for svc in &services {
        for port in &svc.ports {
            all_ports.push((svc.name.clone(), port.clone()));
        }
        for vol in &svc.volumes {
            all_volumes.insert(vol.clone());
        }
        for dep in &svc.depends_on {
            dep_edges.push((svc.name.clone(), dep.clone()));
        }
    }

    // Pass: register every service as a DockerService node + every depends_on
    // as a service→service edge. After this, `pagerank --type docker`
    // surfaces the most-depended-on services (typically databases / message
    // queues) and `meta-path docker->docker` shows dependency chains.
    let pf_id = format!("schema:docker:{target}");
    for svc in &services {
        let svc_id = format!("docker:{}", svc.name);
        graph.ensure_typed_node(&svc_id, EntityKind::DockerService, &[
            ("name", &svc.name),
            ("image", &svc.image),
            ("port_count", &svc.ports.len().to_string()),
        ]);
        graph.add_edge(&pf_id, &svc_id);
    }
    for (from, to) in &dep_edges {
        graph.add_edge(&format!("docker:{from}"), &format!("docker:{to}"));
    }

    let mut out = String::new();
    out.push_str("=== Docker Compose Map ===\n\n");
    out.push_str(&format!("Services: {}\n", services.len()));
    out.push_str(&format!("Exposed ports: {}\n", all_ports.len()));
    out.push_str(&format!("Volume mounts: {}\n", all_volumes.len()));
    out.push_str(&format!("Dependencies: {}\n", dep_edges.len()));

    // Service details
    out.push_str("\n── Services ──\n");
    for svc in &services {
        out.push_str(&format!("\n  {}\n", svc.name));
        if !svc.image.is_empty() {
            out.push_str(&format!("    image: {}\n", svc.image));
        }
        if !svc.build.is_empty() {
            out.push_str(&format!("    build: {}\n", svc.build));
        }
        if !svc.command.is_empty() {
            out.push_str(&format!("    command: {}\n", svc.command));
        }
        if !svc.ports.is_empty() {
            out.push_str("    ports:\n");
            for port in &svc.ports {
                out.push_str(&format!("      {port}\n"));
            }
        }
        if !svc.volumes.is_empty() {
            out.push_str("    volumes:\n");
            for vol in &svc.volumes {
                out.push_str(&format!("      {vol}\n"));
            }
        }
        if !svc.environment.is_empty() {
            out.push_str(&format!("    environment: {} vars\n", svc.environment.len()));
            for env in &svc.environment {
                // Hide values, show only keys
                let key = env.split('=').next().unwrap_or(env);
                out.push_str(&format!("      {key}\n"));
            }
        }
        if !svc.depends_on.is_empty() {
            out.push_str(&format!("    depends_on: {}\n", svc.depends_on.join(", ")));
        }
        if !svc.networks.is_empty() {
            out.push_str(&format!("    networks: {}\n", svc.networks.join(", ")));
        }
    }

    // Dependency graph
    if !dep_edges.is_empty() {
        out.push_str("\n── Dependency Graph ──\n");
        for (from, to) in &dep_edges {
            out.push_str(&format!("  {from} -> {to}\n"));
        }

        // Startup order (topological sort)
        let order = topo_sort_services(&services);
        if !order.is_empty() {
            out.push_str("\n── Startup Order ──\n");
            for (i, name) in order.iter().enumerate() {
                out.push_str(&format!("  {}. {name}\n", i + 1));
            }
        }
    }

    // Exposed ports summary
    if !all_ports.is_empty() {
        out.push_str("\n── Port Map ──\n");
        for (svc, port) in &all_ports {
            out.push_str(&format!("  {svc}: {port}\n"));
        }
    }

    out
}

fn parse_docker_compose(content: &str) -> Vec<DockerService> {
    let lines: Vec<&str> = content.lines().collect();
    let mut services: Vec<DockerService> = Vec::new();

    // Find the "services:" section
    let mut in_services = false;
    let mut _services_indent = 0usize;
    let mut current_service: Option<DockerService> = None;
    let mut service_indent = 0usize;
    let mut current_key = String::new();
    let mut _key_indent = 0usize;

    for line in &lines {
        let stripped = line.trim_end();
        if stripped.is_empty() || stripped.trim().starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let trimmed = stripped.trim();

        // Top-level key detection
        if indent == 0 {
            if trimmed == "services:" {
                in_services = true;
                _services_indent = 0;
            } else {
                // Flush current service
                if let Some(svc) = current_service.take() {
                    services.push(svc);
                }
                in_services = false;
            }
            current_key.clear();
            continue;
        }

        if !in_services {
            continue;
        }

        // Service name level (indent 2 typically)
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') && !trimmed.contains(' ') {
            // Flush previous service
            if let Some(svc) = current_service.take() {
                services.push(svc);
            }
            let name = trimmed.trim_end_matches(':').to_string();
            current_service = Some(DockerService {
                name,
                ..Default::default()
            });
            service_indent = 2;
            current_key.clear();
            continue;
        }

        // Inside a service
        if let Some(ref mut svc) = current_service {
            if indent <= service_indent {
                // Back at service level or above — could be another service
                // This case is handled above
                continue;
            }

            // Key-value pairs at service property level (indent 4)
            if indent == 4 {
                current_key.clear();

                if trimmed.starts_with("image:") {
                    svc.image = yaml_value(trimmed);
                } else if trimmed.starts_with("build:") {
                    let val = yaml_value(trimmed);
                    if !val.is_empty() {
                        svc.build = val;
                    } else {
                        current_key = "build".to_string();
                        _key_indent = indent;
                    }
                } else if trimmed.starts_with("command:") {
                    svc.command = yaml_value(trimmed);
                } else if trimmed == "ports:" {
                    current_key = "ports".to_string();
                    _key_indent = indent;
                } else if trimmed == "volumes:" {
                    current_key = "volumes".to_string();
                    _key_indent = indent;
                } else if trimmed == "environment:" {
                    current_key = "environment".to_string();
                    _key_indent = indent;
                } else if trimmed == "depends_on:" {
                    current_key = "depends_on".to_string();
                    _key_indent = indent;
                } else if trimmed == "networks:" {
                    current_key = "networks".to_string();
                    _key_indent = indent;
                }
                continue;
            }

            // List items under a key (indent 6+)
            if indent > 4 && !current_key.is_empty() {
                let item = if let Some(rest) = trimmed.strip_prefix("- ") {
                    rest.trim().trim_matches('"').trim_matches('\'').to_string()
                } else {
                    // key: value style (for environment)
                    trimmed.trim_matches('"').trim_matches('\'').to_string()
                };

                if item.is_empty() {
                    continue;
                }

                match current_key.as_str() {
                    "ports" => svc.ports.push(item),
                    "volumes" => svc.volumes.push(item),
                    "environment" => svc.environment.push(item),
                    "depends_on" => {
                        // depends_on can be list or map form
                        let dep = item.split(':').next().unwrap_or(&item).trim().to_string();
                        svc.depends_on.push(dep);
                    }
                    "networks" => svc.networks.push(item),
                    "build" => {
                        if trimmed.starts_with("context:") {
                            svc.build = yaml_value(trimmed);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Flush last service
    if let Some(svc) = current_service.take() {
        services.push(svc);
    }

    services
}

fn topo_sort_services(services: &[DockerService]) -> Vec<String> {
    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
    let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for svc in services {
        in_degree.entry(svc.name.clone()).or_insert(0);
        adj.entry(svc.name.clone()).or_default();
        for dep in &svc.depends_on {
            adj.entry(dep.clone()).or_default().push(svc.name.clone());
            *in_degree.entry(svc.name.clone()).or_insert(0) += 1;
            in_degree.entry(dep.clone()).or_insert(0);
        }
    }

    let mut queue: Vec<String> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(k, _)| k.clone())
        .collect();
    queue.sort();

    let mut order = Vec::new();
    while let Some(node) = queue.first().cloned() {
        queue.remove(0);
        order.push(node.clone());
        if let Some(neighbors) = adj.get(&node) {
            for n in neighbors {
                if let Some(deg) = in_degree.get_mut(n) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(n.clone());
                        queue.sort();
                    }
                }
            }
        }
    }

    order
}

// ═══════════════════════════════════════════════════════════════════════
//  5. terraform_map — Parse Terraform .tf files
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug)]
struct TfBlock {
    kind: String,    // resource, data, variable, output, module, provider
    block_type: String,  // e.g. "aws_instance" for resource
    name: String,
    attributes: BTreeMap<String, String>,
    file: String,
}

fn collect_tf_files(target: &str) -> Vec<String> {
    let path = Path::new(target);
    if path.is_file() {
        return vec![target.to_string()];
    }
    if path.is_dir() {
        let mut files = Vec::new();
        collect_tf_dir(path, &mut files);
        files.sort();
        return files;
    }
    Vec::new()
}

fn collect_tf_dir(dir: &Path, out: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // Skip .terraform directory
                if p.file_name().is_some_and(|n| n == ".terraform") {
                    continue;
                }
                collect_tf_dir(&p, out);
            } else if p.extension().is_some_and(|e| e == "tf") {
                out.push(p.to_string_lossy().to_string());
            }
        }
    }
}

fn parse_tf_files(files: &[String]) -> Vec<TfBlock> {
    let mut blocks = Vec::new();

    for file in files {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let trimmed = lines[i].trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                i += 1;
                continue;
            }

            // resource "type" "name" {
            if trimmed.starts_with("resource ") {
                if let Some(block) = parse_tf_block_header(trimmed, "resource", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // data "type" "name" {
            if trimmed.starts_with("data ") {
                if let Some(block) = parse_tf_block_header(trimmed, "data", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // variable "name" {
            if trimmed.starts_with("variable ") {
                if let Some(block) = parse_tf_block_header_single(trimmed, "variable", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // output "name" {
            if trimmed.starts_with("output ") {
                if let Some(block) = parse_tf_block_header_single(trimmed, "output", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // module "name" {
            if trimmed.starts_with("module ") {
                if let Some(block) = parse_tf_block_header_single(trimmed, "module", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // provider "name" {
            if trimmed.starts_with("provider ") {
                if let Some(block) = parse_tf_block_header_single(trimmed, "provider", file) {
                    let attrs = collect_tf_attributes(&lines, &mut i);
                    blocks.push(TfBlock { attributes: attrs, ..block });
                    continue;
                }
            }

            // terraform {
            if trimmed.starts_with("terraform ") || trimmed == "terraform{" || trimmed == "terraform {" {
                let attrs = collect_tf_attributes(&lines, &mut i);
                blocks.push(TfBlock {
                    kind: "terraform".to_string(),
                    block_type: String::new(),
                    name: String::new(),
                    attributes: attrs,
                    file: file.clone(),
                });
                continue;
            }

            i += 1;
        }
    }

    blocks
}

fn parse_tf_block_header(line: &str, kind: &str, file: &str) -> Option<TfBlock> {
    // resource "aws_instance" "web" {
    let after_kind = line.strip_prefix(kind)?.trim();
    let mut quoted = Vec::new();
    let mut in_quote = false;
    let mut current = String::new();

    for ch in after_kind.chars() {
        if ch == '"' {
            if in_quote {
                quoted.push(current.clone());
                current.clear();
                in_quote = false;
            } else {
                in_quote = true;
            }
        } else if in_quote {
            current.push(ch);
        }
    }

    if quoted.len() >= 2 {
        Some(TfBlock {
            kind: kind.to_string(),
            block_type: quoted[0].clone(),
            name: quoted[1].clone(),
            attributes: BTreeMap::new(),
            file: file.to_string(),
        })
    } else {
        None
    }
}

fn parse_tf_block_header_single(line: &str, kind: &str, file: &str) -> Option<TfBlock> {
    // variable "name" { or module "name" {
    let after_kind = line.strip_prefix(kind)?.trim();
    let mut quoted = Vec::new();
    let mut in_quote = false;
    let mut current = String::new();

    for ch in after_kind.chars() {
        if ch == '"' {
            if in_quote {
                quoted.push(current.clone());
                current.clear();
                in_quote = false;
            } else {
                in_quote = true;
            }
        } else if in_quote {
            current.push(ch);
        }
    }

    if !quoted.is_empty() {
        Some(TfBlock {
            kind: kind.to_string(),
            block_type: String::new(),
            name: quoted[0].clone(),
            attributes: BTreeMap::new(),
            file: file.to_string(),
        })
    } else {
        None
    }
}

fn collect_tf_attributes(lines: &[&str], i: &mut usize) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();

    // Find opening brace
    while *i < lines.len() {
        let trimmed = lines[*i].trim();
        if trimmed.contains('{') {
            break;
        }
        *i += 1;
    }

    if *i >= lines.len() {
        return attrs;
    }

    let mut depth = 0i32;
    // Count braces on the opening line
    for ch in lines[*i].chars() {
        if ch == '{' { depth += 1; }
        if ch == '}' { depth -= 1; }
    }
    *i += 1;

    while *i < lines.len() && depth > 0 {
        let trimmed = lines[*i].trim();
        for ch in trimmed.chars() {
            if ch == '{' { depth += 1; }
            if ch == '}' { depth -= 1; }
        }

        // Only collect top-level attributes (depth == 1)
        if depth == 1 && trimmed.contains('=') && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
            let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().to_string();
                let val = parts[1].trim().trim_matches('"').to_string();
                attrs.insert(key, val);
            }
        }

        *i += 1;
    }

    attrs
}

pub fn terraform_map(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap terraform-map <file.tf | directory>".to_string();
    }

    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    ensure_schema_source(graph, target, "terraform");

    let files = collect_tf_files(target);
    if files.is_empty() {
        return format!("No .tf files found in: {target}");
    }

    let blocks = parse_tf_files(&files);

    if blocks.is_empty() {
        return "No Terraform blocks found.".to_string();
    }

    // Pass: register every Terraform block as a TerraformResource node.
    // Cross-reference attributes that mention "<kind>.<block_type>.<name>"
    // patterns (e.g. "aws_subnet.main.id") become edges between blocks.
    let pf_id = format!("schema:terraform:{target}");
    for block in &blocks {
        let block_id = format!("tf:{}.{}.{}", block.kind, block.block_type, block.name);
        graph.ensure_typed_node(&block_id, EntityKind::TerraformResource, &[
            ("kind", &block.kind),
            ("type", &block.block_type),
            ("name", &block.name),
            ("file", &block.file),
        ]);
        graph.add_edge(&pf_id, &block_id);
    }
    // Reference edges: scan each block's attribute values for tokens of
    // the form `<type>.<name>.<field>` matching another block. This is
    // approximate (proper Terraform reference resolution requires full
    // HCL parse) but catches the common case.
    let block_ids: std::collections::HashMap<String, String> = blocks.iter()
        .map(|b| (format!("{}.{}", b.block_type, b.name),
                  format!("tf:{}.{}.{}", b.kind, b.block_type, b.name)))
        .collect();
    for block in &blocks {
        let from = format!("tf:{}.{}.{}", block.kind, block.block_type, block.name);
        for value in block.attributes.values() {
            for tok in value.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.') {
                let parts: Vec<&str> = tok.split('.').collect();
                if parts.len() >= 2 {
                    let key = format!("{}.{}", parts[0], parts[1]);
                    if let Some(to) = block_ids.get(&key) {
                        if to != &from {
                            graph.add_edge(&from, to);
                        }
                    }
                }
            }
        }
    }

    // Categorize
    let mut resources: Vec<&TfBlock> = Vec::new();
    let mut data_sources: Vec<&TfBlock> = Vec::new();
    let mut variables: Vec<&TfBlock> = Vec::new();
    let mut outputs: Vec<&TfBlock> = Vec::new();
    let mut modules: Vec<&TfBlock> = Vec::new();
    let mut providers: BTreeSet<String> = BTreeSet::new();

    for block in &blocks {
        match block.kind.as_str() {
            "resource" => resources.push(block),
            "data" => data_sources.push(block),
            "variable" => variables.push(block),
            "output" => outputs.push(block),
            "module" => modules.push(block),
            "provider" => { providers.insert(block.name.clone()); }
            _ => {}
        }
    }

    // Infer providers from resource types
    for r in &resources {
        if let Some(provider) = r.block_type.split('_').next() {
            providers.insert(provider.to_string());
        }
    }
    for d in &data_sources {
        if let Some(provider) = d.block_type.split('_').next() {
            providers.insert(provider.to_string());
        }
    }

    let mut out = String::new();
    out.push_str("=== Terraform Map ===\n\n");
    out.push_str(&format!("Files: {}\n", files.len()));
    out.push_str(&format!("Resources: {}\n", resources.len()));
    out.push_str(&format!("Data sources: {}\n", data_sources.len()));
    out.push_str(&format!("Variables: {}\n", variables.len()));
    out.push_str(&format!("Outputs: {}\n", outputs.len()));
    out.push_str(&format!("Modules: {}\n", modules.len()));
    out.push_str(&format!("Providers: {}\n", providers.len()));

    // Providers
    if !providers.is_empty() {
        out.push_str("\n── Providers ──\n");
        for p in &providers {
            out.push_str(&format!("  {p}\n"));
        }
    }

    // Resources grouped by type
    if !resources.is_empty() {
        out.push_str("\n── Resources ──\n");
        let mut by_type: BTreeMap<&str, Vec<&TfBlock>> = BTreeMap::new();
        for r in &resources {
            by_type.entry(&r.block_type).or_default().push(r);
        }
        for (typ, items) in &by_type {
            out.push_str(&format!("\n  {typ}:\n"));
            for item in items {
                let file_short = Path::new(&item.file)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                out.push_str(&format!("    {} ({})\n", item.name, file_short));
            }
        }
    }

    // Data sources
    if !data_sources.is_empty() {
        out.push_str("\n── Data Sources ──\n");
        for d in &data_sources {
            let file_short = Path::new(&d.file)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push_str(&format!("  {}.{} ({})\n", d.block_type, d.name, file_short));
        }
    }

    // Modules
    if !modules.is_empty() {
        out.push_str("\n── Modules ──\n");
        for m in &modules {
            let source = m.attributes.get("source").cloned().unwrap_or_default();
            let file_short = Path::new(&m.file)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            if source.is_empty() {
                out.push_str(&format!("  {} ({})\n", m.name, file_short));
            } else {
                out.push_str(&format!("  {} -> {} ({})\n", m.name, source, file_short));
            }
        }
    }

    // Variables
    if !variables.is_empty() {
        out.push_str("\n── Variables ──\n");
        for v in &variables {
            let typ = v.attributes.get("type").cloned().unwrap_or_default();
            let default = v.attributes.get("default").map(|d| format!(" = {d}")).unwrap_or_default();
            if typ.is_empty() {
                out.push_str(&format!("  {}{default}\n", v.name));
            } else {
                out.push_str(&format!("  {} : {typ}{default}\n", v.name));
            }
        }
    }

    // Outputs
    if !outputs.is_empty() {
        out.push_str("\n── Outputs ──\n");
        for o in &outputs {
            let value = o.attributes.get("value").cloned().unwrap_or_default();
            if value.is_empty() {
                out.push_str(&format!("  {}\n", o.name));
            } else {
                let short = if value.len() > 60 { &value[..60] } else { &value };
                out.push_str(&format!("  {} = {short}\n", o.name));
            }
        }
    }

    // Cross-references: look for resource references in attribute values
    let mut refs: Vec<(String, String)> = Vec::new();
    for block in &blocks {
        let block_id = if block.block_type.is_empty() {
            format!("{}.{}", block.kind, block.name)
        } else {
            format!("{}.{}.{}", block.kind, block.block_type, block.name)
        };
        for val in block.attributes.values() {
            // Look for references like aws_instance.web or module.vpc
            for r in &resources {
                let ref_pattern = format!("{}.{}", r.block_type, r.name);
                if val.contains(&ref_pattern) && block_id != format!("resource.{}", ref_pattern) {
                    refs.push((block_id.clone(), format!("resource.{ref_pattern}")));
                }
            }
            for m in &modules {
                let ref_pattern = format!("module.{}", m.name);
                if val.contains(&ref_pattern) && !block_id.starts_with(&ref_pattern) {
                    refs.push((block_id.clone(), ref_pattern));
                }
            }
        }
    }

    refs.sort();
    refs.dedup();
    if !refs.is_empty() {
        out.push_str("\n── Cross-References ──\n");
        for (from, to) in &refs {
            out.push_str(&format!("  {from} -> {to}\n"));
        }
    }

    out
}
