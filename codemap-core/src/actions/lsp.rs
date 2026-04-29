use crate::types::Graph;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

// ── LSP Client ──────────────────────────────────────────────────────

const TIMEOUT: Duration = Duration::from_secs(5);

struct LspClient {
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: i64,
    /// Responses keyed by request id
    pending: HashMap<i64, Value>,
    /// Notifications collected (method, params)
    notifications: Vec<(String, Value)>,
    /// Keep the child handle so we can kill/wait
    child: std::process::Child,
}

impl LspClient {
    fn start(server_cmd: &str, root_dir: &Path) -> Result<Self, String> {
        let parts: Vec<&str> = server_cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Empty server command".into());
        }
        let mut cmd = Command::new(parts[0]);
        for arg in &parts[1..] {
            cmd.arg(arg);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start LSP server '{}': {}", server_cmd, e))?;

        let stdin = child.stdin.take().ok_or("No stdin on child process")?;
        let stdout = child.stdout.take().ok_or("No stdout on child process")?;
        let reader = BufReader::new(stdout);

        let mut client = LspClient {
            stdin,
            reader,
            next_id: 1,
            pending: HashMap::new(),
            notifications: Vec::new(),
            child,
        };

        // Send initialize
        let root_uri = format!("file://{}", root_dir.to_string_lossy());
        let pid = std::process::id();
        let init_params = json!({
            "processId": pid,
            "capabilities": {
                "textDocument": {
                    "documentSymbol": {
                        "hierarchicalDocumentSymbolSupport": true
                    },
                    "references": {},
                    "callHierarchy": {},
                    "hover": {},
                    "publishDiagnostics": {}
                }
            },
            "rootUri": root_uri
        });

        let _resp = client.request("initialize", init_params)?;

        // Send initialized notification
        client.notify("initialized", json!({}))?;

        Ok(client)
    }

    fn send_raw(&mut self, msg: &Value) -> Result<(), String> {
        let body = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        self.stdin
            .write_all(header.as_bytes())
            .map_err(|e| format!("Write header: {}", e))?;
        self.stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("Write body: {}", e))?;
        self.stdin
            .flush()
            .map_err(|e| format!("Flush: {}", e))?;
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        self.send_raw(&msg)?;
        self.wait_for_response(id)
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        self.send_raw(&msg)
    }

    fn read_message(&mut self) -> Result<Value, String> {
        // Read headers until empty line
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .map_err(|e| format!("Read header line: {}", e))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some(val) = trimmed.strip_prefix("Content-Length:") {
                content_length = val
                    .trim()
                    .parse()
                    .map_err(|e| format!("Parse Content-Length: {}", e))?;
            }
        }
        if content_length == 0 {
            return Err("No Content-Length in response".into());
        }
        let mut buf = vec![0u8; content_length];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| format!("Read body ({} bytes): {}", content_length, e))?;
        let text = String::from_utf8(buf).map_err(|e| format!("UTF-8 decode: {}", e))?;
        serde_json::from_str(&text).map_err(|e| format!("JSON parse: {}", e))
    }

    fn wait_for_response(&mut self, id: i64) -> Result<Value, String> {
        // Check if we already have it from a prior read
        if let Some(resp) = self.pending.remove(&id) {
            return extract_result(resp);
        }

        let deadline = std::time::Instant::now() + TIMEOUT;

        loop {
            if std::time::Instant::now() > deadline {
                return Err(format!(
                    "Timeout ({}s) waiting for response to request id={}",
                    TIMEOUT.as_secs(),
                    id
                ));
            }

            // Blocking read — the LSP server should respond quickly.
            // If it hangs, we'll hit the deadline on the next iteration
            // (but this read itself will block). For a CLI tool this is acceptable.
            let msg = self.read_message()?;

            if let Some(resp_id) = msg.get("id").and_then(|v| v.as_i64()) {
                if resp_id == id {
                    return extract_result(msg);
                }
                self.pending.insert(resp_id, msg);
            } else {
                // Notification (no id)
                let method = msg
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                let params = msg.get("params").cloned().unwrap_or(json!(null));
                self.notifications.push((method, params));
            }
        }
    }

    fn open_file(&mut self, file_path: &Path) -> Result<(), String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Read file {}: {}", file_path.display(), e))?;
        let uri = path_to_uri(file_path);
        let lang_id = detect_language(file_path);
        self.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": lang_id,
                    "version": 1,
                    "text": content
                }
            }),
        )
    }

    fn shutdown(mut self) {
        // Send shutdown request (best-effort)
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "shutdown",
            "params": null
        });
        let _ = self.send_raw(&msg);
        // Try to read shutdown response (ignore errors)
        let _ = self.read_message();
        // Send exit notification
        let exit_msg = json!({
            "jsonrpc": "2.0",
            "method": "exit",
            "params": null
        });
        let _ = self.send_raw(&exit_msg);
        // Kill the process if still alive
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Drain pending notifications from the server (best-effort, short wait).
    /// Useful for collecting diagnostics which arrive as notifications.
    fn drain_notifications(&mut self) {
        // Give the server a brief window to send diagnostics
        std::thread::sleep(Duration::from_millis(500));

        // Try to read messages non-destructively. Since our reader is blocking,
        // we'll use fill_buf to check if data is available.
        loop {
            // Check if there's data in the buffer
            match self.reader.fill_buf() {
                Ok([]) => break,
                Err(_) => break,
                _ => {}
            }
            match self.read_message() {
                Ok(msg) => {
                    if let Some(resp_id) = msg.get("id").and_then(|v| v.as_i64()) {
                        self.pending.insert(resp_id, msg);
                    } else {
                        let method = msg
                            .get("method")
                            .and_then(|m| m.as_str())
                            .unwrap_or("")
                            .to_string();
                        let params = msg.get("params").cloned().unwrap_or(json!(null));
                        self.notifications.push((method, params));
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn extract_result(msg: Value) -> Result<Value, String> {
    if let Some(err) = msg.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        return Err(format!("LSP error ({}): {}", code, message));
    }
    Ok(msg.get("result").cloned().unwrap_or(json!(null)))
}

// ── URI / Path Helpers ──────────────────────────────────────────────

fn path_to_uri(path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    format!("file://{}", abs.to_string_lossy())
}

fn uri_to_path(uri: &str) -> String {
    uri.strip_prefix("file://").unwrap_or(uri).to_string()
}

fn detect_language(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "rs" => "rust",
        "py" => "python",
        "ts" | "tsx" => "typescript",
        "js" | "jsx" => "javascript",
        "go" => "go",
        "java" => "java",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp",
        "rb" => "ruby",
        "php" => "php",
        _ => "plaintext",
    }
}

// ── Target Parsing ──────────────────────────────────────────────────

/// Parse target into (server_command, path_or_loc).
/// Format: `<server_command> <file_or_dir>` or `<server_command> <file>:<line>:<col>`
fn parse_target(target: &str) -> Result<(String, String), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(
            "Usage: <server_command> <file_or_dir>\n\
             Examples:\n  \
               rust-analyzer src/main.rs\n  \
               pylsp .\n  \
               rust-analyzer src/main.rs:42:10"
                .into(),
        );
    }
    // Last whitespace-separated token is the path/location,
    // everything before it is the server command (which may have arguments).
    let parts: Vec<&str> = target.rsplitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(format!(
            "Usage: <server_command> <file_or_dir>\nGot: '{}'",
            target
        ));
    }
    let file_part = parts[0].to_string();
    let server_cmd = parts[1].to_string();
    Ok((server_cmd, file_part))
}

/// Parse a location like `file:line:col` or just `file`.
fn parse_location(loc: &str) -> (PathBuf, Option<(u32, u32)>) {
    // Try to match file:line:col from the right side
    // Be careful with Windows paths (C:\...) though unlikely on macOS/Linux
    let parts: Vec<&str> = loc.rsplitn(3, ':').collect();
    if parts.len() == 3 {
        if let (Ok(col), Ok(line)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            let file = PathBuf::from(parts[2]);
            return (file, Some((line, col)));
        }
    }
    (PathBuf::from(loc), None)
}

fn resolve_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}

fn root_dir_from_path(path: &Path) -> PathBuf {
    let abs = resolve_path(path);
    if abs.is_dir() {
        abs
    } else {
        abs.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"))
    }
}

// ── File Collection ─────────────────────────────────────────────────

fn collect_files(path: &Path) -> Vec<PathBuf> {
    let abs = resolve_path(path);
    if abs.is_file() {
        return vec![abs];
    }
    if abs.is_dir() {
        let mut files = Vec::new();
        collect_files_recursive(&abs, &mut files, 0);
        files.sort();
        return files;
    }
    Vec::new()
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>, depth: usize) {
    if depth > 10 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.')
            || name_str == "node_modules"
            || name_str == "target"
            || name_str == "__pycache__"
            || name_str == "venv"
        {
            continue;
        }
        if path.is_dir() {
            collect_files_recursive(&path, files, depth + 1);
        } else if path.is_file() && is_source_file(&path) {
            files.push(path);
        }
    }
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        "rs" | "py" | "ts" | "tsx" | "js" | "jsx" | "go" | "java" | "c" | "h" | "cpp" | "cc"
            | "cxx" | "hpp" | "hxx" | "rb" | "php"
    )
}

// ── Symbol / Diagnostic Formatting ──────────────────────────────────

fn symbol_kind_name(kind: i64) -> &'static str {
    match kind {
        1 => "File",
        2 => "Module",
        3 => "Namespace",
        4 => "Package",
        5 => "Class",
        6 => "Method",
        7 => "Property",
        8 => "Field",
        9 => "Constructor",
        10 => "Enum",
        11 => "Interface",
        12 => "Function",
        13 => "Variable",
        14 => "Constant",
        15 => "String",
        16 => "Number",
        17 => "Boolean",
        18 => "Array",
        19 => "Object",
        20 => "Key",
        21 => "Null",
        22 => "EnumMember",
        23 => "Struct",
        24 => "Event",
        25 => "Operator",
        26 => "TypeParameter",
        _ => "Unknown",
    }
}

fn severity_name(sev: i64) -> &'static str {
    match sev {
        1 => "Error",
        2 => "Warning",
        3 => "Info",
        4 => "Hint",
        _ => "Unknown",
    }
}

fn format_range(range: &Value) -> String {
    let start_line = range
        .get("start")
        .and_then(|s| s.get("line"))
        .and_then(|l| l.as_u64())
        .map(|l| l + 1) // LSP lines are 0-based
        .unwrap_or(0);
    let end_line = range
        .get("end")
        .and_then(|e| e.get("line"))
        .and_then(|l| l.as_u64())
        .map(|l| l + 1)
        .unwrap_or(0);
    if start_line == end_line {
        format!("L{}", start_line)
    } else {
        format!("L{}-{}", start_line, end_line)
    }
}

fn format_symbols(output: &mut String, symbols: &[Value], indent: usize) {
    let prefix = "  ".repeat(indent);
    for sym in symbols {
        let name = sym
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let kind = sym.get("kind").and_then(|k| k.as_i64()).unwrap_or(0);
        let kind_name = symbol_kind_name(kind);

        let range = sym
            .get("range")
            .or_else(|| sym.get("location").and_then(|l| l.get("range")));
        let range_str = range.map(format_range).unwrap_or_default();

        output.push_str(&format!("{}{} {} ({})\n", prefix, kind_name, name, range_str));

        if let Some(children) = sym.get("children").and_then(|c| c.as_array()) {
            format_symbols(output, children, indent + 1);
        }
    }
}

// ── Hover Type Extraction ───────────────────────────────────────────

fn collect_symbol_positions(symbols: &[Value]) -> Vec<(String, i64, u64, u64)> {
    let mut positions = Vec::new();
    collect_symbol_positions_inner(symbols, &mut positions);
    positions
}

fn collect_symbol_positions_inner(
    symbols: &[Value],
    positions: &mut Vec<(String, i64, u64, u64)>,
) {
    for sym in symbols {
        let name = sym
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let kind = sym.get("kind").and_then(|k| k.as_i64()).unwrap_or(0);

        let sel_range = sym
            .get("selectionRange")
            .or_else(|| sym.get("range"))
            .or_else(|| sym.get("location").and_then(|l| l.get("range")));

        if let Some(range) = sel_range {
            let line = range
                .get("start")
                .and_then(|s| s.get("line"))
                .and_then(|l| l.as_u64())
                .unwrap_or(0);
            let col = range
                .get("start")
                .and_then(|s| s.get("character"))
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            positions.push((name, kind, line, col));
        }

        if let Some(children) = sym.get("children").and_then(|c| c.as_array()) {
            collect_symbol_positions_inner(children, positions);
        }
    }
}

fn extract_hover_type(hover: &Value) -> String {
    let contents = match hover.get("contents") {
        Some(c) => c,
        None => return String::new(),
    };

    // MarkupContent { kind, value }
    if let Some(value) = contents.get("value").and_then(|v| v.as_str()) {
        return first_meaningful_line(&strip_code_fences(value));
    }
    // Plain string
    if let Some(s) = contents.as_str() {
        return first_meaningful_line(&strip_code_fences(s));
    }
    // Array of MarkedString
    if let Some(arr) = contents.as_array() {
        for item in arr {
            if let Some(value) = item.get("value").and_then(|v| v.as_str()) {
                let line = first_meaningful_line(&strip_code_fences(value));
                if !line.is_empty() {
                    return line;
                }
            }
            if let Some(s) = item.as_str() {
                if !s.trim().is_empty() {
                    return s.trim().to_string();
                }
            }
        }
    }
    String::new()
}

fn first_meaningful_line(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if line.len() > 120 {
        format!("{}...", &line[..120])
    } else {
        line.to_string()
    }
}

fn strip_code_fences(s: &str) -> String {
    let mut lines: Vec<&str> = s.lines().collect();
    if !lines.is_empty() && lines[0].starts_with("```") {
        lines.remove(0);
    }
    if !lines.is_empty() && lines.last().is_some_and(|l| l.starts_with("```")) {
        lines.pop();
    }
    lines.join("\n")
}

// ═══════════════════════════════════════════════════════════════════
// Actions
// ═══════════════════════════════════════════════════════════════════

/// Extract document symbols from files via a running LSP server.
///
/// Target format: `<server_command> <file_or_dir>`
/// Examples: `rust-analyzer src/main.rs`, `pylsp .`
pub fn lsp_symbols(_graph: &mut Graph, target: &str) -> String {
    let (server_cmd, file_part) = match parse_target(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (path, _) = parse_location(&file_part);
    let abs_path = resolve_path(&path);
    let root = root_dir_from_path(&path);

    let mut client = match LspClient::start(&server_cmd, &root) {
        Ok(c) => c,
        Err(e) => return format!("Error: {}", e),
    };

    let files = collect_files(&abs_path);
    if files.is_empty() {
        client.shutdown();
        return format!("No source files found at: {}", abs_path.display());
    }

    let mut output = String::new();
    output.push_str("=== LSP Document Symbols ===\n");

    for file in &files {
        if let Err(e) = client.open_file(file) {
            output.push_str(&format!("\n# {} (error opening: {})\n", file.display(), e));
            continue;
        }

        let uri = path_to_uri(file);
        let result = client.request(
            "textDocument/documentSymbol",
            json!({ "textDocument": { "uri": uri } }),
        );

        match result {
            Ok(symbols) => {
                if let Some(arr) = symbols.as_array() {
                    if !arr.is_empty() {
                        let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy();
                        output.push_str(&format!("\n# {}\n", rel));
                        format_symbols(&mut output, arr, 0);
                    }
                }
            }
            Err(e) => {
                let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy();
                output.push_str(&format!("\n# {} (error: {})\n", rel, e));
            }
        }
    }

    client.shutdown();

    if output == "=== LSP Document Symbols ===\n" {
        output.push_str("\nNo symbols found.\n");
    }
    output
}

/// Find all references to a symbol at a given position.
///
/// Target format: `<server_command> <file>:<line>:<col>`
/// Example: `rust-analyzer src/main.rs:42:10`
pub fn lsp_references(_graph: &mut Graph, target: &str) -> String {
    let (server_cmd, file_part) = match parse_target(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (path, pos) = parse_location(&file_part);
    let (line, col) = match pos {
        Some(lc) => lc,
        None => {
            return format!(
                "Usage: <server_command> <file>:<line>:<col>\n\
                 Example: rust-analyzer src/main.rs:42:10\n\
                 Got: '{}'",
                file_part
            );
        }
    };

    let abs_path = resolve_path(&path);
    let root = root_dir_from_path(&path);

    let mut client = match LspClient::start(&server_cmd, &root) {
        Ok(c) => c,
        Err(e) => return format!("Error: {}", e),
    };

    if let Err(e) = client.open_file(&abs_path) {
        client.shutdown();
        return format!("Error opening file: {}", e);
    }

    let uri = path_to_uri(&abs_path);
    let result = client.request(
        "textDocument/references",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line - 1, "character": col - 1 },
            "context": { "includeDeclaration": true }
        }),
    );

    client.shutdown();

    match result {
        Ok(refs) => {
            let mut output = String::new();
            output.push_str(&format!(
                "=== LSP References ({}:{}:{}) ===\n",
                path.display(),
                line,
                col
            ));
            if let Some(arr) = refs.as_array() {
                if arr.is_empty() {
                    output.push_str("No references found.\n");
                } else {
                    output.push_str(&format!("{} references:\n\n", arr.len()));
                    for loc in arr {
                        let loc_uri = loc
                            .get("uri")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        let loc_path = uri_to_path(loc_uri);
                        let range = loc.get("range");
                        let loc_line = range
                            .and_then(|r| r.get("start"))
                            .and_then(|s| s.get("line"))
                            .and_then(|l| l.as_u64())
                            .map(|l| l + 1)
                            .unwrap_or(0);
                        let loc_col = range
                            .and_then(|r| r.get("start"))
                            .and_then(|s| s.get("character"))
                            .and_then(|c| c.as_u64())
                            .map(|c| c + 1)
                            .unwrap_or(0);
                        let display_path =
                            if let Ok(rel) = PathBuf::from(&loc_path).strip_prefix(&root) {
                                rel.to_string_lossy().to_string()
                            } else {
                                loc_path
                            };
                        output.push_str(&format!(
                            "  {}:{}:{}\n",
                            display_path, loc_line, loc_col
                        ));
                    }
                }
            } else {
                output.push_str("No references found (server returned null).\n");
            }
            output
        }
        Err(e) => format!("Error: {}", e),
    }
}

/// Get incoming/outgoing call hierarchy for a symbol.
///
/// Target format: `<server_command> <file>:<line>:<col>`
/// Example: `rust-analyzer src/main.rs:42:10`
pub fn lsp_calls(_graph: &mut Graph, target: &str) -> String {
    let (server_cmd, file_part) = match parse_target(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (path, pos) = parse_location(&file_part);
    let (line, col) = match pos {
        Some(lc) => lc,
        None => {
            return format!(
                "Usage: <server_command> <file>:<line>:<col>\n\
                 Example: rust-analyzer src/main.rs:42:10\n\
                 Got: '{}'",
                file_part
            );
        }
    };

    let abs_path = resolve_path(&path);
    let root = root_dir_from_path(&path);

    let mut client = match LspClient::start(&server_cmd, &root) {
        Ok(c) => c,
        Err(e) => return format!("Error: {}", e),
    };

    if let Err(e) = client.open_file(&abs_path) {
        client.shutdown();
        return format!("Error opening file: {}", e);
    }

    let uri = path_to_uri(&abs_path);

    // Step 1: Prepare call hierarchy
    let prepare_result = client.request(
        "textDocument/prepareCallHierarchy",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line - 1, "character": col - 1 }
        }),
    );

    let items = match prepare_result {
        Ok(ref v) => v.as_array().cloned().unwrap_or_default(),
        Err(e) => {
            client.shutdown();
            return format!(
                "Call hierarchy not supported or error: {}\n\
                 (The LSP server may not support textDocument/prepareCallHierarchy)",
                e
            );
        }
    };

    if items.is_empty() {
        client.shutdown();
        return format!(
            "No call hierarchy item found at {}:{}:{}",
            path.display(),
            line,
            col
        );
    }

    let item = &items[0];
    let item_name = item
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("<unknown>");
    let mut output = String::new();
    output.push_str(&format!("=== LSP Call Hierarchy: {} ===\n", item_name));

    // Step 2: Incoming calls
    output.push_str("\n--- Incoming Calls (callers) ---\n");
    match client.request("callHierarchy/incomingCalls", json!({ "item": item })) {
        Ok(ref v) => {
            if let Some(arr) = v.as_array() {
                if arr.is_empty() {
                    output.push_str("  (none)\n");
                } else {
                    for call in arr {
                        format_call_item(&mut output, call, "from", &root);
                    }
                }
            } else {
                output.push_str("  (none)\n");
            }
        }
        Err(e) => output.push_str(&format!("  Error: {}\n", e)),
    }

    // Step 3: Outgoing calls
    output.push_str("\n--- Outgoing Calls (callees) ---\n");
    match client.request("callHierarchy/outgoingCalls", json!({ "item": item })) {
        Ok(ref v) => {
            if let Some(arr) = v.as_array() {
                if arr.is_empty() {
                    output.push_str("  (none)\n");
                } else {
                    for call in arr {
                        format_call_item(&mut output, call, "to", &root);
                    }
                }
            } else {
                output.push_str("  (none)\n");
            }
        }
        Err(e) => output.push_str(&format!("  Error: {}\n", e)),
    }

    client.shutdown();
    output
}

fn format_call_item(output: &mut String, call: &Value, key: &str, root: &Path) {
    let empty = json!({});
    let target_item = call.get(key).unwrap_or(&empty);
    let name = target_item
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("<unknown>");
    let call_uri = target_item
        .get("uri")
        .and_then(|u| u.as_str())
        .unwrap_or("");
    let call_path = uri_to_path(call_uri);
    let range = target_item.get("range");
    let call_line = range
        .and_then(|r| r.get("start"))
        .and_then(|s| s.get("line"))
        .and_then(|l| l.as_u64())
        .map(|l| l + 1)
        .unwrap_or(0);
    let display_path = if let Ok(rel) = PathBuf::from(&call_path).strip_prefix(root) {
        rel.to_string_lossy().to_string()
    } else {
        call_path
    };
    output.push_str(&format!("  {} ({}:{})\n", name, display_path, call_line));
}

/// Get diagnostics (errors, warnings) from the LSP server.
///
/// Target format: `<server_command> <file_or_dir>`
/// Example: `rust-analyzer src/`, `pylsp .`
pub fn lsp_diagnostics(_graph: &mut Graph, target: &str) -> String {
    let (server_cmd, file_part) = match parse_target(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (path, _) = parse_location(&file_part);
    let abs_path = resolve_path(&path);
    let root = root_dir_from_path(&path);

    let mut client = match LspClient::start(&server_cmd, &root) {
        Ok(c) => c,
        Err(e) => return format!("Error: {}", e),
    };

    let files = collect_files(&abs_path);
    if files.is_empty() {
        client.shutdown();
        return format!("No source files found at: {}", abs_path.display());
    }

    // Open all files to trigger diagnostics
    for file in &files {
        let _ = client.open_file(file);
    }

    // Wait for the server to send publishDiagnostics notifications
    client.drain_notifications();

    // Collect diagnostics from notifications
    let mut diag_map: HashMap<String, Vec<(i64, u64, String)>> = HashMap::new();
    for (method, params) in &client.notifications {
        if method == "textDocument/publishDiagnostics" {
            let uri = params
                .get("uri")
                .and_then(|u| u.as_str())
                .unwrap_or("");
            let file_path = uri_to_path(uri);
            let display_path = if let Ok(rel) = PathBuf::from(&file_path).strip_prefix(&root) {
                rel.to_string_lossy().to_string()
            } else {
                file_path
            };

            if let Some(diagnostics) = params.get("diagnostics").and_then(|d| d.as_array()) {
                for diag in diagnostics {
                    let severity = diag
                        .get("severity")
                        .and_then(|s| s.as_i64())
                        .unwrap_or(0);
                    let message = diag
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    let line = diag
                        .get("range")
                        .and_then(|r| r.get("start"))
                        .and_then(|s| s.get("line"))
                        .and_then(|l| l.as_u64())
                        .map(|l| l + 1)
                        .unwrap_or(0);
                    diag_map
                        .entry(display_path.clone())
                        .or_default()
                        .push((severity, line, message));
                }
            }
        }
    }

    client.shutdown();

    let mut output = String::new();
    output.push_str("=== LSP Diagnostics ===\n");

    if diag_map.is_empty() {
        output.push_str("\nNo diagnostics reported.\n");
        return output;
    }

    let mut total = 0usize;
    let mut errors = 0usize;
    let mut warnings = 0usize;

    let mut sorted_files: Vec<_> = diag_map.into_iter().collect();
    sorted_files.sort_by(|a, b| a.0.cmp(&b.0));

    for (file, mut diags) in sorted_files {
        diags.sort_by_key(|d| (d.0, d.1));
        output.push_str(&format!("\n# {} ({} issues)\n", file, diags.len()));
        for (severity, line, message) in &diags {
            let sev_name = severity_name(*severity);
            match severity {
                1 => errors += 1,
                2 => warnings += 1,
                _ => {}
            }
            total += 1;
            output.push_str(&format!("  L{} [{}] {}\n", line, sev_name, message));
        }
    }

    output.push_str(&format!(
        "\nTotal: {} ({} errors, {} warnings)\n",
        total, errors, warnings
    ));
    output
}

/// Extract type information using hover for each symbol in a file.
///
/// Target format: `<server_command> <file_or_dir>`
/// Example: `rust-analyzer src/main.rs`, `pylsp utils.py`
pub fn lsp_types(_graph: &mut Graph, target: &str) -> String {
    let (server_cmd, file_part) = match parse_target(target) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (path, _) = parse_location(&file_part);
    let abs_path = resolve_path(&path);
    let root = root_dir_from_path(&path);

    let mut client = match LspClient::start(&server_cmd, &root) {
        Ok(c) => c,
        Err(e) => return format!("Error: {}", e),
    };

    let files = collect_files(&abs_path);
    if files.is_empty() {
        client.shutdown();
        return format!("No source files found at: {}", abs_path.display());
    }

    let mut output = String::new();
    output.push_str("=== LSP Type Information ===\n");

    for file in &files {
        if let Err(e) = client.open_file(file) {
            output.push_str(&format!("\n# {} (error opening: {})\n", file.display(), e));
            continue;
        }

        let uri = path_to_uri(file);

        // Get document symbols first
        let symbols_result = client.request(
            "textDocument/documentSymbol",
            json!({ "textDocument": { "uri": uri } }),
        );

        let symbols = match symbols_result {
            Ok(ref v) => v.as_array().cloned().unwrap_or_default(),
            Err(_) => continue,
        };

        if symbols.is_empty() {
            continue;
        }

        let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy();
        output.push_str(&format!("\n# {}\n", rel));

        // For each symbol, hover at its start position to get type signatures
        let positions = collect_symbol_positions(&symbols);

        for (name, kind, line, col) in &positions {
            let hover_result = client.request(
                "textDocument/hover",
                json!({
                    "textDocument": { "uri": uri },
                    "position": { "line": line, "character": col }
                }),
            );

            let kind_name = symbol_kind_name(*kind);
            match hover_result {
                Ok(ref hover) if !hover.is_null() => {
                    let type_str = extract_hover_type(hover);
                    if !type_str.is_empty() {
                        output.push_str(&format!(
                            "  {} {} (L{}): {}\n",
                            kind_name,
                            name,
                            line + 1,
                            type_str
                        ));
                    } else {
                        output.push_str(&format!(
                            "  {} {} (L{}): <no type info>\n",
                            kind_name,
                            name,
                            line + 1
                        ));
                    }
                }
                _ => {
                    output.push_str(&format!(
                        "  {} {} (L{}): <no hover>\n",
                        kind_name,
                        name,
                        line + 1
                    ));
                }
            }
        }
    }

    client.shutdown();
    output
}
