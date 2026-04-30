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
        // Maximum Content-Length we'll accept (50 MB). Reject anything larger
        // to prevent unbounded memory allocation from a misbehaving server.
        const MAX_CONTENT_LENGTH: usize = 50 * 1024 * 1024;

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
        if content_length > MAX_CONTENT_LENGTH {
            return Err(format!(
                "Content-Length {} exceeds maximum ({} bytes) — rejecting oversized LSP message",
                content_length, MAX_CONTENT_LENGTH
            ));
        }
        let mut buf = vec![0u8; content_length];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| format!("Read body ({} bytes): {}", content_length, e))?;
        let text = String::from_utf8(buf).map_err(|e| format!("UTF-8 decode: {}", e))?;
        serde_json::from_str(&text).map_err(|e| format!("JSON parse: {}", e))
    }

    /// Wait for a response matching the given request id.
    ///
    /// **Timeout note:** The deadline check runs between messages, but each
    /// individual `read_message()` call blocks on I/O. This means the timeout
    /// is best-effort — if the server sends nothing the read will block
    /// indefinitely. For a CLI tool this is acceptable; the user can Ctrl-C.
    /// The Content-Length cap in `read_message` prevents memory exhaustion
    /// from oversized payloads.
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
// Graph integration helpers (5.18.0)
// ═══════════════════════════════════════════════════════════════════
//
// LSP returns rich semantic data — symbols, references, call hierarchy,
// diagnostics, types — that previously only landed in text output.
// These helpers promote that data into the heterogeneous graph so it
// participates in PageRank / centrality / meta-path queries.
//
// Bounds: each action caps how many graph writes it performs to keep
// huge LSP responses (millions of refs on common APIs) from blowing up
// the graph. Caps are per-call, not per-target.

/// Cap on Symbol nodes written per single LSP call.
const MAX_LSP_SYMBOLS_PER_CALL: usize = 5000;
/// Cap on reference edges written per single LSP call.
const MAX_LSP_REFS_PER_CALL: usize = 1000;
/// Cap on incoming + outgoing call edges per single LSP-calls invocation.
const MAX_LSP_CALL_EDGES: usize = 500;

/// LSP symbol-kind codes worth surfacing as graph edges into the source
/// file. Subset that maps to "real" code constructs (functions / methods
/// / classes / etc.) — skips LSP's object-literal / property / event
/// noise that bloats document-symbol responses.
fn lsp_kind_is_promotable(kind: i64) -> bool {
    matches!(kind,
        5  | // Class
        6  | // Method
        7  | // Property
        8  | // Field
        9  | // Constructor
        10 | // Enum
        11 | // Interface
        12 | // Function
        13 | // Variable (module-level only — children skipped via depth gate)
        14 | // Constant
        22 | // EnumMember
        23   // Struct
    )
}

/// Recursively register Symbol nodes for an LSP DocumentSymbol tree.
/// Returns the running written-count so the caller can stop at the cap.
fn register_lsp_symbols(
    graph: &mut crate::types::Graph,
    file_id: &str,
    symbols: &[Value],
    written: &mut usize,
    depth: usize,
) {
    use crate::types::EntityKind;
    if depth > 8 { return; }
    for sym in symbols {
        if *written >= MAX_LSP_SYMBOLS_PER_CALL { return; }
        let name = sym.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.is_empty() { continue; }
        let kind = sym.get("kind").and_then(|k| k.as_i64()).unwrap_or(0);
        if !lsp_kind_is_promotable(kind) {
            // Recurse into children even when skipping the parent — LSP
            // sometimes nests methods under unrelated wrappers.
            if let Some(children) = sym.get("children").and_then(|c| c.as_array()) {
                register_lsp_symbols(graph, file_id, children, written, depth + 1);
            }
            continue;
        }
        let range = sym.get("range")
            .or_else(|| sym.get("location").and_then(|l| l.get("range")));
        let line = range
            .and_then(|r| r.get("start"))
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64()).map(|l| l + 1).unwrap_or(0);
        let kind_str = symbol_kind_name(kind);
        let line_str = line.to_string();
        let kind_num = kind.to_string();
        let sym_id = format!("lsp_sym:{file_id}::{name}::{line}");
        graph.ensure_typed_node(&sym_id, EntityKind::Symbol, &[
            ("name", name),
            ("source", "lsp"),
            ("lsp_kind", kind_str),
            ("lsp_kind_code", &kind_num),
            ("file", file_id),
            ("line", &line_str),
        ]);
        graph.add_edge(file_id, &sym_id);
        *written += 1;

        if let Some(children) = sym.get("children").and_then(|c| c.as_array()) {
            register_lsp_symbols(graph, file_id, children, written, depth + 1);
        }
    }
}

/// Convert an absolute path back to a graph-friendly source-file ID
/// (relative to scan_dir if possible, else the absolute path).
fn file_id_for_graph(graph: &crate::types::Graph, path: &Path) -> String {
    let scan_root = Path::new(&graph.scan_dir);
    if let Ok(rel) = path.strip_prefix(scan_root) {
        rel.to_string_lossy().into_owned()
    } else {
        path.to_string_lossy().into_owned()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Actions
// ═══════════════════════════════════════════════════════════════════

/// Extract document symbols from files via a running LSP server.
///
/// Target format: `<server_command> <file_or_dir>`
/// Examples: `rust-analyzer src/main.rs`, `pylsp .`
pub fn lsp_symbols(graph: &mut Graph, target: &str) -> String {
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
    let mut written_count = 0usize;

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

                        // 5.18.0: promote each LSP symbol to a Symbol graph
                        // node. Bound at MAX_LSP_SYMBOLS_PER_CALL to keep
                        // huge LSP responses from blowing up the graph.
                        let file_id = file_id_for_graph(graph, file);
                        graph.ensure_typed_node(&file_id,
                            crate::types::EntityKind::SourceFile,
                            &[("path", &file_id)]);
                        register_lsp_symbols(graph, &file_id, arr, &mut written_count, 0);
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
    if written_count > 0 {
        output.push_str(&format!(
            "\n[graph] {} Symbol nodes registered (cap {}).\n",
            written_count, MAX_LSP_SYMBOLS_PER_CALL,
        ));
    }
    output
}

/// Find all references to a symbol at a given position.
///
/// Target format: `<server_command> <file>:<line>:<col>`
/// Example: `rust-analyzer src/main.rs:42:10`
pub fn lsp_references(graph: &mut Graph, target: &str) -> String {
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

                    // 5.18.0: register the queried symbol as a Symbol node,
                    // then add file→symbol edges for each reference.
                    // This makes "which files reference X" answerable via
                    // outgoing-edge traversal of the symbol node.
                    use crate::types::EntityKind;
                    let target_file_id = file_id_for_graph(graph, &abs_path);
                    let target_sym_id =
                        format!("lsp_sym:{target_file_id}::ref_at::{line}");
                    let line_str = line.to_string();
                    let col_str = col.to_string();
                    let ref_count = arr.len().to_string();
                    graph.ensure_typed_node(&target_sym_id, EntityKind::Symbol, &[
                        ("name", &format!("{target_file_id}:{line}:{col}")),
                        ("source", "lsp"),
                        ("lsp_kind", "ReferenceTarget"),
                        ("file", &target_file_id),
                        ("line", &line_str),
                        ("column", &col_str),
                        ("ref_count", &ref_count),
                    ]);
                    let mut edges_written = 0usize;

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
                                loc_path.clone()
                            };
                        output.push_str(&format!(
                            "  {}:{}:{}\n",
                            display_path, loc_line, loc_col
                        ));

                        if edges_written < MAX_LSP_REFS_PER_CALL {
                            let referrer_file_id = file_id_for_graph(
                                graph, &PathBuf::from(&loc_path));
                            graph.ensure_typed_node(&referrer_file_id,
                                EntityKind::SourceFile,
                                &[("path", &referrer_file_id)]);
                            graph.add_edge(&referrer_file_id, &target_sym_id);
                            edges_written += 1;
                        }
                    }
                    if edges_written > 0 {
                        output.push_str(&format!(
                            "\n[graph] {} reference edges → {target_sym_id} (cap {}).\n",
                            edges_written, MAX_LSP_REFS_PER_CALL,
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
pub fn lsp_calls(graph: &mut Graph, target: &str) -> String {
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

    // 5.18.0: register the target symbol + its caller/callee symbols as
    // Symbol nodes. Add caller→target and target→callee edges so
    // call-hierarchy data participates in centrality / meta-path queries.
    use crate::types::EntityKind;
    let target_file_id = file_id_for_graph(graph, &abs_path);
    let target_line_str = line.to_string();
    let target_sym_id = format!("lsp_sym:{target_file_id}::{item_name}::{line}");
    graph.ensure_typed_node(&target_sym_id, EntityKind::Symbol, &[
        ("name", item_name),
        ("source", "lsp"),
        ("lsp_kind", "CallTarget"),
        ("file", &target_file_id),
        ("line", &target_line_str),
    ]);
    graph.ensure_typed_node(&target_file_id, EntityKind::SourceFile,
        &[("path", &target_file_id)]);
    graph.add_edge(&target_file_id, &target_sym_id);
    let mut edges_written = 0usize;

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
                        if edges_written < MAX_LSP_CALL_EDGES {
                            register_call_edge(graph, call, "from",
                                &target_sym_id, /*caller→target=*/ true);
                            edges_written += 1;
                        }
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
                        if edges_written < MAX_LSP_CALL_EDGES {
                            register_call_edge(graph, call, "to",
                                &target_sym_id, /*caller→target=*/ false);
                            edges_written += 1;
                        }
                    }
                }
            } else {
                output.push_str("  (none)\n");
            }
        }
        Err(e) => output.push_str(&format!("  Error: {}\n", e)),
    }

    client.shutdown();
    if edges_written > 0 {
        output.push_str(&format!(
            "\n[graph] {} call edges around {target_sym_id} (cap {}).\n",
            edges_written, MAX_LSP_CALL_EDGES,
        ));
    }
    output
}

/// Register a Symbol node for one side of a call-hierarchy item, then
/// connect it to the central target. `caller_to_target=true` for incoming
/// (caller → target), false for outgoing (target → callee).
fn register_call_edge(
    graph: &mut crate::types::Graph,
    call: &Value,
    key: &str,
    target_sym_id: &str,
    caller_to_target: bool,
) {
    use crate::types::EntityKind;
    let empty = json!({});
    let other = call.get(key).unwrap_or(&empty);
    let name = other.get("name").and_then(|n| n.as_str()).unwrap_or("<unknown>");
    let other_uri = other.get("uri").and_then(|u| u.as_str()).unwrap_or("");
    let other_path = uri_to_path(other_uri);
    let line = other.get("range")
        .and_then(|r| r.get("start"))
        .and_then(|s| s.get("line"))
        .and_then(|l| l.as_u64()).map(|l| l + 1).unwrap_or(0);
    let other_file_id = file_id_for_graph(graph, &PathBuf::from(&other_path));
    let line_str = line.to_string();
    let other_sym_id = format!("lsp_sym:{other_file_id}::{name}::{line}");
    graph.ensure_typed_node(&other_sym_id, EntityKind::Symbol, &[
        ("name", name),
        ("source", "lsp"),
        ("lsp_kind", "CallParticipant"),
        ("file", &other_file_id),
        ("line", &line_str),
    ]);
    graph.ensure_typed_node(&other_file_id, EntityKind::SourceFile,
        &[("path", &other_file_id)]);
    graph.add_edge(&other_file_id, &other_sym_id);
    if caller_to_target {
        graph.add_edge(&other_sym_id, target_sym_id);
    } else {
        graph.add_edge(target_sym_id, &other_sym_id);
    }
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
pub fn lsp_diagnostics(graph: &mut Graph, target: &str) -> String {
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
        let mut file_errors = 0usize;
        let mut file_warnings = 0usize;
        let mut file_info = 0usize;
        let mut first_error: Option<String> = None;
        for (severity, line, message) in &diags {
            let sev_name = severity_name(*severity);
            match severity {
                1 => { errors += 1; file_errors += 1;
                       if first_error.is_none() {
                           let trimmed: String = message.chars().take(200).collect();
                           first_error = Some(format!("L{line}: {trimmed}"));
                       } }
                2 => { warnings += 1; file_warnings += 1; }
                3 => file_info += 1,
                _ => {}
            }
            total += 1;
            output.push_str(&format!("  L{} [{}] {}\n", line, sev_name, message));
        }
        // 5.18.0: attach diagnostic counts to the SourceFile node so
        // `--type source` filtering can rank files by error density.
        let file_id = file_id_for_graph(graph, &PathBuf::from(&file));
        graph.ensure_typed_node(&file_id, crate::types::EntityKind::SourceFile,
            &[("path", &file_id)]);
        if let Some(node) = graph.nodes.get_mut(&file_id) {
            node.attrs.insert("lsp_errors".into(), file_errors.to_string());
            node.attrs.insert("lsp_warnings".into(), file_warnings.to_string());
            node.attrs.insert("lsp_info".into(), file_info.to_string());
            if let Some(msg) = first_error {
                node.attrs.insert("lsp_first_error".into(), msg);
            }
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
pub fn lsp_types(graph: &mut Graph, target: &str) -> String {
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
        // 5.18.0: count typed symbols per file as an attr — rather than
        // storing every hover body (huge), surface aggregate signal.
        let mut typed_count = 0usize;

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
                        typed_count += 1;
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

        // Per-file attr summarizing type-info coverage.
        let file_id = file_id_for_graph(graph, file);
        graph.ensure_typed_node(&file_id, crate::types::EntityKind::SourceFile,
            &[("path", &file_id)]);
        if let Some(node) = graph.nodes.get_mut(&file_id) {
            node.attrs.insert("lsp_typed_symbols".into(), typed_count.to_string());
            node.attrs.insert("lsp_total_symbols".into(), positions.len().to_string());
        }
    }

    client.shutdown();
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Graph, EntityKind};
    use std::collections::HashMap;

    /// Verifies 5.18.0's lsp_symbols promotion: walking a synthetic
    /// DocumentSymbol tree registers Symbol nodes with `source=lsp`
    /// attr + edges from the source-file id; non-promotable kinds are
    /// skipped while their children are still visited.
    #[test]
    fn lsp_symbol_walker_promotes_promotable_kinds_only() {
        // LSP DocumentSymbol kinds: 5=Class, 6=Method, 12=Function,
        // 13=Variable, 19=Object (skipped), 20=Key (skipped).
        // Tree shape: Class { Method, Method, Object { Method (nested) } }
        // Plus a top-level Function and a top-level Variable.
        let payload = serde_json::json!([
            {
                "name": "Calculator",
                "kind": 5,
                "range": { "start": { "line": 0, "character": 0 },
                           "end":   { "line": 50, "character": 0 } },
                "children": [
                    { "name": "__init__", "kind": 6,
                      "range": { "start": { "line": 1, "character": 4 },
                                 "end":   { "line": 3, "character": 4 } } },
                    { "name": "add",      "kind": 6,
                      "range": { "start": { "line": 5, "character": 4 },
                                 "end":   { "line": 7, "character": 4 } } },
                    { "name": "_helpers", "kind": 19,
                      "range": { "start": { "line": 9, "character": 4 },
                                 "end":   { "line": 12, "character": 4 } },
                      "children": [
                          { "name": "nested_method", "kind": 6,
                            "range": { "start": { "line": 10, "character": 8 },
                                       "end":   { "line": 11, "character": 8 } } }
                      ] }
                ]
            },
            { "name": "top_level_fn", "kind": 12,
              "range": { "start": { "line": 60, "character": 0 },
                         "end":   { "line": 65, "character": 0 } } },
            { "name": "MAX_SIZE", "kind": 14,
              "range": { "start": { "line": 70, "character": 0 },
                         "end":   { "line": 70, "character": 30 } } }
        ]);

        let mut g = Graph {
            nodes: HashMap::new(),
            scan_dir: ".".to_string(),
            cpg: None,
        };
        let file_id = "src/calc.py".to_string();
        g.ensure_typed_node(&file_id, EntityKind::SourceFile, &[("path", &file_id)]);

        let mut written = 0usize;
        let arr = payload.as_array().unwrap();
        register_lsp_symbols(&mut g, &file_id, arr, &mut written, 0);

        let lsp_syms: Vec<&crate::types::GraphNode> = g.nodes.values()
            .filter(|n| n.kind == EntityKind::Symbol)
            .filter(|n| n.attrs.get("source").map(|s| s == "lsp").unwrap_or(false))
            .collect();

        let names: Vec<&String> = lsp_syms.iter()
            .filter_map(|n| n.attrs.get("name")).collect();

        // Promotable: Class, Method×3 (incl. nested under Object), Function, Constant
        for expected in ["Calculator", "__init__", "add", "nested_method",
                         "top_level_fn", "MAX_SIZE"] {
            assert!(names.iter().any(|n| n.as_str() == expected),
                "expected `{expected}` registered as Symbol; got {names:?}");
        }
        // Object (kind=19) must NOT be registered itself, but its child IS.
        assert!(!names.iter().any(|n| n.as_str() == "_helpers"),
            "Object-kind `_helpers` should be skipped; got {names:?}");

        // Each Symbol should have an edge from the source file.
        let src = g.nodes.get(&file_id).unwrap();
        for sym in &lsp_syms {
            assert!(src.imports.iter().any(|i| i == &sym.id),
                "expected source `{file_id}` → `{}` edge", sym.id);
        }

        assert_eq!(written, 6, "should have written exactly 6 promotable symbols");
    }

    /// Bound check: the cap kicks in once we exceed MAX_LSP_SYMBOLS_PER_CALL.
    #[test]
    fn lsp_symbol_walker_respects_cap() {
        let mut children = Vec::with_capacity(MAX_LSP_SYMBOLS_PER_CALL + 100);
        for i in 0..(MAX_LSP_SYMBOLS_PER_CALL + 100) {
            children.push(serde_json::json!({
                "name": format!("fn_{i}"), "kind": 12,
                "range": { "start": { "line": i, "character": 0 },
                           "end":   { "line": i, "character": 10 } }
            }));
        }
        let payload = serde_json::Value::Array(children);

        let mut g = Graph {
            nodes: HashMap::new(),
            scan_dir: ".".to_string(),
            cpg: None,
        };
        let file_id = "huge.rs".to_string();
        g.ensure_typed_node(&file_id, EntityKind::SourceFile, &[("path", &file_id)]);

        let mut written = 0usize;
        register_lsp_symbols(&mut g, &file_id, payload.as_array().unwrap(),
            &mut written, 0);

        assert_eq!(written, MAX_LSP_SYMBOLS_PER_CALL,
            "cap MAX_LSP_SYMBOLS_PER_CALL must stop the walker exactly at the limit");
    }
}
