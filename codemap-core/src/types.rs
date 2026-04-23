use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// ── Graph Types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub calls: Vec<String>,
    pub is_exported: bool,
    pub parameters: Option<Vec<String>>,
    pub return_lines: Option<Vec<usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub imports: Vec<String>,
    pub imported_by: Vec<String>,
    pub urls: Vec<String>,
    pub exports: Vec<String>,
    pub lines: usize,
    pub functions: Vec<FunctionInfo>,
    pub data_flow: Option<FileDataFlow>,
    #[serde(skip)]
    pub mtime: Option<f64>,
}

pub struct Graph {
    pub nodes: HashMap<String, GraphNode>,
    pub scan_dir: String,
    pub cpg: Option<CodePropertyGraph>,
}

// ── Data Flow Types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UseContext { Arg, Return, AssignRhs, Property, Template, Other }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowDef {
    pub name: String,
    pub line: usize,
    pub rhs: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowUse {
    pub name: String,
    pub line: usize,
    pub context: UseContext,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallArgInfo {
    pub position: usize,
    pub expr: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowCallArg {
    pub callee: String,
    pub args: Vec<CallArgInfo>,
    pub line: usize,
    pub scope: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PropertyAccessKind { Read, Write }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPropertyAccess {
    pub base: String,
    pub property: String,
    pub line: usize,
    pub kind: PropertyAccessKind,
    pub scope: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileDataFlow {
    pub definitions: Vec<DataFlowDef>,
    pub uses: Vec<DataFlowUse>,
    pub call_args: Vec<DataFlowCallArg>,
    pub property_accesses: Vec<DataFlowPropertyAccess>,
}

// ── CPG Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeKind { Def, Use, Param, Return, Call, Phi, Property }

impl NodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeKind::Def => "def",
            NodeKind::Use => "use",
            NodeKind::Param => "param",
            NodeKind::Return => "return",
            NodeKind::Call => "call",
            NodeKind::Phi => "phi",
            NodeKind::Property => "prop",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeKind { Data, Control, Call, PropertyRead, PropertyWrite }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPGNode {
    pub id: String,
    pub kind: NodeKind,
    pub file: String,
    pub line: usize,
    pub name: String,
    pub version: Option<u32>,
    pub expr: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPGEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Default)]
pub struct CodePropertyGraph {
    pub nodes: HashMap<String, CPGNode>,
    pub edges: Vec<CPGEdge>,
    pub edges_from: HashMap<String, Vec<CPGEdge>>,
    pub edges_to: HashMap<String, Vec<CPGEdge>>,
}

// ── Sink/Source Registry ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkSourcePattern {
    pub pattern: String,
    pub category: String,
}

pub struct DataFlowConfig {
    pub sinks: Vec<SinkSourcePattern>,
    pub sources: Vec<SinkSourcePattern>,
    pub sanitizers: Vec<String>,
}

// ── Graph helpers ────────────────────────────────────────────────────

impl Graph {
    /// Find a node by exact match, suffix match, or partial match.
    pub fn find_node(&self, target: &str) -> Option<&GraphNode> {
        if let Some(node) = self.nodes.get(target) {
            return Some(node);
        }
        let matches: Vec<&GraphNode> = self.nodes.values()
            .filter(|n| n.id.ends_with(target) || n.id.ends_with(&format!("/{target}")))
            .collect();
        if matches.len() == 1 {
            return Some(matches[0]);
        }
        if matches.len() > 1 {
            eprintln!("Warning: ambiguous match for \"{target}\": {}. Using first match.",
                matches.iter().map(|m| m.id.as_str()).collect::<Vec<_>>().join(", "));
            return Some(matches[0]);
        }
        None
    }
}

// ── Default sinks/sources ────────────────────────────────────────────

impl Default for DataFlowConfig {
    fn default() -> Self {
        DataFlowConfig {
            sinks: default_sinks(),
            sources: default_sources(),
            sanitizers: vec!["parseInt".into(), "encodeURIComponent".into(), "escapeHtml".into()],
        }
    }
}

fn default_sinks() -> Vec<SinkSourcePattern> {
    vec![
        SinkSourcePattern { pattern: "fetch".into(), category: "network".into() },
        SinkSourcePattern { pattern: "axios.get".into(), category: "network".into() },
        SinkSourcePattern { pattern: "axios.post".into(), category: "network".into() },
        SinkSourcePattern { pattern: "axios.put".into(), category: "network".into() },
        SinkSourcePattern { pattern: "axios.delete".into(), category: "network".into() },
        SinkSourcePattern { pattern: "http.request".into(), category: "network".into() },
        SinkSourcePattern { pattern: "https.request".into(), category: "network".into() },
        SinkSourcePattern { pattern: "requests.get".into(), category: "network".into() },
        SinkSourcePattern { pattern: "requests.post".into(), category: "network".into() },
        SinkSourcePattern { pattern: "http.Get".into(), category: "network".into() },
        SinkSourcePattern { pattern: "http.Post".into(), category: "network".into() },
        SinkSourcePattern { pattern: "eval".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "execSync".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "execFile".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "child_process.exec".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "child_process.spawn".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "subprocess.run".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "os.system".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "exec.Command".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "Runtime.exec".into(), category: "exec".into() },
        SinkSourcePattern { pattern: "writeFileSync".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "writeFile".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "fs.writeFile".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "fs.writeFileSync".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "fs.appendFile".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "fs.unlink".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "os.WriteFile".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "ioutil.WriteFile".into(), category: "filesystem".into() },
        SinkSourcePattern { pattern: "db.query".into(), category: "database".into() },
        SinkSourcePattern { pattern: "db.execute".into(), category: "database".into() },
        SinkSourcePattern { pattern: "cursor.execute".into(), category: "database".into() },
        SinkSourcePattern { pattern: "knex.raw".into(), category: "database".into() },
    ]
}

fn default_sources() -> Vec<SinkSourcePattern> {
    vec![
        SinkSourcePattern { pattern: "req.body".into(), category: "user-input".into() },
        SinkSourcePattern { pattern: "req.params".into(), category: "user-input".into() },
        SinkSourcePattern { pattern: "req.query".into(), category: "user-input".into() },
        SinkSourcePattern { pattern: "process.argv".into(), category: "user-input".into() },
        SinkSourcePattern { pattern: "process.env".into(), category: "config".into() },
        SinkSourcePattern { pattern: "os.environ".into(), category: "config".into() },
        SinkSourcePattern { pattern: "os.Getenv".into(), category: "config".into() },
        SinkSourcePattern { pattern: "readFileSync".into(), category: "file-read".into() },
        SinkSourcePattern { pattern: "readFile".into(), category: "file-read".into() },
    ]
}

pub fn load_dataflow_config(dir: &str) -> DataFlowConfig {
    let mut config = DataFlowConfig::default();
    let config_path = std::path::Path::new(dir).join(".codemap").join("dataflow.json");
    if let Ok(content) = std::fs::read_to_string(&config_path) {
        if let Ok(user_config) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(sinks) = user_config.get("sinks").and_then(|v| v.as_array()) {
                for s in sinks {
                    if let (Some(pattern), Some(category)) = (s.get("pattern").and_then(|v| v.as_str()), s.get("category").and_then(|v| v.as_str())) {
                        config.sinks.push(SinkSourcePattern { pattern: pattern.into(), category: category.into() });
                    }
                }
            }
            if let Some(sources) = user_config.get("sources").and_then(|v| v.as_array()) {
                for s in sources {
                    if let (Some(pattern), Some(category)) = (s.get("pattern").and_then(|v| v.as_str()), s.get("category").and_then(|v| v.as_str())) {
                        config.sources.push(SinkSourcePattern { pattern: pattern.into(), category: category.into() });
                    }
                }
            }
            if let Some(sanitizers) = user_config.get("sanitizers").and_then(|v| v.as_array()) {
                for s in sanitizers {
                    if let Some(pattern) = s.get("pattern").and_then(|v| v.as_str()) {
                        config.sanitizers.push(pattern.into());
                    }
                }
            }
        }
    }
    config
}

// ── Utility functions ────────────────────────────────────────────────

pub fn matches_pattern(callee: &str, pattern: &str) -> bool {
    if callee == pattern { return true; }
    if pattern.contains('.') {
        let pp: Vec<&str> = pattern.split('.').collect();
        let cp: Vec<&str> = callee.split('.').collect();
        if cp.len() >= pp.len() {
            let off = cp.len() - pp.len();
            let mut ok = true;
            for i in 0..pp.len() {
                if pp[i] != "*" && pp[i] != cp[off + i] { ok = false; break; }
            }
            if ok { return true; }
        }
        if pattern.ends_with(".*") && callee.starts_with(&pattern[..pattern.len()-1]) { return true; }
    } else if pattern.len() > 5 {
        if let Some(last) = callee.split('.').last() {
            if last == pattern { return true; }
        }
    }
    false
}

pub fn escape_regex(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

pub fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            if scheme_end + 3 < at_pos {
                return format!("{}[redacted]@{}", &url[..scheme_end + 3], &url[at_pos + 1..]);
            }
        }
    }
    url.to_string()
}
