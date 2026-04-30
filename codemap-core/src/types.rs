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
pub struct BridgeInfo {
    pub kind: BridgeKind,
    pub name: String,
    pub target: Option<String>,  // C++ function name, Rust impl, etc.
    pub line: usize,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BridgeKind {
    TorchLibrary,    // C++ TORCH_LIBRARY m.def/m.impl
    TorchOps,        // Python torch.ops.ns.op call
    Pybind11,        // C++ PYBIND11_MODULE, m.def
    PyO3Class,       // Rust #[pyclass]
    PyO3Function,    // Rust #[pyfunction]
    PyO3Methods,     // Rust #[pymethods]
    TritonKernel,    // Python @triton.jit
    TritonLaunch,    // Python kernel[grid](args)
    CudaKernel,      // C++ __global__ function
    CudaLaunch,      // C++ kernel<<<grid>>>(args)
    MonkeyPatch,     // Python module.Class = Replacement
    AutogradFunc,    // Python torch.autograd.Function subclass
    YamlDispatch,    // YAML native_functions.yaml op→kernel mapping
    BuildDep,        // CMake target_link_libraries, setup.py ext_modules
    DispatchKey,     // C++ DispatchKey::CUDA, Rust #[cfg(feature)]
    TraitImpl,       // Rust trait Backend impl
}

impl BridgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeKind::TorchLibrary => "torch_library",
            BridgeKind::TorchOps => "torch_ops",
            BridgeKind::Pybind11 => "pybind11",
            BridgeKind::PyO3Class => "pyo3_class",
            BridgeKind::PyO3Function => "pyo3_function",
            BridgeKind::PyO3Methods => "pyo3_methods",
            BridgeKind::TritonKernel => "triton_kernel",
            BridgeKind::TritonLaunch => "triton_launch",
            BridgeKind::CudaKernel => "cuda_kernel",
            BridgeKind::CudaLaunch => "cuda_launch",
            BridgeKind::MonkeyPatch => "monkey_patch",
            BridgeKind::AutogradFunc => "autograd_func",
            BridgeKind::YamlDispatch => "yaml_dispatch",
            BridgeKind::BuildDep => "build_dep",
            BridgeKind::DispatchKey => "dispatch_key",
            BridgeKind::TraitImpl => "trait_impl",
        }
    }

    pub fn is_gpu(&self) -> bool {
        matches!(self, BridgeKind::TritonKernel | BridgeKind::CudaKernel)
    }

    pub fn is_registration(&self) -> bool {
        matches!(self, BridgeKind::TorchLibrary | BridgeKind::Pybind11 | BridgeKind::PyO3Class | BridgeKind::PyO3Function | BridgeKind::PyO3Methods)
    }

    pub fn is_call(&self) -> bool {
        matches!(self, BridgeKind::TorchOps | BridgeKind::TritonLaunch | BridgeKind::CudaLaunch)
    }
}

// ── EntityKind ──────────────────────────────────────────────────────
//
// Heterogeneous graph: a single Graph can hold source files, PE/ELF/Mach-O
// binaries, DLLs, schema tables, HTTP endpoints, ML models, etc. Every node
// declares what it represents via `kind`. Algorithms can filter or weight by
// kind, visualizations get distinct shapes/colors, and `meta-path` queries
// can traverse paths through specific kind sequences.
//
// Inspired by GitHub's stack-graphs (Node enum with predicate methods) and
// Joern's pass-based CPG augmentation: each RE action is a "pass" that
// inserts kind-tagged nodes/edges into the shared Graph.

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityKind {
    /// Source file with parsed AST (Python, Rust, TypeScript, etc.). Default.
    SourceFile,
    /// Windows PE binary (EXE/DLL).
    PeBinary,
    /// Linux ELF binary.
    ElfBinary,
    /// macOS Mach-O binary (universal or per-arch).
    MachoBinary,
    /// JVM Java/Kotlin .class or .jar.
    JavaClass,
    /// WebAssembly module.
    WasmModule,
    /// External library a binary imports (e.g. `kernel32.dll`, `libc.so.6`).
    Dll,
    /// Function/method symbol from a binary's import or export table.
    Symbol,
    /// HTTP endpoint discovered from web-api/web-blueprint/openapi/etc.
    HttpEndpoint,
    /// HTML form action endpoint with method + fields.
    WebForm,
    /// Database table from SQL/Clarion/DBF schema extraction.
    SchemaTable,
    /// Field/column on a SchemaTable.
    SchemaField,
    /// Protobuf message type.
    ProtoMessage,
    /// GraphQL type (object, scalar, interface, etc.).
    GraphqlType,
    /// OpenAPI/Swagger path operation.
    OpenApiPath,
    /// Docker Compose service.
    DockerService,
    /// Terraform resource or module.
    TerraformResource,
    /// ML model file (GGUF, SafeTensors, ONNX, .pyc, CUDA fatbin).
    MlModel,
    /// .NET assembly.
    DotnetAssembly,
    /// .NET type (class, struct, interface).
    DotnetType,
    /// Compiler / toolchain detected by language fingerprinting (rust,
    /// go, msvc, gcc, mingw, .NET, Delphi, PyInstaller, Electron, etc.).
    /// Edges: binary → compiler. Lets meta-path queries answer "every
    /// Go-compiled binary in this repo" or "what toolchains do we ship?"
    Compiler,
    /// String literal extracted from a binary's data sections.
    /// Edges: binary → string. attrs["string_type"] classifies as
    /// url/sql/path/registry/guid/base64/hex/format_str/error_msg/
    /// generic. Strings that classify as URLs additionally feed the
    /// existing HttpEndpoint promotion pipeline so meta-path queries
    /// like "pe->string->endpoint" work uniformly.
    StringLiteral,
    /// Data appended past the official end of a PE/ELF/Mach-O binary.
    /// Edges: binary → overlay. attrs["size"] / attrs["entropy"]
    /// classify the overlay (NSIS installer / Inno Setup / PyInstaller
    /// bootstrap / generic / encrypted-blob). Common malware
    /// indicator + the heart of how installers ship extra payloads.
    Overlay,
    /// Function recovered from a binary's .text section via disasm.
    /// Edges: binary → bin_func, bin_func → bin_func (intra-binary
    /// calls), bin_func → symbol (imports it calls). attrs include
    /// address, size, instruction_count, demangled_name. Lets graph
    /// algorithms (PageRank, Leiden, betweenness) run at the
    /// function-within-binary level — not just file-within-repo.
    BinaryFunction,
    /// Software license detected via SPDX identifier, manifest
    /// `license` field, or LICENSE / COPYING / NOTICE template
    /// matching. Edges: source/binary → license. attrs include
    /// SPDX id, family (permissive/copyleft/proprietary/unknown),
    /// detection method. Feeds the SBOM exporter and lets
    /// meta-path queries answer "which copyleft files are in this
    /// repo?"
    License,
    /// CVE imported from an offline NVD JSON dump. Edges: dll →
    /// cve when a known-vulnerable version matches. attrs include
    /// CVE id, CVSS score, severity, year, CWE. Together with the
    /// existing dll/binary nodes, this turns codemap into a real
    /// supply-chain auditor: meta-path "source->binary->dll->cve"
    /// finds vulnerable transitive deps in your code.
    Cve,
    /// Code-signing certificate extracted from a signed binary.
    /// Edges: binary → cert (signs it), cert → cert (issuer chain).
    /// attrs: subject, issuer, serial, sha256, valid_from,
    /// valid_to. Lets you ask "who signed this?" / "are all our
    /// vendors using current certs?" / "find the chain root."
    Cert,
    /// Android APK package — the top-level container holding
    /// classes.dex + AndroidManifest.xml + resources. Edges:
    /// apk → permission (declared in manifest), apk → bin_func
    /// (DEX methods). attrs: package, version, min_sdk, target_sdk.
    AndroidPackage,
    /// Android permission declared by an APK (CAMERA, INTERNET,
    /// READ_CONTACTS, etc.). Edges: apk → permission, method →
    /// permission (when methods use the permission). Killer
    /// query: meta-path "permission->method" answers "what code
    /// uses CAMERA permission?"
    Permission,
    /// Hardcoded secret discovered by `secret-scan` (AWS access key,
    /// GitHub PAT, JWT, private key, connection string, etc.).
    /// Edges: source → secret. attrs: pattern_name, severity
    /// (critical/high/medium), line, preview (masked).
    /// Killer queries: `meta-path "source->secret"` for inventory,
    /// `pagerank --type secret` for files concentrating risk.
    Secret,
}

impl EntityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityKind::SourceFile => "source",
            EntityKind::PeBinary => "pe",
            EntityKind::ElfBinary => "elf",
            EntityKind::MachoBinary => "macho",
            EntityKind::JavaClass => "jclass",
            EntityKind::WasmModule => "wasm",
            EntityKind::Dll => "dll",
            EntityKind::Symbol => "symbol",
            EntityKind::HttpEndpoint => "endpoint",
            EntityKind::WebForm => "form",
            EntityKind::SchemaTable => "table",
            EntityKind::SchemaField => "field",
            EntityKind::ProtoMessage => "proto",
            EntityKind::GraphqlType => "gql",
            EntityKind::OpenApiPath => "oapi",
            EntityKind::DockerService => "docker",
            EntityKind::TerraformResource => "tf",
            EntityKind::MlModel => "model",
            EntityKind::DotnetAssembly => "asm",
            EntityKind::DotnetType => "type",
            EntityKind::Compiler => "compiler",
            EntityKind::StringLiteral => "string",
            EntityKind::Overlay => "overlay",
            EntityKind::BinaryFunction => "bin_func",
            EntityKind::License => "license",
            EntityKind::Cve => "cve",
            EntityKind::Cert => "cert",
            EntityKind::AndroidPackage => "apk",
            EntityKind::Permission => "permission",
            EntityKind::Secret => "secret",
        }
    }

    /// Parse a kind from CLI input ("source", "pe", etc.). Used by --type filter.
    pub fn from_str(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        Some(match s.as_str() {
            "source" | "src" | "file" => EntityKind::SourceFile,
            "pe"      => EntityKind::PeBinary,
            "elf"     => EntityKind::ElfBinary,
            "macho"   => EntityKind::MachoBinary,
            "jclass" | "java"  => EntityKind::JavaClass,
            "wasm"    => EntityKind::WasmModule,
            "dll"     => EntityKind::Dll,
            "symbol" | "sym"   => EntityKind::Symbol,
            "endpoint" | "ep"  => EntityKind::HttpEndpoint,
            "form"    => EntityKind::WebForm,
            "table"   => EntityKind::SchemaTable,
            "field"   => EntityKind::SchemaField,
            "proto"   => EntityKind::ProtoMessage,
            "gql" | "graphql"  => EntityKind::GraphqlType,
            "oapi" | "openapi" => EntityKind::OpenApiPath,
            "docker" | "service" => EntityKind::DockerService,
            "tf" | "terraform"   => EntityKind::TerraformResource,
            "model" | "ml"       => EntityKind::MlModel,
            "asm" | "assembly"   => EntityKind::DotnetAssembly,
            "type" | "dotnet-type" => EntityKind::DotnetType,
            "compiler" | "toolchain" | "lang" => EntityKind::Compiler,
            "string" | "str" | "literal" => EntityKind::StringLiteral,
            "overlay" | "trailing" => EntityKind::Overlay,
            "bin_func" | "binfunc" | "function" | "func" => EntityKind::BinaryFunction,
            "license" | "spdx" => EntityKind::License,
            "cve" | "vuln" => EntityKind::Cve,
            "cert" | "certificate" | "x509" => EntityKind::Cert,
            "apk" | "android" | "androidpackage" => EntityKind::AndroidPackage,
            "permission" | "perm" => EntityKind::Permission,
            "secret" | "credential" | "leaked" => EntityKind::Secret,
            _ => return None,
        })
    }

    pub fn is_binary(&self) -> bool {
        matches!(self,
            EntityKind::PeBinary | EntityKind::ElfBinary | EntityKind::MachoBinary
                | EntityKind::JavaClass | EntityKind::WasmModule)
    }

    pub fn is_schema(&self) -> bool {
        matches!(self,
            EntityKind::SchemaTable | EntityKind::SchemaField
                | EntityKind::ProtoMessage | EntityKind::GraphqlType)
    }

    pub fn is_web(&self) -> bool {
        matches!(self,
            EntityKind::HttpEndpoint | EntityKind::WebForm | EntityKind::OpenApiPath)
    }

    pub fn is_infra(&self) -> bool {
        matches!(self, EntityKind::DockerService | EntityKind::TerraformResource)
    }
}

fn default_entity_kind() -> EntityKind { EntityKind::SourceFile }

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
    pub bridges: Vec<BridgeInfo>,
    /// Heterogeneous-graph node kind. Defaults to SourceFile so existing
    /// scanner code (which only produces source-file nodes) keeps working.
    /// RE actions tag their nodes with the appropriate non-default kind.
    #[serde(default = "default_entity_kind")]
    pub kind: EntityKind,
    /// Free-form attribute bag for kind-specific metadata. e.g. a SchemaTable
    /// might store {"engine": "innodb"}; an HttpEndpoint might store
    /// {"method": "POST", "auth": "bearer"}. Kept generic so adding new node
    /// kinds doesn't churn the struct.
    #[serde(default)]
    pub attrs: HashMap<String, String>,
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

    /// Insert (or fetch) a typed node. Used by RE-action passes to register
    /// kind-tagged nodes — PE binaries, schema tables, HTTP endpoints, etc.
    /// If a node with the same id already exists, returns it without overwriting
    /// fields (so repeated runs are idempotent and won't lose state). Pass
    /// kind-specific metadata via the `attrs` slice.
    pub fn ensure_typed_node(
        &mut self,
        id: &str,
        kind: EntityKind,
        attrs: &[(&str, &str)],
    ) -> &mut GraphNode {
        if !self.nodes.contains_key(id) {
            let mut attr_map = HashMap::new();
            for (k, v) in attrs {
                attr_map.insert((*k).to_string(), (*v).to_string());
            }
            self.nodes.insert(id.to_string(), GraphNode {
                id: id.to_string(),
                imports: Vec::new(),
                imported_by: Vec::new(),
                urls: Vec::new(),
                exports: Vec::new(),
                lines: 0,
                functions: Vec::new(),
                data_flow: None,
                bridges: Vec::new(),
                kind,
                attrs: attr_map,
                mtime: None,
            });
        } else {
            // Existing node — merge attrs, but preserve kind if already set
            // (don't let a later pass downgrade a node's classification).
            let n = self.nodes.get_mut(id).unwrap();
            for (k, v) in attrs {
                n.attrs.insert((*k).to_string(), (*v).to_string());
            }
        }
        self.nodes.get_mut(id).unwrap()
    }

    /// Add a directed import-style edge between two nodes by id. Both nodes
    /// must exist; missing nodes are silently no-op'd to keep RE passes
    /// robust against partial extraction. Idempotent — repeated calls do not
    /// duplicate edges.
    pub fn add_edge(&mut self, from: &str, to: &str) {
        if from == to { return; }
        if !self.nodes.contains_key(from) || !self.nodes.contains_key(to) { return; }
        if let Some(src) = self.nodes.get_mut(from) {
            if !src.imports.iter().any(|i| i == to) {
                src.imports.push(to.to_string());
            }
        }
        if let Some(dst) = self.nodes.get_mut(to) {
            if !dst.imported_by.iter().any(|i| i == from) {
                dst.imported_by.push(from.to_string());
            }
        }
    }

    /// Filter nodes by a set of allowed kinds. Returns ids in stable order.
    /// Used by `--type` flag on graph-theory actions.
    pub fn nodes_by_kind(&self, kinds: &[EntityKind]) -> Vec<&GraphNode> {
        let mut v: Vec<&GraphNode> = self.nodes.values()
            .filter(|n| kinds.contains(&n.kind))
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Traverse a meta-path: a sequence of EntityKinds that edges should
    /// connect. Returns every concrete path through the graph that follows
    /// the kind sequence. Powers the `meta-path` action — the heterogeneous
    /// graph killer feature ("show me every SourceFile that ends in an
    /// HttpEndpoint"). Limited to `max_paths` to avoid blowups on dense
    /// graphs; depth bounded by the kind sequence length.
    pub fn meta_path(&self, kinds: &[EntityKind], max_paths: usize) -> Vec<Vec<String>> {
        if kinds.len() < 2 { return Vec::new(); }
        let mut out: Vec<Vec<String>> = Vec::new();
        let starts: Vec<&str> = self.nodes.values()
            .filter(|n| n.kind == kinds[0])
            .map(|n| n.id.as_str())
            .collect();
        for start in starts {
            self.meta_path_dfs(start, kinds, 0, &mut Vec::new(), &mut out, max_paths);
            if out.len() >= max_paths { break; }
        }
        out
    }

    fn meta_path_dfs(
        &self,
        cur: &str,
        kinds: &[EntityKind],
        depth: usize,
        path: &mut Vec<String>,
        out: &mut Vec<Vec<String>>,
        max_paths: usize,
    ) {
        if out.len() >= max_paths { return; }
        path.push(cur.to_string());
        if depth + 1 == kinds.len() {
            out.push(path.clone());
        } else if let Some(node) = self.nodes.get(cur) {
            let next_kind = kinds[depth + 1];
            for n in &node.imports {
                if let Some(next) = self.nodes.get(n) {
                    if next.kind == next_kind {
                        self.meta_path_dfs(&next.id, kinds, depth + 1, path, out, max_paths);
                    }
                }
                if out.len() >= max_paths { break; }
            }
        }
        path.pop();
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
    } else {
        if let Some(last) = callee.split('.').next_back() {
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
