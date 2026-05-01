use crate::types::*;
use crate::utils::truncate;
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use tree_sitter::{Language, Node, Parser, Tree};
use tree_sitter_bash;

// ── Static Regex Compilation ───────────────────────────────────────

// extract_exports_from_ast
static EXPORT_DEFAULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"export\s+default\s+(?:class|function\s*\*?)\s+(\w+)").unwrap()
});

// extract_functions_from_ast
static KERNEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\w+)\s*<<<[^>]*>>>").unwrap()
});

// extract_urls
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"`](https?://[^'"`\s]{5,})['"`]"#).unwrap()
});

// extract_yaml_bridges
static YAML_FUNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"- func:\s*(\w+)"#).unwrap()
});
static YAML_DISPATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s+(CUDA|CPU|CompositeExplicitAutograd|CompositeImplicitAutograd|SparseCPU|SparseCUDA|Meta)\s*:\s*(\w+)"#).unwrap()
});

// extract_python_bridges
static TORCH_OPS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"torch\.ops\.(\w+)\.(\w+)"#).unwrap()
});
static TRITON_JIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"@\s*triton\s*\.\s*jit"#).unwrap()
});
static DEF_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s).*?def\s+(\w+)\s*\("#).unwrap()
});
static AUTOTUNE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"@\s*triton\s*\.\s*autotune"#).unwrap()
});
static TRITON_LAUNCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\[([^\]]+)\]\s*\("#).unwrap()
});
static TRITON_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*=\s*triton\s*\.\s*jit\s*\(\s*(\w+)\s*\)"#).unwrap()
});
static MONKEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+(?:\.\w+)+)\.([A-Z]\w+)\s*=\s*([A-Z]\w+)"#).unwrap()
});
static AUTOGRAD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"class\s+(\w+)\s*\(\s*(?:torch\.)?autograd\.Function\s*\)"#).unwrap()
});
static APPLY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\.\s*apply\s*\("#).unwrap()
});
static EXT_MODULE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:CMakeExtension|Extension)\s*\(\s*(?:name\s*=\s*)?['"]([\w.]+)['"]"#).unwrap()
});

// extract_cpp_bridges
static TORCH_LIB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"TORCH_LIBRARY\s*\(\s*(\w+)"#).unwrap()
});
static TORCH_DEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"m\s*\.\s*def\s*\(\s*"(\w+)"#).unwrap()
});
static TORCH_IMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"m\s*\.\s*impl\s*\(\s*"(\w+)"\s*,\s*(?:&\s*)?(\w+)"#).unwrap()
});
static TORCH_IMPL_FUNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"TORCH_IMPL_FUNC\s*\(\s*(\w+)"#).unwrap()
});
static PYBIND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"PYBIND11_MODULE\s*\(\s*(\w+)"#).unwrap()
});
static PY_CLASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"py::class_<\s*(\w+)\s*>\s*\(\s*\w+\s*,\s*"(\w+)""#).unwrap()
});
static CUDA_KERNEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"__global__\s+\w+\s+(\w+)\s*\("#).unwrap()
});
static CUDA_LAUNCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*<<<.+?>>>"#).unwrap()
});
static CMAKE_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"target_link_libraries\s*\(\s*(\w+)\s+(?:PUBLIC|PRIVATE|INTERFACE)?\s*([\w\s]+)\)"#).unwrap()
});
static FIND_PKG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"find_package\s*\(\s*(\w+)"#).unwrap()
});
static DISPATCH_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"DispatchKey(?:Set)?\s*::\s*(\w+)"#).unwrap()
});

// extract_rust_bridges
static RUST_STRUCT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\s*(?:pub\s+)?(?:struct|enum)\s+(\w+)"#).unwrap()
});
static RUST_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\s*(?:pub\s+)?(?:fn|async\s+fn)\s+(\w+)"#).unwrap()
});
static RUST_IMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\s*impl\s+(\w+)"#).unwrap()
});
static RUST_PUB_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\s*(?:pub\s+)?fn\s+(\w+)"#).unwrap()
});
static PYCLASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"#\[pyclass(?:\s*\([^)]*name\s*=\s*"(\w+)"[^)]*\))?\]"#).unwrap()
});
static PYFN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"#\[pyfunction\]"#).unwrap()
});
static PYMETHODS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"#\[pymethods\]"#).unwrap()
});
static PYMOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"#\[pymodule\]"#).unwrap()
});
static CFG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"#\[cfg\s*\(\s*feature\s*=\s*"(\w+)"\s*\)\]"#).unwrap()
});
static TRAIT_IMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"impl\s+(\w+)\s+for\s+(\w+)"#).unwrap()
});

// regex_extract_imports
static IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:import|export)\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
    ).unwrap()
});
static DYNAMIC_IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"import\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap()
});

// regex_extract_exports
static EXPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"export\s+(?:const|let|var|function|async\s+function|class|type|interface|enum)\s+(\w+)",
    ).unwrap()
});

/// Global quiet flag to suppress parser warnings.
static QUIET: AtomicBool = AtomicBool::new(false);

/// Set the global quiet flag for parser warnings.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

// ── Public Interface ────────────────────────────────────────────────

pub struct ParseResult {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub functions: Vec<FunctionInfo>,
    pub data_flow: Option<FileDataFlow>,
    pub urls: Vec<String>,
    pub bridges: Vec<BridgeInfo>,
}

/// Detect minified-JS-style bundles where the AST is meaningless. Two
/// signals: filename pattern (.min./.bundle./.chunk./.dist.) AND/OR
/// avg-line-length > 500 chars (compressed code without newlines).
fn is_minified(path: &str, content: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.contains(".min.") || lower.ends_with(".min")
        || lower.contains(".bundle.") || lower.contains(".chunk.")
        || lower.contains(".dist.") {
        return true;
    }
    // Average line length check — only for JS/TS/CSS where minification
    // is common. Skips the check for normal source langs that legitimately
    // have long-ish lines (tables, big match expressions).
    if !(lower.ends_with(".js") || lower.ends_with(".ts")
        || lower.ends_with(".mjs") || lower.ends_with(".cjs")
        || lower.ends_with(".jsx") || lower.ends_with(".tsx")) {
        return false;
    }
    let nlines = content.lines().count();
    if nlines == 0 { return false; }
    let avg = content.len() / nlines.max(1);
    avg > 500
}

pub fn parse_file(path: &str, content: &str, ext: &str) -> ParseResult {
    // Skip minified-JS bundles. Minified files like cosmos.min.js,
    // d3.v7.min.js, vendor.bundle.js etc. have all their code on one
    // line — the AST extractor sees one mega-function with cyclomatic
    // complexity of thousands, plus thousands of irrelevant call sites
    // that pollute pagerank, dead-functions, hubs, etc.
    //
    // Heuristic: filename contains .min./.bundle./.chunk., OR the file's
    // average line length is > 500 chars. The minified-JS test in
    // promote_urls_to_endpoints uses a similar heuristic; we're applying
    // it earlier here (parse stage) so the noise never enters the graph.
    if is_minified(path, content) {
        return ParseResult {
            imports: Vec::new(),
            exports: Vec::new(),
            functions: Vec::new(),
            data_flow: None,
            urls: extract_urls(content),  // URLs still extracted, but
                                           // promote_urls filters them
            bridges: Vec::new(),
        };
    }

    let grammar = ext_to_grammar(ext);
    if let Some(grammar) = grammar {
        if let Some(tree) = parse_with_treesitter(content, grammar) {
            let src = content.as_bytes();
            let root = tree.root_node();

            let imports = extract_imports_from_ast(root, grammar, src);
            let exports = extract_exports_from_ast(root, grammar, src);
            let mut functions = extract_functions_from_ast(root, grammar, src);
            let data_flow = Some(extract_data_flow_from_ast(root, grammar, src, &mut functions));
            let urls = extract_urls(content);
            let bridges = extract_bridges(content, ext, Some(root), src);

            return ParseResult { imports, exports, functions, data_flow, urls, bridges };
        }
    }

    // Regex fallback for unsupported grammars or parse failure
    let imports = regex_extract_imports(content);
    let exports = regex_extract_exports(content);
    let urls = extract_urls(content);
    let bridges = extract_bridges(content, ext, None, &[]);

    ParseResult { imports, exports, functions: vec![], data_flow: None, urls, bridges }
}

// ── Grammar Mapping ─────────────────────────────────────────────────

fn ext_to_grammar(ext: &str) -> Option<&'static str> {
    match ext {
        ".ts" => Some("typescript"),
        ".tsx" => Some("tsx"),
        ".js" | ".jsx" | ".mjs" | ".cjs" => Some("javascript"),
        ".py" => Some("python"),
        ".rs" => Some("rust"),
        ".go" => Some("go"),
        ".java" => Some("java"),
        ".rb" => Some("ruby"),
        ".php" => Some("php"),
        ".c" | ".h" => Some("c"),
        ".cpp" | ".cc" | ".cxx" | ".hpp" | ".hxx" => Some("cpp"),
        ".cu" | ".cuh" => Some("cpp"), // CUDA as C++ superset
        ".sh" | ".bash" => Some("bash"),
        ".cs" => Some("c_sharp"),
        ".lua" => Some("lua"),
        // 5.26.0: closes the AST coverage gap surfaced by the COMPETITION
        // audit (Joern was almost invisible without Scala, Flutter apps
        // had no analysis story).
        ".scala" | ".sc" => Some("scala"),
        ".swift"         => Some("swift"),
        ".dart"          => Some("dart"),
        ".kt" | ".kts" | ".sql" => None, // regex-only, no compatible tree-sitter crate
        ".yaml" | ".yml" | ".cmake" => None, // regex-only, no tree-sitter grammar
        _ => None,
    }
}

fn grammar_to_language(grammar: &str) -> Option<Language> {
    match grammar {
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "bash" => Some(tree_sitter_bash::LANGUAGE.into()),
        "c_sharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        "lua" => Some(tree_sitter_lua::LANGUAGE.into()),
        "scala" => Some(tree_sitter_scala::LANGUAGE.into()),
        "swift" => Some(tree_sitter_swift::LANGUAGE.into()),
        "dart"  => Some(tree_sitter_dart::LANGUAGE.into()),
        // kotlin and sql: no compatible tree-sitter crate, use regex fallback
        _ => None,
    }
}

// ── Thread-local Parser Pool ────────────────────────────────────────

thread_local! {
    static PARSER_CACHE: RefCell<HashMap<&'static str, Parser>> = RefCell::new(HashMap::new());
}

fn parse_with_treesitter(content: &str, grammar: &'static str) -> Option<Tree> {
    PARSER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let parser = cache.entry(grammar).or_insert_with(|| {
            let mut p = Parser::new();
            if let Some(lang) = grammar_to_language(grammar) {
                if let Err(e) = p.set_language(&lang) {
                    if !QUIET.load(Ordering::Relaxed) {
                        eprintln!("Warning: failed to load {grammar} grammar: {e}");
                    }
                }
            }
            p
        });
        parser.parse(content, None)
    })
}

// ── AST Node Collection ─────────────────────────────────────────────

fn collect_nodes<'a>(node: Node<'a>, type_set: &HashSet<&str>, results: &mut Vec<Node<'a>>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if type_set.contains(current.kind()) {
            results.push(current);
        }
        // Push children in reverse order so we process left-to-right
        let count = current.child_count();
        for i in (0..count).rev() {
            if let Some(child) = current.child(i) {
                stack.push(child);
            }
        }
    }
}

fn collect<'a>(node: Node<'a>, types: &[&str]) -> Vec<Node<'a>> {
    let set: HashSet<&str> = types.iter().copied().collect();
    let mut results = Vec::new();
    collect_nodes(node, &set, &mut results);
    results
}

/// Get node text, returning empty string on UTF-8 errors.
fn text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn is_js_like(grammar: &str) -> bool {
    matches!(grammar, "typescript" | "tsx" | "javascript")
}

// ── Import Type Sets ────────────────────────────────────────────────

fn import_types(grammar: &str) -> &'static [&'static str] {
    match grammar {
        "typescript" | "tsx" | "javascript" => &["import_statement", "export_statement"],
        "python" => &["import_statement", "import_from_statement"],
        "rust" => &["use_declaration", "mod_item"],
        "go" => &["import_spec"],
        "java" => &["import_declaration"],
        "ruby" => &["call", "command_call", "command"],
        "php" => &["namespace_use_declaration", "include_expression", "require_expression"],
        "c" | "cpp" => &["preproc_include"],
        "bash" => &["command"],
        "c_sharp" => &["using_directive"],
        "kotlin" => &["import_header"],
        "lua" => &["function_call"],
        "sql" => &[], // SQL has no imports
        // 5.26.0
        "scala" => &["import_declaration"],
        "swift" => &["import_declaration"],
        "dart"  => &["import_or_export", "library_import", "library_export"],
        _ => &[],
    }
}

fn func_types(grammar: &str) -> &'static [&'static str] {
    match grammar {
        "typescript" | "tsx" | "javascript" => &["function_declaration", "method_definition", "arrow_function"],
        "python" => &["function_definition"],
        "rust" => &["function_item"],
        "go" => &["function_declaration", "method_declaration"],
        "java" => &["method_declaration", "constructor_declaration"],
        "ruby" => &["method", "singleton_method"],
        "php" => &["function_definition", "method_declaration"],
        "c" => &["function_definition"],
        "cpp" => &["function_definition", "template_declaration"],
        "bash" => &["function_definition"],
        "c_sharp" => &["method_declaration", "constructor_declaration"],
        "kotlin" => &["function_declaration"],
        "lua" => &["function_declaration", "function_definition_statement"],
        "sql" => &["create_function_statement"],
        // 5.26.0
        "scala" => &["function_definition", "function_declaration", "given_definition"],
        "swift" => &["function_declaration", "init_declaration", "deinit_declaration",
                     "protocol_function_declaration"],
        "dart"  => &["function_declaration", "function_signature", "method_declaration",
                     "method_signature", "external_function_declaration",
                     "local_function_declaration", "constructor_signature",
                     "factory_constructor_signature", "getter_declaration",
                     "setter_declaration", "getter_signature"],
        _ => &[],
    }
}

fn export_types(grammar: &str) -> &'static [&'static str] {
    match grammar {
        "typescript" | "tsx" | "javascript" => &["export_statement"],
        "python" => &["function_definition", "class_definition"],
        "rust" => &["function_item", "struct_item", "enum_item", "type_item", "impl_item"],
        "go" => &["function_declaration", "method_declaration", "type_declaration"],
        "java" => &["method_declaration", "class_declaration"],
        "ruby" => &["method", "singleton_method"],
        "php" => &["function_definition", "class_declaration"],
        "c" => &["function_definition"],
        "cpp" => &["function_definition", "template_declaration", "class_specifier"],
        "bash" => &["function_definition"],
        "c_sharp" => &["method_declaration", "class_declaration"],
        "kotlin" => &["function_declaration", "class_declaration"],
        "lua" => &["function_declaration", "function_definition_statement"],
        "sql" => &["create_function_statement", "create_table_statement"],
        // 5.26.0 — top-level Scala defs (function_definition, class_definition,
        // object_definition, trait_definition, enum_definition); Swift type
        // declarations; Dart class + mixin + extension types.
        "scala" => &["function_definition", "class_definition", "object_definition",
                     "trait_definition", "enum_definition", "type_definition",
                     "extension_definition", "given_definition"],
        "swift" => &["function_declaration", "class_declaration", "protocol_declaration",
                     "typealias_declaration", "init_declaration"],
        "dart"  => &["class_declaration", "mixin_declaration", "extension_declaration",
                     "extension_type_declaration", "enum_declaration",
                     "function_declaration"],
        _ => &[],
    }
}

fn return_types(grammar: &str) -> &'static [&'static str] {
    match grammar {
        "typescript" | "tsx" | "javascript" => &["return_statement"],
        "python" => &["return_statement"],
        "rust" => &["return_expression"],
        "go" => &["return_statement"],
        "java" => &["return_statement"],
        "ruby" => &["return"],
        "php" => &["return_statement"],
        "c_sharp" => &["return_statement"],
        "kotlin" => &["jump_expression"],
        _ => &[],
    }
}

// ── Import Extraction ───────────────────────────────────────────────

fn extract_imports_from_ast(root: Node, grammar: &str, src: &[u8]) -> Vec<String> {
    let mut imports = Vec::new();
    let itypes = import_types(grammar);

    if is_js_like(grammar) {
        for node in collect(root, itypes) {
            let node_text = text(node, src);
            if node_text.starts_with("import type") {
                continue;
            }
            if let Some(source) = node.child_by_field_name("source") {
                let s = text(source, src).replace(&['\'', '"'][..], "");
                if !s.is_empty() {
                    imports.push(s);
                }
            }
        }
        // Dynamic imports: call_expression where function is "import"
        for node in collect(root, &["call_expression"]) {
            let func = node.child_by_field_name("function").or_else(|| node.child(0));
            if let Some(f) = func {
                if f.kind() == "import" {
                    let args = node.child_by_field_name("arguments").or_else(|| node.child(1));
                    if let Some(args) = args {
                        let arg = args.child(1).or_else(|| args.child(0));
                        if let Some(arg) = arg {
                            if arg.kind() == "string" {
                                let s = text(arg, src).replace(&['\'', '"'][..], "");
                                if !s.is_empty() {
                                    imports.push(s);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if grammar == "python" {
        for node in collect(root, itypes) {
            if node.kind() == "import_from_statement" {
                if let Some(mod_name) = node.child_by_field_name("module_name") {
                    let t = text(mod_name, src);
                    // Skip relative-only imports like "." or ".."
                    if !t.chars().all(|c| c == '.') && !t.is_empty() {
                        imports.push(t.to_string());
                    }
                }
            } else {
                // import X
                let count = node.child_count();
                for i in 0..count {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "dotted_name" {
                            let t = text(child, src);
                            if !t.is_empty() {
                                imports.push(t.to_string());
                            }
                        }
                    }
                }
            }
        }
    } else if grammar == "rust" {
        for node in collect(root, itypes) {
            if node.kind() == "mod_item" {
                // mod foo; → import "foo" (resolved to foo.rs or foo/mod.rs)
                if let Some(name) = node.child_by_field_name("name") {
                    let mod_name = text(name, src);
                    if !mod_name.is_empty() {
                        // Check if this is a `mod foo;` (external) vs `mod foo { ... }` (inline)
                        // Inline mods have a body child; external ones don't
                        let has_body = node.child_by_field_name("body").is_some();
                        if !has_body {
                            imports.push(format!("./{mod_name}"));
                        }
                    }
                }
            } else {
                // use_declaration
                let path_node = node.child_by_field_name("argument").or_else(|| node.child(1));
                if let Some(pn) = path_node {
                    let t = text(pn, src);
                    if t != "use" && !t.is_empty() {
                        // Take first 2 :: segments
                        let trimmed = t.trim_end_matches(';');
                        let segments: Vec<&str> = trimmed.split("::").take(2).collect();
                        imports.push(segments.join("::"));
                    }
                }
            }
        }
    } else if grammar == "go" {
        for node in collect(root, &["import_spec"]) {
            if let Some(path) = node.child_by_field_name("path") {
                let s = text(path, src).replace('"', "");
                if !s.is_empty() {
                    imports.push(s);
                }
            }
        }
    } else if grammar == "java" {
        for node in collect(root, itypes) {
            let t = text(node, src);
            let cleaned = t
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .trim();
            if !cleaned.is_empty() {
                imports.push(cleaned.to_string());
            }
        }
    } else if grammar == "ruby" {
        for node in collect(root, &["call", "command_call", "command"]) {
            let method = node
                .child_by_field_name("method")
                .or_else(|| node.child_by_field_name("name"));
            if let Some(m) = method {
                let mt = text(m, src);
                if mt == "require" || mt == "require_relative" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let ac = args.child_count();
                        for i in 0..ac {
                            if let Some(arg) = args.child(i) {
                                let k = arg.kind();
                                if k == "string" || k == "string_content" {
                                    let s = text(arg, src).replace(&['\'', '"'][..], "");
                                    if !s.is_empty() {
                                        imports.push(s);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if grammar == "php" {
        for node in collect(root, itypes) {
            if node.kind() == "namespace_use_declaration" {
                let count = node.child_count();
                for i in 0..count {
                    if let Some(child) = node.child(i) {
                        let k = child.kind();
                        if k == "namespace_use_clause" || k == "qualified_name" {
                            let t = text(child, src).trim_end_matches(';').trim().to_string();
                            if !t.is_empty() {
                                imports.push(t);
                            }
                        }
                    }
                }
            } else if node.kind() == "include_expression" || node.kind() == "require_expression" {
                let count = node.child_count();
                for i in 0..count {
                    if let Some(child) = node.child(i) {
                        let k = child.kind();
                        if k == "string" || k == "encapsed_string" {
                            let s = text(child, src).replace(&['\'', '"'][..], "");
                            if !s.is_empty() {
                                imports.push(s);
                            }
                            break;
                        }
                    }
                }
            }
        }
    } else if grammar == "c" || grammar == "cpp" {
        for node in collect(root, itypes) {
            if let Some(path) = node.child_by_field_name("path") {
                let s = text(path, src)
                    .replace(&['\'', '"', '<', '>'][..], "");
                if !s.is_empty() {
                    imports.push(s);
                }
            }
        }
    } else if grammar == "bash" {
        // Look for `source file` and `. file` commands
        for node in collect(root, itypes) {
            if node.kind() == "command" {
                let name_node = node.child_by_field_name("name");
                if let Some(name) = name_node {
                    let cmd = text(name, src);
                    if cmd == "source" || cmd == "." {
                        // The argument is the file to source
                        let count = node.child_count();
                        for i in 0..count {
                            if let Some(arg) = node.child(i) {
                                if arg.kind() == "word" || arg.kind() == "string" || arg.kind() == "raw_string" || arg.kind() == "concatenation" {
                                    let s = text(arg, src).replace(&['\'', '"'][..], "");
                                    if !s.is_empty() && s != "source" && s != "." {
                                        imports.push(s);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if grammar == "c_sharp" {
        // using Namespace.Name;
        for node in collect(root, itypes) {
            let t = text(node, src);
            let cleaned = t
                .trim_start_matches("using ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .trim();
            if !cleaned.is_empty() {
                imports.push(cleaned.to_string());
            }
        }
    } else if grammar == "kotlin" {
        // import package.name
        for node in collect(root, itypes) {
            let t = text(node, src);
            let cleaned = t
                .trim_start_matches("import ")
                .trim_end_matches(';')
                .trim();
            if !cleaned.is_empty() {
                imports.push(cleaned.to_string());
            }
        }
    } else if grammar == "lua" {
        // require("module") or require "module"
        for node in collect(root, itypes) {
            let t = text(node, src);
            if t.contains("require") {
                // Extract string argument
                for child in collect(node, &["string"]) {
                    let s = text(child, src).replace(&['\'', '"'][..], "");
                    if !s.is_empty() {
                        imports.push(s);
                    }
                }
            }
        }
    }
    // SQL: no imports to extract

    imports
}

// ── Export Extraction ────────────────────────────────────────────────

fn extract_exports_from_ast(root: Node, grammar: &str, src: &[u8]) -> Vec<String> {
    let mut exports = Vec::new();
    let etypes = export_types(grammar);

    if is_js_like(grammar) {
        for node in collect(root, etypes) {
            let node_text = text(node, src);
            if node_text.starts_with("export type") || node_text.starts_with("export interface") {
                continue;
            }
            if let Some(decl) = node.child_by_field_name("declaration") {
                if let Some(name) = decl.child_by_field_name("name") {
                    exports.push(text(name, src).to_string());
                } else if decl.kind() == "lexical_declaration" || decl.kind() == "variable_declaration" {
                    for declarator in collect(decl, &["variable_declarator"]) {
                        if let Some(n) = declarator.child_by_field_name("name") {
                            exports.push(text(n, src).to_string());
                        }
                    }
                }
            } else if node_text.contains("export default") {
                if let Some(caps) = EXPORT_DEFAULT_RE.captures(node_text) {
                    exports.push(caps[1].to_string());
                } else {
                    exports.push("default".to_string());
                }
            } else {
                // export { foo, bar } and export { foo as Foo }
                for spec in collect(node, &["export_specifier"]) {
                    let name = spec
                        .child_by_field_name("name")
                        .or_else(|| spec.child_by_field_name("alias"));
                    if let Some(n) = name {
                        exports.push(text(n, src).to_string());
                    }
                }
            }
        }
    } else if grammar == "python" {
        for node in collect(root, etypes) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "module" {
                    if let Some(name) = node.child_by_field_name("name") {
                        let t = text(name, src);
                        if !t.starts_with('_') {
                            exports.push(t.to_string());
                        }
                    }
                }
            }
        }
    } else if grammar == "rust" {
        for node in collect(root, etypes) {
            if let Some(first) = node.child(0) {
                if first.kind() == "visibility_modifier" {
                    if let Some(name) = node.child_by_field_name("name") {
                        exports.push(text(name, src).to_string());
                    }
                }
            }
        }
    } else if grammar == "go" {
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                if !t.is_empty() {
                    let first_char = t.chars().next().unwrap();
                    if first_char.is_uppercase() {
                        exports.push(t.to_string());
                    }
                }
            }
        }
    } else if grammar == "java" {
        for node in collect(root, etypes) {
            if let Some(modifiers) = node.child(0) {
                if modifiers.kind() == "modifiers" && text(modifiers, src).contains("public") {
                    if let Some(name) = node.child_by_field_name("name") {
                        exports.push(text(name, src).to_string());
                    }
                }
            }
        }
    } else if grammar == "ruby" {
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                if !t.starts_with('_') {
                    exports.push(t.to_string());
                }
            }
        }
    } else if grammar == "php" {
        for node in collect(root, etypes) {
            if node.kind() == "class_declaration" || node.kind() == "function_definition" {
                if let Some(name) = node.child_by_field_name("name") {
                    exports.push(text(name, src).to_string());
                }
            }
        }
    } else if grammar == "bash" {
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                if !t.is_empty() {
                    exports.push(t.to_string());
                }
            }
        }
    } else if grammar == "c_sharp" {
        // public methods and classes
        for node in collect(root, etypes) {
            if let Some(modifiers) = node.child(0) {
                if modifiers.kind() == "modifier" || text(modifiers, src).contains("public") {
                    if let Some(name) = node.child_by_field_name("name") {
                        exports.push(text(name, src).to_string());
                    }
                }
            }
        }
    } else if grammar == "kotlin" {
        // fun declarations and class declarations (public by default)
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                let node_text = text(node, src);
                // Skip private/internal
                if !node_text.contains("private ") && !node_text.contains("internal ") && !t.is_empty() {
                    exports.push(t.to_string());
                }
            }
        }
    } else if grammar == "lua" {
        // function declarations
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                if !t.is_empty() {
                    exports.push(t.to_string());
                }
            }
        }
    } else if grammar == "sql" {
        // CREATE TABLE and CREATE FUNCTION names
        for node in collect(root, etypes) {
            if let Some(name) = node.child_by_field_name("name") {
                let t = text(name, src);
                if !t.is_empty() {
                    exports.push(t.to_string());
                }
            }
        }
    } else if grammar == "c" || grammar == "cpp" {
        for node in collect(root, etypes) {
            if node.kind() == "function_definition" {
                let node_text = text(node, src);
                if node_text.starts_with("static ") {
                    continue;
                }
                let decl = node.child_by_field_name("declarator");
                if let Some(d) = decl {
                    let inner = d
                        .child_by_field_name("declarator")
                        .or_else(|| d.child_by_field_name("name"));
                    let name_text = if let Some(inner) = inner {
                        text(inner, src)
                    } else {
                        text(d, src)
                    };
                    // Strip parameter list and get last :: segment
                    let clean = name_text
                        .split('(')
                        .next()
                        .unwrap_or(name_text)
                        .split("::")
                        .last()
                        .unwrap_or(name_text);
                    if !clean.is_empty() {
                        exports.push(clean.to_string());
                    }
                }
            } else if node.kind() == "class_specifier" {
                if let Some(name) = node.child_by_field_name("name") {
                    exports.push(text(name, src).to_string());
                }
            } else if node.kind() == "template_declaration" {
                let count = node.child_count();
                for i in 0..count {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "function_definition" || child.kind() == "class_specifier" {
                            let name_node = child
                                .child_by_field_name("name")
                                .or_else(|| {
                                    child
                                        .child_by_field_name("declarator")
                                        .and_then(|d| d.child_by_field_name("declarator"))
                                });
                            if let Some(n) = name_node {
                                let t = text(n, src);
                                let clean = t
                                    .split('(')
                                    .next()
                                    .unwrap_or(t)
                                    .split("::")
                                    .last()
                                    .unwrap_or(t);
                                if !clean.is_empty() {
                                    exports.push(clean.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    exports
}

// ── Function Extraction ─────────────────────────────────────────────

fn extract_functions_from_ast(root: Node, grammar: &str, src: &[u8]) -> Vec<FunctionInfo> {
    let mut functions = Vec::new();
    let ftypes = func_types(grammar);

    for node in collect(root, ftypes) {
        let name = get_function_name(node, grammar, src);
        let name = match name {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        let start_line = node.start_position().row + 1;
        let end_line = node.end_position().row + 1;

        // Extract call expressions within this function
        let call_nodes = collect(node, &["call_expression", "call"]);
        let mut calls = Vec::new();
        let mut seen = HashSet::new();
        for call in &call_nodes {
            let func = call
                .child_by_field_name("function")
                .or_else(|| call.child_by_field_name("method"))
                .or_else(|| call.child(0));
            if let Some(f) = func {
                let callee = if f.kind() == "member_expression" || f.kind() == "field_expression" {
                    f.child_by_field_name("property")
                        .or_else(|| f.child_by_field_name("field"))
                        .map(|p| text(p, src).to_string())
                        .unwrap_or_else(|| text(f, src).to_string())
                } else {
                    text(f, src).to_string()
                };
                if !callee.is_empty() && callee != name && seen.insert(callee.clone()) {
                    calls.push(callee);
                }
            }
        }

        // CUDA kernel launches: detect <<<>>> syntax
        if grammar == "cpp" || grammar == "c" {
            let body_text = text(node, src);
            for caps in KERNEL_RE.captures_iter(body_text) {
                let kernel_name = caps[1].to_string();
                if !kernel_name.is_empty() && seen.insert(kernel_name.clone()) {
                    calls.push(kernel_name);
                }
            }
        }

        // Determine if exported
        let is_exported = is_function_exported(node, grammar, &name, src);

        functions.push(FunctionInfo {
            name,
            start_line,
            end_line,
            calls,
            is_exported,
            parameters: None,
            return_lines: None,
        });
    }

    functions
}

fn get_function_name(node: Node, grammar: &str, src: &[u8]) -> Option<String> {
    // Try the standard "name" field first
    if let Some(name) = node.child_by_field_name("name") {
        return Some(text(name, src).to_string());
    }

    // Arrow functions: find parent variable_declarator name
    if node.kind() == "arrow_function" {
        if let Some(parent) = node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(n) = parent.child_by_field_name("name") {
                    return Some(text(n, src).to_string());
                }
            }
        }
    }

    // C/C++: function name is inside declarator -> function_declarator -> identifier
    if grammar == "c" || grammar == "cpp" {
        if let Some(decl) = node.child_by_field_name("declarator") {
            let inner = decl
                .child_by_field_name("declarator")
                .or_else(|| decl.child_by_field_name("name"));
            if let Some(inner) = inner {
                return Some(text(inner, src).to_string());
            }
            // Fallback: split on ( and take last :: segment
            let dt = text(decl, src);
            let clean = dt
                .split('(')
                .next()
                .unwrap_or(dt)
                .split("::")
                .last()
                .unwrap_or(dt);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }

        // Template declarations: dig into the inner function
        if node.kind() == "template_declaration" {
            let count = node.child_count();
            for i in 0..count {
                if let Some(child) = node.child(i) {
                    if child.kind() == "function_definition" {
                        if let Some(d) = child.child_by_field_name("declarator") {
                            let inner = d
                                .child_by_field_name("declarator")
                                .or_else(|| d.child_by_field_name("name"));
                            if let Some(inner) = inner {
                                return Some(text(inner, src).to_string());
                            }
                            let dt = text(d, src);
                            let clean = dt
                                .split('(')
                                .next()
                                .unwrap_or(dt)
                                .split("::")
                                .last()
                                .unwrap_or(dt);
                            if !clean.is_empty() {
                                return Some(clean.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn is_function_exported(node: Node, grammar: &str, name: &str, src: &[u8]) -> bool {
    if is_js_like(grammar) {
        if let Some(parent) = node.parent() {
            if parent.kind() == "export_statement" {
                return true;
            }
            // Arrow function → variable_declarator → lexical_declaration → export_statement
            if node.kind() == "arrow_function" {
                if let Some(gp) = parent.parent() {
                    if let Some(ggp) = gp.parent() {
                        if ggp.kind() == "export_statement" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    } else if grammar == "python" {
        !name.starts_with('_')
    } else if grammar == "rust" {
        node.child(0)
            .map(|c| c.kind() == "visibility_modifier")
            .unwrap_or(false)
    } else if grammar == "go" {
        name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
    } else if grammar == "java" {
        node.child(0)
            .map(|c| c.kind() == "modifiers" && text(c, src).contains("public"))
            .unwrap_or(false)
    } else if grammar == "ruby" {
        !name.starts_with('_')
    } else if grammar == "php" {
        node.child(0)
            .map(|c| {
                if c.kind() == "visibility_modifier" {
                    text(c, src) == "public"
                } else {
                    true
                }
            })
            .unwrap_or(true)
    } else if grammar == "c" || grammar == "cpp" {
        !text(node, src).starts_with("static ")
    } else if grammar == "bash" {
        // All bash functions are effectively exported (available to subshells via export -f)
        true
    } else if grammar == "c_sharp" {
        // public methods
        node.child(0)
            .map(|c| text(c, src).contains("public"))
            .unwrap_or(false)
    } else if grammar == "kotlin" {
        // Kotlin: public by default, check for private/internal
        let nt = text(node, src);
        !nt.contains("private ") && !nt.contains("internal ")
    } else if grammar == "lua" {
        // Lua: all top-level functions are effectively exported
        true
    } else if grammar == "sql" {
        // SQL: stored procedures/functions are always exported
        true
    } else {
        false
    }
}

// ── Data Flow Extraction ────────────────────────────────────────────

fn extract_data_flow_from_ast(
    root: Node,
    grammar: &str,
    src: &[u8],
    functions: &mut [FunctionInfo],
) -> FileDataFlow {
    let mut definitions = Vec::new();
    let mut uses = Vec::new();
    let mut call_args = Vec::new();
    let mut property_accesses = Vec::new();
    let js_like = is_js_like(grammar);

    // Scope lookup closure (find which function a line belongs to)
    let find_scope = |line: usize, funcs: &[FunctionInfo]| -> String {
        for f in funcs {
            if line >= f.start_line && line <= f.end_line {
                return f.name.clone();
            }
        }
        "__module__".to_string()
    };

    // 1) Extract parameters from functions
    let ftypes = func_types(grammar);
    for node in collect(root, ftypes) {
        let fn_name = get_function_name(node, grammar, src);
        let fn_name = match fn_name {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        // Find matching FunctionInfo
        let fn_info_idx = functions.iter().position(|f| f.name == fn_name);
        if fn_info_idx.is_none() {
            continue;
        }
        let fn_info_idx = fn_info_idx.unwrap();

        let mut params = Vec::new();
        if let Some(params_node) = node.child_by_field_name("parameters") {
            if js_like {
                // JS/TS: required_parameter, optional_parameter
                for pnode in collect(params_node, &["required_parameter", "optional_parameter"]) {
                    let pname = pnode
                        .child_by_field_name("pattern")
                        .or_else(|| pnode.child_by_field_name("name"));
                    if let Some(pn) = pname {
                        params.push(text(pn, src).to_string());
                    }
                }
                // Fallback: bare identifiers
                if params.is_empty() {
                    let count = params_node.child_count();
                    for i in 0..count {
                        if let Some(c) = params_node.child(i) {
                            if c.kind() == "identifier" {
                                params.push(text(c, src).to_string());
                            }
                        }
                    }
                }
            } else if grammar == "python" {
                let count = params_node.child_count();
                for i in 0..count {
                    if let Some(c) = params_node.child(i) {
                        match c.kind() {
                            "identifier" => params.push(text(c, src).to_string()),
                            "typed_parameter" | "default_parameter" => {
                                if let Some(n) = c.child_by_field_name("name") {
                                    params.push(text(n, src).to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                // Generic: collect identifiers that aren't type annotations
                for id_node in collect(params_node, &["identifier"]) {
                    if let Some(parent) = id_node.parent() {
                        let pk = parent.kind();
                        if pk != "type_identifier" && pk != "type_annotation" {
                            params.push(text(id_node, src).to_string());
                        }
                    }
                }
            }
        }

        let start_line = node.start_position().row + 1;
        for p in &params {
            definitions.push(DataFlowDef {
                name: p.clone(),
                line: start_line,
                rhs: format!("param:{fn_name}"),
                scope: fn_name.clone(),
            });
        }

        // Return lines
        let ret_types = return_types(grammar);
        let mut ret_lines = Vec::new();
        for ret in collect(node, ret_types) {
            ret_lines.push(ret.start_position().row + 1);
        }

        // Update the function info
        functions[fn_info_idx].parameters = Some(params);
        functions[fn_info_idx].return_lines = Some(ret_lines);
    }

    // 2) Variable declarations / assignments
    let assign_types: &[&str] = if js_like {
        &["variable_declarator", "assignment_expression", "augmented_assignment_expression"]
    } else if grammar == "python" {
        &["assignment", "augmented_assignment"]
    } else if grammar == "go" {
        &["short_var_declaration", "assignment_statement"]
    } else if grammar == "rust" {
        &["let_declaration", "assignment_expression"]
    } else if grammar == "java" {
        &["variable_declarator", "assignment_expression"]
    } else {
        &[]
    };

    for node in collect(root, assign_types) {
        let line = node.start_position().row + 1;
        let scope = find_scope(line, functions);

        if js_like {
            if node.kind() == "variable_declarator" {
                let name_node = node.child_by_field_name("name");
                let value_node = node.child_by_field_name("value");
                if let (Some(name), Some(value)) = (name_node, value_node) {
                    let name_text = text(name, src).to_string();
                    let rhs_text = truncate(text(value, src), 200);
                    definitions.push(DataFlowDef {
                        name: name_text,
                        line,
                        rhs: rhs_text,
                        scope: scope.clone(),
                    });
                    for id in collect(value, &["identifier"]) {
                        uses.push(DataFlowUse {
                            name: text(id, src).to_string(),
                            line,
                            context: UseContext::AssignRhs,
                            scope: scope.clone(),
                        });
                    }
                }
            } else {
                // assignment_expression / augmented_assignment_expression
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                if let (Some(left), Some(right)) = (left, right) {
                    if left.kind() == "identifier" {
                        definitions.push(DataFlowDef {
                            name: text(left, src).to_string(),
                            line,
                            rhs: truncate(text(right, src), 200),
                            scope: scope.clone(),
                        });
                    } else if left.kind() == "member_expression" {
                        let base = left.child_by_field_name("object").map(|o| text(o, src));
                        let prop = left.child_by_field_name("property").map(|p| text(p, src));
                        if let (Some(base), Some(prop)) = (base, prop) {
                            property_accesses.push(DataFlowPropertyAccess {
                                base: base.to_string(),
                                property: prop.to_string(),
                                line,
                                kind: PropertyAccessKind::Write,
                                scope: scope.clone(),
                            });
                        }
                    }
                    for id in collect(right, &["identifier"]) {
                        uses.push(DataFlowUse {
                            name: text(id, src).to_string(),
                            line,
                            context: UseContext::AssignRhs,
                            scope: scope.clone(),
                        });
                    }
                }
            }
        } else if grammar == "python" {
            let left = node.child_by_field_name("left").or_else(|| node.child(0));
            let right = node.child_by_field_name("right").or_else(|| node.child(2));
            if let (Some(left), Some(right)) = (left, right) {
                if left.kind() == "identifier" {
                    definitions.push(DataFlowDef {
                        name: text(left, src).to_string(),
                        line,
                        rhs: truncate(text(right, src), 200),
                        scope: scope.clone(),
                    });
                }
            }
        } else if grammar == "go" {
            let left = node.child_by_field_name("left").or_else(|| node.child(0));
            let right = node.child_by_field_name("right").or_else(|| node.child(2));
            if let (Some(left), Some(right)) = (left, right) {
                if left.kind() == "identifier" {
                    definitions.push(DataFlowDef {
                        name: text(left, src).to_string(),
                        line,
                        rhs: truncate(text(right, src), 200),
                        scope: scope.clone(),
                    });
                } else if left.kind() == "expression_list" {
                    let count = left.child_count();
                    for i in 0..count {
                        if let Some(c) = left.child(i) {
                            if c.kind() == "identifier" {
                                definitions.push(DataFlowDef {
                                    name: text(c, src).to_string(),
                                    line,
                                    rhs: truncate(text(right, src), 200),
                                    scope: scope.clone(),
                                });
                            }
                        }
                    }
                }
            }
        } else if grammar == "rust" && node.kind() == "let_declaration" {
            let pattern = node.child_by_field_name("pattern");
            let value = node.child_by_field_name("value");
            if let (Some(pattern), Some(value)) = (pattern, value) {
                if pattern.kind() == "identifier" {
                    definitions.push(DataFlowDef {
                        name: text(pattern, src).to_string(),
                        line,
                        rhs: truncate(text(value, src), 200),
                        scope: scope.clone(),
                    });
                }
            }
        } else if grammar == "java" && node.kind() == "variable_declarator" {
            let name_node = node.child_by_field_name("name");
            let value_node = node.child_by_field_name("value");
            if let (Some(name), Some(value)) = (name_node, value_node) {
                definitions.push(DataFlowDef {
                    name: text(name, src).to_string(),
                    line,
                    rhs: truncate(text(value, src), 200),
                    scope: scope.clone(),
                });
            }
        }
    }

    // 3) Call arguments
    for node in collect(root, &["call_expression", "call"]) {
        let line = node.start_position().row + 1;
        let scope = find_scope(line, functions);

        let func = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("method"))
            .or_else(|| node.child(0));
        let callee = match func {
            Some(f) => {
                if f.kind() == "member_expression" || f.kind() == "field_expression" {
                    truncate(text(f, src), 100)
                } else {
                    text(f, src).to_string()
                }
            }
            None => continue,
        };
        if callee.is_empty() {
            continue;
        }

        // Find arguments node
        let args_node = node.child_by_field_name("arguments").or_else(|| {
            let count = node.child_count();
            for i in 0..count {
                if let Some(c) = node.child(i) {
                    if c.kind() == "arguments" || c.kind() == "argument_list" {
                        return Some(c);
                    }
                }
            }
            None
        });

        if let Some(args_node) = args_node {
            let mut args = Vec::new();
            let mut pos = 0usize;
            let ac = args_node.child_count();
            for i in 0..ac {
                if let Some(arg) = args_node.child(i) {
                    let k = arg.kind();
                    if k == "," || k == "(" || k == ")" {
                        continue;
                    }
                    let mut names = Vec::new();
                    for id in collect(arg, &["identifier"]) {
                        let n = text(id, src).to_string();
                        uses.push(DataFlowUse {
                            name: n.clone(),
                            line,
                            context: UseContext::Arg,
                            scope: scope.clone(),
                        });
                        names.push(n);
                    }
                    args.push(CallArgInfo {
                        position: pos,
                        expr: truncate(text(arg, src), 150),
                        names,
                    });
                    pos += 1;
                }
            }
            if !args.is_empty() {
                call_args.push(DataFlowCallArg {
                    callee: callee.clone(),
                    args,
                    line,
                    scope: scope.clone(),
                });
            }
        }
    }

    // 4) Property reads
    let prop_read_types: &[&str] = if js_like {
        &["member_expression"]
    } else if grammar == "python" {
        &["attribute"]
    } else if grammar == "go" {
        &["selector_expression"]
    } else if grammar == "rust" {
        &["field_expression"]
    } else if grammar == "java" {
        &["field_access"]
    } else {
        &[]
    };

    if !prop_read_types.is_empty() {
        for node in collect(root, prop_read_types) {
            // Skip if this is the LHS of an assignment
            if let Some(parent) = node.parent() {
                if parent.kind() == "assignment_expression" {
                    if let Some(first) = parent.child(0) {
                        if first.id() == node.id() {
                            continue;
                        }
                    }
                }
            }

            let line = node.start_position().row + 1;
            let scope = find_scope(line, functions);

            let base = node
                .child_by_field_name("object")
                .or_else(|| node.child(0))
                .map(|n| text(n, src));
            let prop = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("field"))
                .or_else(|| node.child_by_field_name("attribute"))
                .map(|n| text(n, src));

            if let (Some(base), Some(prop)) = (base, prop) {
                property_accesses.push(DataFlowPropertyAccess {
                    base: truncate(base, 80),
                    property: prop.to_string(),
                    line,
                    kind: PropertyAccessKind::Read,
                    scope,
                });
            }
        }
    }

    // 5) Return statement uses
    let ret_types = return_types(grammar);
    for node in collect(root, ret_types) {
        let line = node.start_position().row + 1;
        let scope = find_scope(line, functions);
        let expr = node.child(1).or_else(|| node.child_by_field_name("value"));
        if let Some(expr) = expr {
            for id in collect(expr, &["identifier"]) {
                uses.push(DataFlowUse {
                    name: text(id, src).to_string(),
                    line,
                    context: UseContext::Return,
                    scope: scope.clone(),
                });
            }
        }
    }

    // 6) Template substitution uses (JS-like only)
    if js_like {
        for node in collect(root, &["template_substitution"]) {
            let line = node.start_position().row + 1;
            let scope = find_scope(line, functions);
            for id in collect(node, &["identifier"]) {
                uses.push(DataFlowUse {
                    name: text(id, src).to_string(),
                    line,
                    context: UseContext::Template,
                    scope: scope.clone(),
                });
            }
        }
    }

    // 7) Object destructuring patterns (JS-like only)
    if js_like {
        for node in collect(root, &["object_pattern"]) {
            let parent = match node.parent() {
                Some(p) if p.kind() == "variable_declarator" => p,
                _ => continue,
            };
            let value_node = match parent.child_by_field_name("value") {
                Some(v) => v,
                None => continue,
            };
            let line = node.start_position().row + 1;
            let scope = find_scope(line, functions);
            let base_name = if value_node.kind() == "identifier" {
                text(value_node, src).to_string()
            } else {
                truncate(text(value_node, src), 80)
            };

            for prop in collect(node, &["shorthand_property_identifier_pattern", "pair_pattern"]) {
                let prop_name = if prop.kind() == "shorthand_property_identifier_pattern" {
                    text(prop, src).to_string()
                } else {
                    match prop.child_by_field_name("key") {
                        Some(k) => text(k, src).to_string(),
                        None => continue,
                    }
                };
                if !prop_name.is_empty() {
                    definitions.push(DataFlowDef {
                        name: prop_name.clone(),
                        line,
                        rhs: format!("{base_name}.{prop_name}"),
                        scope: scope.clone(),
                    });
                    property_accesses.push(DataFlowPropertyAccess {
                        base: base_name.clone(),
                        property: prop_name,
                        line,
                        kind: PropertyAccessKind::Read,
                        scope: scope.clone(),
                    });
                }
            }
        }
    }

    FileDataFlow {
        definitions,
        uses,
        call_args,
        property_accesses,
    }
}

// ── URL Extraction ──────────────────────────────────────────────────

fn extract_urls(content: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for caps in URL_RE.captures_iter(content) {
        let url = &caps[1];
        if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("example.com") {
            continue;
        }
        // Truncate at ? and 120 chars, sanitize credentials
        let truncated = url.split('?').next().unwrap_or(url);
        let limited = if truncated.len() > 120 { &truncated[..120] } else { truncated };
        urls.push(sanitize_url(limited));
    }
    urls
}

// ── Line Index Helpers ─────────────────────────────────────────────

/// Build a sorted index of byte positions where each line starts.
/// Entry 0 is always 0 (line 1 starts at byte 0).
fn build_line_index(content: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(content.match_indices('\n').map(|(i, _)| i + 1))
        .collect()
}

/// Given a line index and a byte position, return the 1-based line number.
/// Uses binary search for O(log n) lookup.
fn line_at(line_index: &[usize], pos: usize) -> usize {
    line_index.partition_point(|&start| start <= pos)
}

// ── Bridge Detection ───────────────────────────────────────────────

fn extract_bridges(content: &str, ext: &str, root: Option<tree_sitter::Node>, src: &[u8]) -> Vec<BridgeInfo> {
    let mut bridges = Vec::new();

    match ext {
        ".py" => extract_python_bridges(content, &mut bridges),
        ".cpp" | ".cc" | ".cxx" | ".hpp" | ".cu" | ".cuh" | ".c" | ".h" => {
            extract_cpp_bridges(content, &mut bridges);
        }
        ".rs" => extract_rust_bridges(content, root, src, &mut bridges),
        ".yaml" | ".yml" => extract_yaml_bridges(content, &mut bridges),
        ".cmake" => extract_cpp_bridges(content, &mut bridges), // CMake uses same build-dep patterns
        _ => {}
    }

    bridges
}

fn extract_yaml_bridges(content: &str, bridges: &mut Vec<BridgeInfo>) {
    let line_index = build_line_index(content);

    // PyTorch native_functions.yaml pattern:
    // - func: op_name.variant(args) -> return
    //   dispatch:
    //     CUDA: op_cuda_impl
    //     CPU: op_cpu_impl
    for caps in YAML_FUNC_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::YamlDispatch,
            name,
            target: None,
            line,
            namespace: None,
        });
    }

    // dispatch: \n    KEY: impl_function
    for caps in YAML_DISPATCH_RE.captures_iter(content) {
        let device = caps[1].to_string();
        let func = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::YamlDispatch,
            name: func,
            target: None,
            line,
            namespace: Some(device),
        });
    }
}

fn extract_python_bridges(content: &str, bridges: &mut Vec<BridgeInfo>) {
    let line_index = build_line_index(content);

    // torch.ops.namespace.op_name(...)
    for caps in TORCH_OPS_RE.captures_iter(content) {
        let ns = caps[1].to_string();
        let op = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TorchOps,
            name: op,
            target: None,
            line,
            namespace: Some(ns),
        });
    }

    // @triton.jit decorator
    for m in TRITON_JIT_RE.find_iter(content) {
        let pos = m.start();
        let line = line_at(&line_index, pos);
        // Get function name from next line: def func_name(
        let after = &content[m.end()..];
        if let Some(caps) = DEF_FN_RE.captures(after) {
            let name = caps[1].to_string();
            bridges.push(BridgeInfo {
                kind: BridgeKind::TritonKernel,
                name: name.clone(),
                target: Some(name),
                line,
                namespace: None,
            });
        }
    }

    // @triton.autotune wrapping @triton.jit
    for m in AUTOTUNE_RE.find_iter(content) {
        let pos = m.start();
        let line = line_at(&line_index, pos);
        let after = &content[m.end()..];
        if let Some(caps) = DEF_FN_RE.captures(after) {
            let name = caps[1].to_string();
            // Only add if not already caught by @triton.jit
            if !bridges.iter().any(|b| b.kind == BridgeKind::TritonKernel && b.name == name) {
                bridges.push(BridgeInfo {
                    kind: BridgeKind::TritonKernel,
                    name: name.clone(),
                    target: Some(name),
                    line,
                    namespace: None,
                });
            }
        }
    }

    // Triton kernel launch: kernel_name[grid](args) -- subscript followed by call
    for caps in TRITON_LAUNCH_RE.captures_iter(content) {
        let name = caps[1].to_string();
        // Filter out obvious non-kernel subscripts (dict access, list indexing with numbers)
        let grid = &caps[2];
        if grid.contains(',') || grid.contains("BLOCK") || grid.contains("grid") || grid.contains("n_") || grid.contains("cdiv") {
            // Skip common false positives
            if name == "dict" || name == "list" || name == "type" || name == "super" || name == "getattr" {
                continue;
            }
            let pos = caps.get(0).unwrap().start();
            let line = line_at(&line_index, pos);
            bridges.push(BridgeInfo {
                kind: BridgeKind::TritonLaunch,
                name: name.clone(),
                target: Some(name),
                line,
                namespace: None,
            });
        }
    }

    // triton.jit(fn) -- function-call form (Unsloth pattern)
    for caps in TRITON_FN_RE.captures_iter(content) {
        let var_name = caps[1].to_string();
        let fn_name = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TritonKernel,
            name: var_name,
            target: Some(fn_name),
            line,
            namespace: None,
        });
    }

    // Module monkey-patching: module.path.ClassName = ReplacementClass
    // Pattern: dotted.path.Name = SomeName (where Name is capitalized)
    for caps in MONKEY_RE.captures_iter(content) {
        let full_path = format!("{}.{}", &caps[1], &caps[2]);
        let original = caps[2].to_string();
        let replacement = caps[3].to_string();
        if original != replacement {
            // Skip self/cls attribute assignments (not monkey-patching)
            let path = &caps[1];
            if path.starts_with("self.") || path.starts_with("cls.") {
                continue;
            }
            let pos = caps.get(0).unwrap().start();
            let line = line_at(&line_index, pos);
            bridges.push(BridgeInfo {
                kind: BridgeKind::MonkeyPatch,
                name: original,
                target: Some(replacement),
                line,
                namespace: Some(full_path),
            });
        }
    }

    // torch.autograd.Function subclass
    // Pattern: class Name(torch.autograd.Function): or class Name(autograd.Function):
    for caps in AUTOGRAD_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::AutogradFunc,
            name: name.clone(),
            target: Some(name),
            line,
            namespace: None,
        });
    }

    // .apply() invocations for autograd functions: ClassName.apply(args)
    for caps in APPLY_RE.captures_iter(content) {
        let name = caps[1].to_string();
        // Only if the name starts with uppercase (likely a class)
        if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            let pos = caps.get(0).unwrap().start();
            let line = line_at(&line_index, pos);
            // Skip if it's a common non-autograd .apply (like pd.apply)
            if name != "DataFrame" && name != "Series" && name != "GroupBy" {
                bridges.push(BridgeInfo {
                    kind: BridgeKind::AutogradFunc,
                    name: format!("{name}.apply"),
                    target: Some(name),
                    line,
                    namespace: None,
                });
            }
        }
    }

    // setup.py: ext_modules / CMakeExtension
    for caps in EXT_MODULE_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::BuildDep,
            name,
            target: None,
            line,
            namespace: None,
        });
    }
}

fn extract_cpp_bridges(content: &str, bridges: &mut Vec<BridgeInfo>) {
    let line_index = build_line_index(content);

    // TORCH_LIBRARY(namespace, m) { ... }
    for caps in TORCH_LIB_RE.captures_iter(content) {
        let ns = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TorchLibrary,
            name: format!("TORCH_LIBRARY({ns})"),
            target: None,
            line,
            namespace: Some(ns),
        });
    }

    // m.def("op_name(...)")  and  m.impl("op_name", &cpp_func)
    for caps in TORCH_DEF_RE.captures_iter(content) {
        let op = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TorchLibrary,
            name: op,
            target: None,
            line,
            namespace: None,
        });
    }

    for caps in TORCH_IMPL_RE.captures_iter(content) {
        let op = caps[1].to_string();
        let func = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TorchLibrary,
            name: op,
            target: Some(func),
            line,
            namespace: None,
        });
    }

    // TORCH_IMPL_FUNC(op_name)
    for caps in TORCH_IMPL_FUNC_RE.captures_iter(content) {
        let op = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::TorchLibrary,
            name: op.clone(),
            target: Some(op),
            line,
            namespace: None,
        });
    }

    // PYBIND11_MODULE(name, m)
    for caps in PYBIND_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::Pybind11,
            name: name.clone(),
            target: None,
            line,
            namespace: Some(name),
        });
    }

    // py::class_<Type>(m, "PythonName")
    for caps in PY_CLASS_RE.captures_iter(content) {
        let cpp_type = caps[1].to_string();
        let py_name = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::Pybind11,
            name: py_name,
            target: Some(cpp_type),
            line,
            namespace: None,
        });
    }

    // CUDA kernel declarations: __global__ void kernel_name(...)
    for caps in CUDA_KERNEL_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::CudaKernel,
            name: name.clone(),
            target: Some(name),
            line,
            namespace: None,
        });
    }

    // CUDA kernel launches: kernel<<<grid, block>>>(args)
    for caps in CUDA_LAUNCH_RE.captures_iter(content) {
        let name = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::CudaLaunch,
            name: name.clone(),
            target: Some(name),
            line,
            namespace: None,
        });
    }

    // CMake: target_link_libraries(target lib1 lib2)
    for caps in CMAKE_LINK_RE.captures_iter(content) {
        let target = caps[1].to_string();
        let libs = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        for lib in libs.split_whitespace() {
            if lib != "PUBLIC" && lib != "PRIVATE" && lib != "INTERFACE" {
                bridges.push(BridgeInfo {
                    kind: BridgeKind::BuildDep,
                    name: target.clone(),
                    target: Some(lib.to_string()),
                    line,
                    namespace: None,
                });
            }
        }
    }

    // find_package(Name REQUIRED)
    for caps in FIND_PKG_RE.captures_iter(content) {
        let pkg = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::BuildDep,
            name: pkg.clone(),
            target: Some(pkg),
            line,
            namespace: None,
        });
    }

    // C++ DispatchKey: DispatchKeySet::CUDA, DispatchKey::CUDA
    for caps in DISPATCH_KEY_RE.captures_iter(content) {
        let key = caps[1].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::DispatchKey,
            name: format!("DispatchKey::{key}"),
            target: None,
            line,
            namespace: Some(key),
        });
    }
}

fn extract_rust_bridges(content: &str, _root: Option<tree_sitter::Node>, _src: &[u8], bridges: &mut Vec<BridgeInfo>) {
    let line_index = build_line_index(content);

    // #[pyclass] or #[pyclass(name = "PythonName")]
    for caps in PYCLASS_RE.captures_iter(content) {
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        // Get the struct/enum name from the next line
        let after = &content[caps.get(0).unwrap().end()..];
        if let Some(sc) = RUST_STRUCT_RE.captures(after) {
            let rust_name = sc[1].to_string();
            let py_name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| rust_name.clone());
            bridges.push(BridgeInfo {
                kind: BridgeKind::PyO3Class,
                name: py_name,
                target: Some(rust_name),
                line,
                namespace: None,
            });
        }
    }

    // #[pyfunction]
    for m in PYFN_RE.find_iter(content) {
        let pos = m.start();
        let line = line_at(&line_index, pos);
        let after = &content[m.end()..];
        if let Some(caps) = RUST_FN_RE.captures(after) {
            let name = caps[1].to_string();
            bridges.push(BridgeInfo {
                kind: BridgeKind::PyO3Function,
                name: name.clone(),
                target: Some(name),
                line,
                namespace: None,
            });
        }
    }

    // #[pymethods]
    for m in PYMETHODS_RE.find_iter(content) {
        let pos = m.start();
        let line = line_at(&line_index, pos);
        // Get the impl block name
        let after = &content[m.end()..];
        if let Some(caps) = RUST_IMPL_RE.captures(after) {
            let name = caps[1].to_string();
            bridges.push(BridgeInfo {
                kind: BridgeKind::PyO3Methods,
                name: name.clone(),
                target: Some(name),
                line,
                namespace: None,
            });
        }
    }

    // #[pymodule]
    for m in PYMOD_RE.find_iter(content) {
        let pos = m.start();
        let line = line_at(&line_index, pos);
        let after = &content[m.end()..];
        if let Some(caps) = RUST_PUB_FN_RE.captures(after) {
            let name = caps[1].to_string();
            bridges.push(BridgeInfo {
                kind: BridgeKind::PyO3Function,
                name: name.clone(),
                target: Some(name),
                line,
                namespace: None,
            });
        }
    }

    // #[cfg(feature = "cuda")] or #[cfg(feature = "metal")]
    for caps in CFG_RE.captures_iter(content) {
        let feature = caps[1].to_string();
        let gpu_features = ["cuda", "metal", "opencl", "hip", "vulkan", "wgpu", "accelerate"];
        if !gpu_features.iter().any(|&f| feature == f) {
            continue;
        }
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        bridges.push(BridgeInfo {
            kind: BridgeKind::DispatchKey,
            name: format!("cfg(feature={feature})"),
            target: None,
            line,
            namespace: Some(feature),
        });
    }

    // impl Trait for Type -- detect trait implementations
    for caps in TRAIT_IMPL_RE.captures_iter(content) {
        let trait_name = caps[1].to_string();
        let type_name = caps[2].to_string();
        let pos = caps.get(0).unwrap().start();
        let line = line_at(&line_index, pos);
        // Filter to interesting trait names (Backend, Storage, CustomOp, etc.)
        let interesting = ["Backend", "BackendStorage", "CustomOp", "CustomOp1", "CustomOp2",
            "Map1", "Map2", "Module", "Layer", "Forward", "Backward"];
        if interesting.iter().any(|&t| trait_name == t) || trait_name.ends_with("Backend") || trait_name.ends_with("Storage") {
            bridges.push(BridgeInfo {
                kind: BridgeKind::TraitImpl,
                name: trait_name,
                target: Some(type_name),
                line,
                namespace: None,
            });
        }
    }
}

// ── Regex Fallback ──────────────────────────────────────────────────

fn regex_extract_imports(content: &str) -> Vec<String> {
    let mut imports = Vec::new();

    for caps in IMPORT_RE.captures_iter(content) {
        let t = caps.get(1).or_else(|| caps.get(2));
        if let Some(m) = t {
            imports.push(m.as_str().to_string());
        }
    }

    for caps in DYNAMIC_IMPORT_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            imports.push(m.as_str().to_string());
        }
    }

    imports
}

fn regex_extract_exports(content: &str) -> Vec<String> {
    let mut exports = Vec::new();
    for caps in EXPORT_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            exports.push(m.as_str().to_string());
        }
    }
    exports
}

