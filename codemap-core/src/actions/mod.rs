pub mod analysis;
pub mod navigation;
pub mod graph_theory;
pub mod functions;
pub mod dataflow;
pub mod bridges;
pub mod compare;
pub mod insights;
pub mod reverse;
pub mod binary;
pub mod security;
pub mod lsp;
pub mod schemas;
pub mod ml;
pub mod composite;

use crate::types::Graph;
use crate::CodemapError;

pub fn dispatch(graph: &mut Graph, action: &str, target: &str, tree_mode: bool) -> Result<String, CodemapError> {
    match action {
        // Analysis (14)
        "stats" => Ok(analysis::stats(graph)),
        "trace" => Ok(analysis::trace(graph, target)),
        "blast-radius" => Ok(analysis::blast_radius(graph, target)),
        "phone-home" => Ok(analysis::phone_home(graph)),
        "coupling" => Ok(analysis::coupling(graph, target)),
        "dead-files" => Ok(analysis::dead_files(graph)),
        "circular" => Ok(analysis::circular(graph)),
        "exports" | "functions" => Ok(analysis::list_exports(graph, target)),
        "callers" => Ok(analysis::callers(graph, target)),
        "hotspots" => Ok(analysis::hotspots(graph)),
        "size" => Ok(analysis::size(graph)),
        "layers" => Ok(analysis::layers(graph)),
        "diff" => Ok(analysis::diff(graph, target)),
        "orphan-exports" => Ok(analysis::orphan_exports(graph)),
        // Insights (5)
        "health" => Ok(analysis::health(graph)),
        "summary" => Ok(insights::summary(graph)),
        "decorators" => Ok(insights::decorators(graph, target)),
        "rename" => Ok(insights::rename(graph, target)),
        "context" => Ok(insights::context(graph, target)),
        // Navigation (5)
        "why" => Ok(navigation::why(graph, target)),
        "paths" => Ok(navigation::paths(graph, target)),
        "subgraph" => Ok(navigation::subgraph(graph, target)),
        "similar" => Ok(navigation::similar(graph, target)),
        "structure" => Ok(navigation::structure(graph, target)),
        // Graph Theory (7)
        "pagerank" => Ok(graph_theory::pagerank(graph)),
        "hubs" => Ok(graph_theory::hubs(graph)),
        "bridges" => Ok(graph_theory::bridges(graph)),
        "clusters" => Ok(graph_theory::clusters(graph)),
        "islands" => Ok(graph_theory::islands(graph)),
        "dot" => Ok(graph_theory::dot(graph, target)),
        "mermaid" => Ok(graph_theory::mermaid(graph, target)),
        // Function-Level (13)
        "call-graph" => Ok(functions::call_graph(graph, target)),
        "dead-functions" => Ok(functions::dead_functions(graph)),
        "fn-info" => Ok(functions::fn_info(graph, target)),
        "diff-functions" => Ok(functions::diff_functions(graph, target)),
        "complexity" => Ok(functions::complexity(graph, target)),
        "import-cost" => Ok(functions::import_cost(graph, target)),
        "churn" => Ok(functions::churn(graph, target)),
        "api-diff" => Ok(functions::api_diff(graph, target)),
        "clones" => Ok(functions::clones(graph, target)),
        "git-coupling" => Ok(functions::git_coupling(graph, target)),
        "risk" => Ok(functions::risk(graph, target)),
        "diff-impact" => Ok(functions::diff_impact(graph, target)),
        "entry-points" => Ok(functions::entry_points(graph, target)),
        // Data Flow (5)
        "data-flow" => Ok(dataflow::data_flow(graph, target, tree_mode)),
        "taint" => Ok(dataflow::taint(graph, target, tree_mode)),
        "slice" => Ok(dataflow::slice(graph, target, tree_mode)),
        "trace-value" => Ok(dataflow::trace_value(graph, target, tree_mode)),
        "sinks" => Ok(dataflow::sinks(graph, target)),
        // Comparison (1)
        "compare" => Ok(compare::compare(graph, target)),
        // Cross-Language (4)
        "lang-bridges" => Ok(bridges::bridges(graph, target)),
        "gpu-functions" => Ok(bridges::gpu_functions(graph)),
        "monkey-patches" => Ok(bridges::monkey_patches(graph)),
        "dispatch-map" => Ok(bridges::dispatch_map(graph)),
        // Security & Deps (4)
        "secret-scan" => Ok(security::secret_scan(graph, target)),
        "dep-tree" => Ok(security::dep_tree(graph, target)),
        "dead-deps" => Ok(security::dead_deps(graph, target)),
        "api-surface" => Ok(security::api_surface(graph, target)),
        // Reverse Engineering (11)
        "clarion-schema" => Ok(reverse::clarion_schema(graph, target)),
        "pe-strings" => Ok(reverse::pe_strings(graph, target)),
        "pe-exports" => Ok(reverse::pe_exports(graph, target)),
        "pe-imports" => Ok(reverse::pe_imports(graph, target)),
        "pe-resources" => Ok(reverse::pe_resources(graph, target)),
        "pe-debug" => Ok(reverse::pe_debug(graph, target)),
        "dbf-schema" => Ok(reverse::dbf_schema(graph, target)),
        "pe-sections" => Ok(reverse::pe_sections(graph, target)),
        "dotnet-meta" => Ok(reverse::dotnet_meta(graph, target)),
        "sql-extract" => Ok(reverse::sql_extract(graph, target)),
        "binary-diff" => Ok(reverse::binary_diff(graph, target)),
        // Binary Formats (4)
        "elf-info" => Ok(binary::elf_info(graph, target)),
        "macho-info" => Ok(binary::macho_info(graph, target)),
        "java-class" => Ok(binary::java_class(graph, target)),
        "wasm-info" => Ok(binary::wasm_info(graph, target)),
        // Web (5)
        "web-api" => Ok(reverse::web_api(graph, target)),
        "web-dom" => Ok(reverse::web_dom(graph, target)),
        "web-sitemap" => Ok(reverse::web_sitemap(graph, target)),
        "web-blueprint" => Ok(reverse::web_blueprint(graph, target)),
        "js-api-extract" => Ok(reverse::js_api_extract(graph, target)),
        // LSP (5)
        "lsp-symbols" => Ok(lsp::lsp_symbols(graph, target)),
        "lsp-references" => Ok(lsp::lsp_references(graph, target)),
        "lsp-calls" => Ok(lsp::lsp_calls(graph, target)),
        "lsp-diagnostics" => Ok(lsp::lsp_diagnostics(graph, target)),
        "lsp-types" => Ok(lsp::lsp_types(graph, target)),
        // Schemas (5)
        "proto-schema" => Ok(schemas::proto_schema(graph, target)),
        "openapi-schema" => Ok(schemas::openapi_schema(graph, target)),
        "graphql-schema" => Ok(schemas::graphql_schema(graph, target)),
        "docker-map" => Ok(schemas::docker_map(graph, target)),
        "terraform-map" => Ok(schemas::terraform_map(graph, target)),
        // ML/AI (5)
        "gguf-info" => Ok(ml::gguf_info(graph, target)),
        "safetensors-info" => Ok(ml::safetensors_info(graph, target)),
        "onnx-info" => Ok(ml::onnx_info(graph, target)),
        "pyc-info" => Ok(ml::pyc_info(graph, target)),
        "cuda-info" => Ok(ml::cuda_info(graph, target)),
        // Composite (3)
        "validate" => Ok(composite::validate(graph, target)),
        "changeset" => Ok(composite::changeset(graph, target)),
        "handoff" => Ok(composite::handoff(graph, target)),
        _ => Err(CodemapError::UnknownAction(action.to_string())),
    }
}
