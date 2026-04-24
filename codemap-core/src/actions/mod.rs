pub mod analysis;
pub mod navigation;
pub mod graph_theory;
pub mod functions;
pub mod dataflow;
pub mod bridges;
pub mod compare;

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
        "health" => Ok(analysis::health(graph)),
        "summary" => Ok(analysis::summary(graph)),
        // Navigation (4)
        "why" => Ok(navigation::why(graph, target)),
        "paths" => Ok(navigation::paths(graph, target)),
        "subgraph" => Ok(navigation::subgraph(graph, target)),
        "similar" => Ok(navigation::similar(graph, target)),
        // Graph Theory (6)
        "pagerank" => Ok(graph_theory::pagerank(graph)),
        "hubs" => Ok(graph_theory::hubs(graph)),
        "bridges" => Ok(graph_theory::bridges(graph)),
        "clusters" => Ok(graph_theory::clusters(graph)),
        "islands" => Ok(graph_theory::islands(graph)),
        "dot" => Ok(graph_theory::dot(graph, target)),
        "mermaid" => Ok(graph_theory::mermaid(graph, target)),
        // Function-Level (8)
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
        "decorators" => Ok(analysis::decorators(graph, target)),
        "rename" => Ok(analysis::rename(graph, target)),
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
        _ => Err(CodemapError::UnknownAction(action.to_string())),
    }
}
