pub mod analysis;
pub mod navigation;
pub mod graph_theory;
pub mod functions;
pub mod dataflow;
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
        // Function-Level (8)
        "call-graph" => Ok(functions::call_graph(graph, target)),
        "dead-functions" => Ok(functions::dead_functions(graph)),
        "fn-info" => Ok(functions::fn_info(graph, target)),
        "diff-functions" => Ok(functions::diff_functions(graph, target)),
        "complexity" => Ok(functions::complexity(graph, target)),
        "import-cost" => Ok(functions::import_cost(graph, target)),
        "churn" => Ok(functions::churn(graph, target)),
        "api-diff" => Ok(functions::api_diff(graph, target)),
        // Data Flow (5)
        "data-flow" => Ok(dataflow::data_flow(graph, target, tree_mode)),
        "taint" => Ok(dataflow::taint(graph, target, tree_mode)),
        "slice" => Ok(dataflow::slice(graph, target, tree_mode)),
        "trace-value" => Ok(dataflow::trace_value(graph, target, tree_mode)),
        "sinks" => Ok(dataflow::sinks(graph, target)),
        // Comparison (1)
        "compare" => Ok(compare::compare(graph, target)),
        _ => Err(CodemapError::UnknownAction(action.to_string())),
    }
}
