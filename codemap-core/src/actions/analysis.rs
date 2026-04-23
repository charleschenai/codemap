use crate::types::Graph;

pub fn stats(graph: &Graph) -> String {
    let files = graph.nodes.len();
    let total_lines: usize = graph.nodes.values().map(|n| n.lines).sum();
    let import_edges: usize = graph.nodes.values().map(|n| n.imports.len()).sum();
    let total_functions: usize = graph.nodes.values().map(|n| n.functions.len()).sum();
    let total_exports: usize = graph.nodes.values().map(|n| n.exports.len()).sum();
    let total_urls: usize = graph.nodes.values().map(|n| n.urls.len()).sum();
    let files_with_dataflow = graph.nodes.values().filter(|n| n.data_flow.is_some()).count();

    format!(
        "=== Codemap Stats ===\n\
         Files: {files}\n\
         Lines: {total_lines}\n\
         Import edges: {import_edges}\n\
         Functions: {total_functions}\n\
         Exports: {total_exports}\n\
         URLs: {total_urls}\n\
         Files with data flow: {files_with_dataflow}"
    )
}
