use crate::types::Graph;

pub fn stats(graph: &Graph) -> String {
    format!("=== Codemap Stats ===\nFiles: {}", graph.nodes.len())
}
