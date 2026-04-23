use crate::types::*;

pub fn ensure_cpg(graph: &mut Graph) -> &CodePropertyGraph {
    if graph.cpg.is_none() {
        graph.cpg = Some(build_cpg(graph));
    }
    graph.cpg.as_ref().unwrap()
}

fn build_cpg(_graph: &Graph) -> CodePropertyGraph {
    CodePropertyGraph::default()
}
