pub mod analysis;
pub mod navigation;
pub mod graph_theory;
pub mod functions;
pub mod dataflow;
pub mod compare;

use crate::types::Graph;
use crate::CodemapError;

pub fn dispatch(graph: &mut Graph, action: &str, target: &str, tree_mode: bool) -> Result<String, CodemapError> {
    let _ = tree_mode; // used by data-flow actions
    match action {
        "stats" => Ok(analysis::stats(graph)),
        _ => Err(CodemapError::UnknownAction(action.to_string())),
    }
}
