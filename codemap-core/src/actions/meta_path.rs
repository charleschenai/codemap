use crate::types::{Graph, EntityKind};
use super::centrality::parse_kinds;

// ── Meta-Path Queries ────────────────────────────────────────────────
//
// Heterogeneous-graph killer feature: traverse paths whose nodes follow a
// specific sequence of EntityKinds. The classic example from the
// recommender-systems literature is meta-paths over scholar networks
// (Author → Paper → Venue → Paper → Author = "co-publishing peers"). For
// codemap, the canonical use cases are:
//
//   meta-path source->endpoint
//     → every source file that ultimately makes an HTTP call
//   meta-path pe->dll->symbol
//     → every binary's full library/symbol fan-out
//   meta-path source->table
//     → every code file that touches a database table
//   meta-path form->endpoint
//     → every HTML form that posts to an API endpoint
//
// The traversal is depth-bounded to the kind sequence length and capped
// at 200 paths to keep dense graphs from blowing up. Output is a tabular
// view of unique paths.

const MAX_PATHS: usize = 200;

pub fn meta_path(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return concat!(
            "Usage: codemap meta-path <kind1>-><kind2>[-><kind3>...]\n",
            "\nKinds: source pe elf macho dll symbol endpoint form table field\n",
            "       proto gql oapi docker tf model asm jclass wasm\n",
            "\nExamples:\n",
            "  codemap meta-path source->endpoint           # source files that hit APIs\n",
            "  codemap meta-path pe->dll->symbol            # binary→DLL→symbol fan-out\n",
            "  codemap meta-path source->table              # code that touches schema tables\n",
            "  codemap meta-path form->endpoint             # forms posting to endpoints\n"
        ).to_string();
    }

    // Accept "->" or "," separators
    let normalized = target.replace("->", ",");
    let kinds = parse_kinds(&normalized);
    if kinds.len() < 2 {
        return format!(
            "Need at least 2 kinds separated by '->'.\nGot: {:?}\nExample: codemap meta-path source->endpoint",
            kinds.iter().map(|k| k.as_str()).collect::<Vec<_>>()
        );
    }

    let paths = graph.meta_path(&kinds, MAX_PATHS);

    let mut out = String::new();
    let kinds_str: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    out.push_str(&format!("=== Meta-Path: {} ===\n\n", kinds_str.join(" → ")));
    out.push_str(&format!("Paths: {}{}\n\n",
        paths.len(),
        if paths.len() == MAX_PATHS { format!(" (capped at {MAX_PATHS})") } else { String::new() }
    ));

    if paths.is_empty() {
        out.push_str("(no paths found — verify the kind sequence has matching nodes + edges in the graph)\n");
        return out;
    }

    // Stats: how many distinct nodes per kind position?
    let mut per_position: Vec<std::collections::BTreeSet<&str>> =
        (0..kinds.len()).map(|_| std::collections::BTreeSet::new()).collect();
    for path in &paths {
        for (i, n) in path.iter().enumerate() {
            per_position[i].insert(n.as_str());
        }
    }
    out.push_str("── Distinct nodes per position ──\n");
    for (i, kind) in kinds.iter().enumerate() {
        out.push_str(&format!("  [{}] {} : {}\n", i, kind.as_str(), per_position[i].len()));
    }
    out.push('\n');

    // Sample paths (first 30; full list at --json)
    out.push_str("── Sample paths ──\n");
    for path in paths.iter().take(30) {
        out.push_str("  ");
        for (i, node) in path.iter().enumerate() {
            if i > 0 { out.push_str(" → "); }
            out.push_str(node);
        }
        out.push('\n');
    }
    if paths.len() > 30 {
        out.push_str(&format!("  ... +{} more\n", paths.len() - 30));
    }

    out
}

// ── Type-Aware Filters ───────────────────────────────────────────────
//
// Helpers shared by graph-theory actions that accept `--type kind1,kind2`.
// The CLI surfaces this as a target argument (since codemap's flag syntax
// is fixed); actions parse it via `parse_kinds`.

/// Restrict graph view to a kind set. Returns the subset of nodes by id
/// — callers iterate through this list and look up nodes individually.
/// Used by pagerank/hubs/dot/mermaid when --type is specified.
pub fn filter_by_kinds<'a>(graph: &'a Graph, kinds: &[EntityKind]) -> Vec<&'a str> {
    if kinds.is_empty() {
        return graph.nodes.keys().map(|s| s.as_str()).collect();
    }
    graph.nodes.values()
        .filter(|n| kinds.contains(&n.kind))
        .map(|n| n.id.as_str())
        .collect()
}
