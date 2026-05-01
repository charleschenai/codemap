// ── CFF (Control-Flow Flattening) Detector — Ship 3 #5 ─────────────
//
// Heuristic v1 — surfaces functions whose control flow looks
// flattened by inspecting back-edge convergence + jump-table presence.
// A real CFF detector would compute the dominator tree of each
// function's basic-block CFG and apply Tim Blazytko's
// `calc_flattening_score` (max ratio of dominated-block-set-size to
// total-block-count gated by a back-edge from inside the dominated
// set). v1 ships a cheaper proxy that uses the data
// `decode_functions` already collects:
//
//   - `back_edge_count` (Ship 3 #9b prerequisite)
//   - `cff_dispatcher_va` + `cff_dispatcher_hits` (5.35.0 — the
//     back-edge target that captures the most edges)
//   - `cff_score` = dispatcher_hits / back_edge_count
//   - `jump_targets` (Ship 1 #7 — switch dispatch is the giveaway)
//
// Heuristic: a function is flagged "likely flattened" if
//   cff_score ≥ 0.6 (≥ 60% of back-edges converge on one target)
//   AND back_edge_count ≥ 3 (real loops, not single-iteration)
//   AND jump_targets.len() ≥ 4 (real switch dispatch, not function pointer)
//
// Honest limitations:
//   - No false-negative free for hand-rolled CFF without switch tables.
//   - Functions that legitimately use a state-machine dispatcher
//     (e.g., parser DFA, network protocol state) will look flattened.
//     Confidence levels capture this nuance.
//   - Real CFF detector (port of Blazytko's algorithm) requires the
//     basic-block CFG + dom tree work — that's the v2 plan.

use crate::types::{Graph, EntityKind};
use crate::disasm::{disasm_binary, DisasmFunction};

pub fn cff_detect(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap cff-detect <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    let mut hits: Vec<(&DisasmFunction, &'static str)> = Vec::new();
    for f in &result.functions {
        if let Some(conf) = classify(f) {
            hits.push((f, conf));
        }
    }
    // Sort by score descending
    hits.sort_by(|a, b| b.0.cff_score.partial_cmp(&a.0.cff_score).unwrap_or(std::cmp::Ordering::Equal));

    register_into_graph(graph, target, &hits);
    format_report(target, &result.functions, &hits)
}

/// Confidence-level classification. Returns Some(label) if the
/// function passes any tier, None if it doesn't qualify.
fn classify(f: &DisasmFunction) -> Option<&'static str> {
    let score = f.cff_score;
    let be = f.back_edge_count;
    let jt = f.jump_targets.len();

    // High: strong dispatcher convergence + real switch dispatch + many loops
    if score >= 0.8 && be >= 5 && jt >= 8 {
        return Some("high");
    }
    // Medium: clear dispatcher + at least one switch-style branch
    if score >= 0.6 && be >= 3 && jt >= 4 {
        return Some("medium");
    }
    // Low: dispatcher signal exists but no switch backing
    if score >= 0.6 && be >= 5 && jt == 0 {
        return Some("low");
    }
    None
}

fn register_into_graph(graph: &mut Graph, target: &str, hits: &[(&DisasmFunction, &str)]) {
    if hits.is_empty() { return; }

    const MAX_NODES: usize = 1_000;
    for (h, conf) in hits.iter().take(MAX_NODES) {
        // Re-use the SwitchTable EntityKind family with a `pattern=cff_dispatcher`
        // tag — saves another EntityKind for what's essentially "this dispatcher
        // is suspicious." Will revisit if this gets crowded.
        let node_id = format!("switch_table:{target}::cff::{:#x}", h.address);
        let func_id = format!("bin_func:{target}::{:#x}", h.address);
        let func_addr = format!("{:#x}", h.address);
        let dispatcher = h.cff_dispatcher_va.map(|v| format!("{v:#x}")).unwrap_or_default();
        let score = format!("{:.3}", h.cff_score);
        let be = h.back_edge_count.to_string();
        let dh = h.cff_dispatcher_hits.to_string();
        let jt = h.jump_targets.len().to_string();
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());

        graph.ensure_typed_node(&node_id, EntityKind::SwitchTable, &[
            ("function_address", &func_addr),
            ("function_name", display.as_str()),
            ("pattern", "cff_dispatcher"),
            ("cff_score", &score),
            ("dispatcher_va", &dispatcher),
            ("dispatcher_hits", &dh),
            ("back_edges", &be),
            ("case_count", &jt),
            ("confidence", conf),
        ]);
        graph.add_edge(&func_id, &node_id);
    }
}

fn format_report(
    target: &str,
    all: &[DisasmFunction],
    hits: &[(&DisasmFunction, &str)],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Control-Flow Flattening Detection: {} ===\n\n", target));

    let total = all.len();
    let funcs_with_loops = all.iter().filter(|f| f.back_edge_count > 0).count();
    let funcs_with_switch = all.iter().filter(|f| !f.jump_targets.is_empty()).count();

    out.push_str(&format!("Functions disasmed:    {}\n", total));
    out.push_str(&format!("Functions w/ loops:    {}\n", funcs_with_loops));
    out.push_str(&format!("Functions w/ switch:   {}\n", funcs_with_switch));
    out.push_str(&format!("Functions flagged:     {}\n", hits.len()));
    out.push('\n');

    if hits.is_empty() {
        out.push_str("No flattened functions detected.\n");
        out.push_str("(Heuristic v1: requires both back-edge convergence ≥ 0.6 AND\n");
        out.push_str(" switch-dispatch evidence ≥ 4 case targets. ARM/AArch64 disasm\n");
        out.push_str(" path doesn't capture back-edges yet.)\n");
        return out;
    }

    let high = hits.iter().filter(|(_, c)| *c == "high").count();
    let medium = hits.iter().filter(|(_, c)| *c == "medium").count();
    let low = hits.iter().filter(|(_, c)| *c == "low").count();
    out.push_str(&format!("Confidence: high={high} medium={medium} low={low}\n\n"));

    out.push_str("── Top CFF candidates (by score) ──\n");
    let n_show = 30.min(hits.len());
    for (i, (h, conf)) in hits.iter().take(n_show).enumerate() {
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());
        let dispatcher = h.cff_dispatcher_va
            .map(|v| format!("{v:#012x}"))
            .unwrap_or_else(|| "(none)".to_string());
        out.push_str(&format!(
            "  {:>2}. [{:<6}] {:#012x}  score={:.2}  be={:>3}  disp@{}  jt={:>3}  {}\n",
            i + 1, conf,
            h.address, h.cff_score, h.back_edge_count, dispatcher,
            h.jump_targets.len(),
            truncate(&display, 50),
        ));
    }
    if hits.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", hits.len() - n_show));
    }
    out.push('\n');
    out.push_str("Try: codemap callers <function-name>           (callers of the dispatcher)\n");
    out.push_str("     codemap pagerank --type switch_table       (heaviest dispatchers)\n");
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let cut: String = s.chars().take(max - 1).collect();
    format!("{cut}…")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(name: &str, score: f64, be: usize, jt: usize) -> DisasmFunction {
        DisasmFunction {
            name: name.into(),
            address: 0x1000,
            size: 100,
            instruction_count: 25,
            calls: vec![],
            indirect_calls: 0,
            jump_targets: vec![0; jt],
            crypto_xor_in_loop: 0,
            back_edge_count: be,
            cff_dispatcher_va: Some(0x1100),
            cff_dispatcher_hits: (be as f64 * score).round() as usize,
            cff_score: score,
            opaque_pred_count: 0,
            is_entry: false,
        }
    }

    #[test]
    fn high_confidence_for_strong_dispatcher_with_switch() {
        let f = mk("flattened_func", 0.85, 12, 16);
        assert_eq!(classify(&f), Some("high"));
    }

    #[test]
    fn medium_confidence_for_moderate_signals() {
        let f = mk("dispatcher_func", 0.65, 4, 5);
        assert_eq!(classify(&f), Some("medium"));
    }

    #[test]
    fn low_confidence_for_dispatcher_without_switch() {
        let f = mk("loopy_func", 0.7, 8, 0);
        assert_eq!(classify(&f), Some("low"));
    }

    #[test]
    fn does_not_flag_simple_loops() {
        // Single back-edge, no switch — typical for-loop. Should NOT flag.
        let f = mk("for_loop", 1.0, 1, 0);
        assert_eq!(classify(&f), None);
    }

    #[test]
    fn does_not_flag_switch_without_back_edges() {
        // Switch statement but no looping back to a dispatcher.
        // Standard `switch(x) { case 1: ... break; }` falls through after each case.
        let f = mk("plain_switch", 0.0, 0, 8);
        assert_eq!(classify(&f), None);
    }

    #[test]
    fn empty_hits_yields_none_report() {
        let funcs = vec![mk("benign", 0.0, 0, 0)];
        let report = format_report("/tmp/test.bin", &funcs, &[]);
        assert!(report.contains("No flattened functions detected"));
    }
}
