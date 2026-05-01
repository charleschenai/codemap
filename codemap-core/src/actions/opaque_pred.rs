// ── Opaque-Predicate Detector — Ship 3 #6 (heuristic v1) ───────────
//
// Surfaces functions containing tautological branch conditions —
// `cmp reg, reg` (always equal) or `test reg, reg` against a register
// the propagator has tracked as zero (always-zero) — followed by a
// conditional branch within 3 instructions. Both patterns are
// signature opaque-predicate idioms inserted by obfuscators
// (Themida / VMProtect / OLLVM) to insert junk control-flow that
// looks like real branching but always evaluates one way.
//
// Detection runs as a side-effect of the existing decode pass:
// `decode_functions` already maintains a `pending_self_compare`
// counter that ticks down with each instruction; if a Jcc fires
// while pending > 0, `opaque_pred_count` increments.
//
// Honest limitations:
//   - Doesn't catch arithmetic-based opaque predicates like
//     `(x*x + x) % 2 == 0`. Real Tim Blazytko detection uses
//     irreducible-loop analysis + Weisfeiler-Lehman block
//     duplicate detection — both need basic-block CFG. Deferred to v2.
//   - Compilers occasionally emit `xor reg, reg / test reg, reg`
//     in zero-initialization paths that aren't obfuscation —
//     marked low-confidence to surface them without crying wolf.
//
// What it catches reliably:
//   - Themida / VMProtect-style `cmp reg, reg / je <bogus>`.
//   - OLLVM bogus-control-flow pass `xor reg, reg / test reg, reg /
//     jne <real_block>` (always taken because reg=0).
//   - Hand-rolled malware obfuscators using the same idioms.

use crate::types::{Graph, EntityKind};
use crate::disasm::{disasm_binary, DisasmFunction};

pub fn opaque_pred(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap opaque-pred <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    let mut hits: Vec<&DisasmFunction> = result.functions.iter()
        .filter(|f| f.opaque_pred_count > 0)
        .collect();
    hits.sort_by(|a, b| b.opaque_pred_count.cmp(&a.opaque_pred_count));

    register_into_graph(graph, target, &hits);
    format_report(target, &result.functions, &hits)
}

fn confidence_for(count: usize) -> &'static str {
    if count >= 5 { "high" }
    else if count >= 2 { "medium" }
    else { "low" }
}

fn register_into_graph(graph: &mut Graph, target: &str, hits: &[&DisasmFunction]) {
    if hits.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    const MAX_NODES: usize = 1_000;
    for h in hits.iter().take(MAX_NODES) {
        // Reuse the AntiAnalysis EntityKind under the obfuscation
        // category — opaque predicates are an obfuscation technique
        // per capa-rules taxonomy (anti-analysis/obfuscation).
        let node_id = format!("anti_tech:obfuscation/opaque-predicate::{}::{:#x}",
            target, h.address);
        let func_addr = format!("{:#x}", h.address);
        let count = h.opaque_pred_count.to_string();
        let conf = confidence_for(h.opaque_pred_count);
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());
        graph.ensure_typed_node(&node_id, EntityKind::AntiAnalysis, &[
            ("name", "opaque predicate (cmp/test self-compare → Jcc)"),
            ("namespace", "anti-analysis/obfuscation/opaque-predicate"),
            ("category", "obfuscation"),
            ("confidence", conf),
            ("function_address", func_addr.as_str()),
            ("function_name", display.as_str()),
            ("opaque_pred_count", count.as_str()),
            ("reference", "Tim Blazytko obfuscation_detection — heuristic surrogate"),
        ]);
        graph.add_edge(&bin_id, &node_id);
    }
}

fn format_report(target: &str, all: &[DisasmFunction], hits: &[&DisasmFunction]) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Opaque-Predicate Detection: {} ===\n\n", target));

    let total_op = all.iter().map(|f| f.opaque_pred_count).sum::<usize>();
    out.push_str(&format!("Functions disasmed:  {}\n", all.len()));
    out.push_str(&format!("Functions flagged:   {}\n", hits.len()));
    out.push_str(&format!("Total opaque preds:  {}\n", total_op));
    out.push('\n');

    if hits.is_empty() {
        out.push_str("No opaque-predicate patterns detected.\n");
        out.push_str("(Heuristic v1: matches cmp reg,reg / test reg,reg-after-xor\n");
        out.push_str(" patterns followed by Jcc within 3 instructions. Arithmetic-\n");
        out.push_str(" based predicates require basic-block CFG = v2.)\n");
        return out;
    }

    let high = hits.iter().filter(|f| confidence_for(f.opaque_pred_count) == "high").count();
    let medium = hits.iter().filter(|f| confidence_for(f.opaque_pred_count) == "medium").count();
    let low = hits.iter().filter(|f| confidence_for(f.opaque_pred_count) == "low").count();
    out.push_str(&format!("Confidence: high={high} medium={medium} low={low}\n\n"));

    out.push_str("── Top opaque-predicate candidates ──\n");
    let n_show = 30.min(hits.len());
    for (i, h) in hits.iter().take(n_show).enumerate() {
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());
        let conf = confidence_for(h.opaque_pred_count);
        out.push_str(&format!(
            "  {:>2}. [{:<6}] {:#012x}  preds={:>2}  insns={:>5}  {}\n",
            i + 1, conf,
            h.address, h.opaque_pred_count, h.instruction_count,
            truncate(&display, 60),
        ));
    }
    if hits.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", hits.len() - n_show));
    }
    out.push('\n');
    out.push_str("Try: codemap meta-path \"pe->anti_tech\"  (cross-binary obfuscation inventory)\n");
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

    fn mk(name: &str, addr: u64, op: usize) -> DisasmFunction {
        DisasmFunction {
            name: name.into(),
            address: addr,
            size: 100,
            instruction_count: 25,
            calls: vec![],
            indirect_calls: 0,
            jump_targets: vec![],
            crypto_xor_in_loop: 0,
            back_edge_count: 0,
            cff_dispatcher_va: None,
            cff_dispatcher_hits: 0,
            cff_score: 0.0,
            opaque_pred_count: op,
            is_entry: false,
        }
    }

    #[test]
    fn confidence_thresholds() {
        assert_eq!(confidence_for(0), "low");
        assert_eq!(confidence_for(1), "low");
        assert_eq!(confidence_for(2), "medium");
        assert_eq!(confidence_for(4), "medium");
        assert_eq!(confidence_for(5), "high");
        assert_eq!(confidence_for(50), "high");
    }

    #[test]
    fn report_groups_by_confidence() {
        let funcs = vec![
            mk("heavy_obfusc",  0x1000, 8),  // high
            mk("med_obfusc",    0x2000, 3),  // medium
            mk("light",         0x3000, 1),  // low
            mk("benign",        0x4000, 0),  // not flagged
        ];
        let hits: Vec<&DisasmFunction> = funcs.iter().filter(|f| f.opaque_pred_count > 0).collect();
        let report = format_report("/tmp/test.bin", &funcs, &hits);
        assert!(report.contains("Functions flagged:   3"));
        assert!(report.contains("[high  ]"));
        assert!(report.contains("[medium]"));
        assert!(report.contains("[low   ]"));
        assert!(report.contains("preds= 8"));
    }

    #[test]
    fn empty_hits_yields_no_detection_message() {
        let funcs = vec![mk("benign", 0x1000, 0)];
        let report = format_report("/tmp/test.bin", &funcs, &[]);
        assert!(report.contains("No opaque-predicate patterns"));
    }
}
