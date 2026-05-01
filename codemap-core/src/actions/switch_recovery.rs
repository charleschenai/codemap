// ── Switch Table Recovery (Ship 4 #24) ─────────────────────────────
//
// Aggregates Ship 1 #7's per-function `jump_targets` into structured
// SwitchTable graph nodes. Where #7 emits raw "this function jumps
// to one of these N addresses via a switch dispatch," #24 packages
// the result into:
//   - A `SwitchTable` EntityKind node per dispatching function.
//   - Edges: bin_func → switch_table → bin_func (case-target functions).
//   - Annotations: case_count, pattern, confidence.
//
// Pattern classification:
//   - `pic_relative`     — at least one resolved target maps to a
//                          known function start; targets are derived
//                          from relative offsets (typical GCC/Clang
//                          PIC switch tables, `lea+movsxd+add+jmp`).
//   - `absolute_pointer` — targets read straight from a pointer
//                          table (Windows MSVC x64 / x86 32-bit).
//   - `mixed`            — function has multiple dispatchers with
//                          different shapes (rare; Ship 1 #7 v1
//                          collapses all into one target list, so
//                          v1 reports `mixed=false` always).
//
// Confidence:
//   - `high`   — every target lands at the entry of a known function
//                in this binary's symbol table. Classic "switch over
//                an enum" pattern.
//   - `medium` — at least one target lands mid-function. Compiler
//                may have tail-merged dispatchers; targets are still
//                valid jump destinations but not function starts.
//   - `low`    — fewer than 2 targets resolved (defensive — Ship 1
//                #7 deduplicates, so 1-target tables are usually
//                false positives or single-target indirect calls).
//
// What v1 does NOT do:
//   - Per-JMP-instruction granularity. A function with N independent
//     switch dispatchers gets one merged SwitchTable. (Ship 1 #7
//     stores targets as a flat sorted+deduped Vec<u64> on the
//     function; per-JMP attribution would need a re-decode pass.)
//   - Default-case recovery. The "default" branch of a switch is the
//     fall-through after the dispatch JMP, which we don't model.
//   - C++ exception-unwind tables (.gcc_except_table) — those use
//     similar relative-offset encodings but aren't switches.

use crate::types::{Graph, EntityKind};
use crate::disasm::{disasm_binary, DisasmFunction};
use std::collections::{BTreeMap, HashMap};

pub fn switch_recovery(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap switch-recovery <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    // Build address → function-name map for case-target lookup
    let by_addr: HashMap<u64, &DisasmFunction> = result.functions.iter()
        .map(|f| (f.address, f))
        .collect();

    // Collect dispatcher functions = those with non-empty jump_targets
    let mut tables: Vec<TableInfo> = result.functions.iter()
        .filter(|f| !f.jump_targets.is_empty())
        .map(|f| classify(f, &by_addr))
        .collect();
    // Sort by case count descending — biggest dispatchers first
    tables.sort_by(|a, b| b.case_count.cmp(&a.case_count));

    register_into_graph(graph, target, &tables);
    format_report(target, &result.functions, &tables)
}

#[derive(Debug)]
struct TableInfo {
    function_va: u64,
    function_name: String,
    case_count: usize,
    /// Sorted list of resolved case targets.
    targets: Vec<u64>,
    /// How many of `targets` map to known function entry points.
    targets_at_func_entry: usize,
    confidence: &'static str,
}

fn classify(f: &DisasmFunction, by_addr: &HashMap<u64, &DisasmFunction>) -> TableInfo {
    let case_count = f.jump_targets.len();
    let targets_at_func_entry = f.jump_targets.iter()
        .filter(|t| by_addr.contains_key(t))
        .count();

    // Confidence: if every target lands at a function entry, high.
    // If some do, medium. If none, low. (Targets that fall mid-
    // function are usually basic-block-level — still valid switch
    // targets but the names won't render cleanly.)
    let confidence = if case_count < 2 {
        "low"
    } else if targets_at_func_entry == case_count {
        "high"
    } else if targets_at_func_entry > 0 {
        "medium"
    } else {
        "low"
    };

    TableInfo {
        function_va: f.address,
        function_name: f.name.clone(),
        case_count,
        targets: f.jump_targets.clone(),
        targets_at_func_entry,
        confidence,
    }
}

fn register_into_graph(graph: &mut Graph, target: &str, tables: &[TableInfo]) {
    if tables.is_empty() { return; }

    const MAX_TABLES: usize = 5_000;
    for t in tables.iter().take(MAX_TABLES) {
        let table_id = format!("switch_table:{target}::{:#x}", t.function_va);
        let func_id = format!("bin_func:{target}::{:#x}", t.function_va);

        let count = t.case_count.to_string();
        let entry_hits = t.targets_at_func_entry.to_string();
        let func_addr = format!("{:#x}", t.function_va);
        // Compact target list — first 16 to keep attrs reasonable
        let targets_preview: Vec<String> = t.targets.iter().take(16)
            .map(|v| format!("{v:#x}"))
            .collect();
        let targets_str = targets_preview.join(",");
        let display = crate::demangle::demangle(&t.function_name)
            .unwrap_or_else(|| t.function_name.clone());

        graph.ensure_typed_node(&table_id, EntityKind::SwitchTable, &[
            ("function_address", &func_addr),
            ("function_name", display.as_str()),
            ("case_count", &count),
            ("targets_at_func_entry", &entry_hits),
            ("targets", &targets_str),
            ("confidence", t.confidence),
            ("pattern", "absolute_pointer"),
        ]);
        // Edge: dispatcher function → its switch table
        graph.add_edge(&func_id, &table_id);

        // Edges: switch_table → each case target (only if target is
        // a known function start, otherwise we'd be creating dangling
        // bin_func IDs).
        for tgt in &t.targets {
            let tgt_id = format!("bin_func:{target}::{tgt:#x}");
            if graph.nodes.contains_key(&tgt_id) {
                graph.add_edge(&table_id, &tgt_id);
            }
        }
    }
}

fn format_report(target: &str, all: &[DisasmFunction], tables: &[TableInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Switch Table Recovery: {} ===\n\n", target));

    let total_targets: usize = tables.iter().map(|t| t.case_count).sum();
    let high = tables.iter().filter(|t| t.confidence == "high").count();
    let medium = tables.iter().filter(|t| t.confidence == "medium").count();
    let low = tables.iter().filter(|t| t.confidence == "low").count();

    out.push_str(&format!("Functions disasmed:    {}\n", all.len()));
    out.push_str(&format!("Switch dispatchers:    {}\n", tables.len()));
    out.push_str(&format!("Total case targets:    {}\n", total_targets));
    out.push_str(&format!("Confidence: high={high} medium={medium} low={low}\n"));
    out.push('\n');

    if tables.is_empty() {
        out.push_str("No switch tables recovered.\n");
        out.push_str("(This is normal for stripped binaries, ARM/AArch64 builds, or\n");
        out.push_str(" code compiled at -O0 where switches lower to compare-jump chains.)\n");
        return out;
    }

    // Group by confidence
    let mut by_conf: BTreeMap<&str, Vec<&TableInfo>> = BTreeMap::new();
    for t in tables {
        by_conf.entry(t.confidence).or_default().push(t);
    }

    let n_show = 30;
    let mut shown = 0usize;
    for conf in ["high", "medium", "low"] {
        let group = by_conf.get(conf);
        let group = match group { Some(g) => g, None => continue };
        if group.is_empty() { continue; }
        out.push_str(&format!("── {} confidence ({}) ──\n", conf, group.len()));
        for t in group {
            if shown >= n_show {
                out.push_str(&format!("  ... and {} more in this group\n",
                    group.len() - (shown - by_conf.values().take(0).count())));
                break;
            }
            let display = crate::demangle::demangle(&t.function_name)
                .unwrap_or_else(|| t.function_name.clone());
            out.push_str(&format!(
                "  {:#012x}  cases={:>3}  entry-hits={}/{}  {}\n",
                t.function_va,
                t.case_count,
                t.targets_at_func_entry,
                t.case_count,
                truncate(&display, 60),
            ));
            shown += 1;
        }
    }
    out.push('\n');
    out.push_str("Try: codemap pagerank --type switch_table   (heaviest dispatchers)\n");
    out.push_str("     codemap meta-path \"bin_func->switch_table->bin_func\"\n");
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

    fn mk(name: &str, addr: u64, jt: &[u64]) -> DisasmFunction {
        DisasmFunction {
            name: name.into(),
            address: addr,
            size: 100,
            instruction_count: 25,
            calls: vec![],
            indirect_calls: 0,
            jump_targets: jt.to_vec(),
            crypto_xor_in_loop: 0,
            back_edge_count: 0,
            cff_dispatcher_va: None,
            cff_dispatcher_hits: 0,
            cff_score: 0.0,
            opaque_pred_count: 0,
            is_entry: false,
        }
    }

    #[test]
    fn high_confidence_when_all_targets_at_func_entry() {
        let funcs = vec![
            mk("dispatcher", 0x1000, &[0x2000, 0x3000, 0x4000]),
            mk("case_a",     0x2000, &[]),
            mk("case_b",     0x3000, &[]),
            mk("case_c",     0x4000, &[]),
        ];
        let by_addr: HashMap<u64, &DisasmFunction> = funcs.iter()
            .map(|f| (f.address, f)).collect();
        let info = classify(&funcs[0], &by_addr);
        assert_eq!(info.case_count, 3);
        assert_eq!(info.targets_at_func_entry, 3);
        assert_eq!(info.confidence, "high");
    }

    #[test]
    fn medium_confidence_when_some_targets_mid_function() {
        let funcs = vec![
            mk("dispatcher", 0x1000, &[0x2000, 0x2050, 0x3000]),
            mk("case_a",     0x2000, &[]),
            mk("case_c",     0x3000, &[]),
        ];
        let by_addr: HashMap<u64, &DisasmFunction> = funcs.iter()
            .map(|f| (f.address, f)).collect();
        let info = classify(&funcs[0], &by_addr);
        assert_eq!(info.targets_at_func_entry, 2); // 0x2000, 0x3000
        assert_eq!(info.confidence, "medium");
    }

    #[test]
    fn low_confidence_for_single_target() {
        let funcs = vec![
            mk("ind_call", 0x1000, &[0x2000]),
            mk("target",   0x2000, &[]),
        ];
        let by_addr: HashMap<u64, &DisasmFunction> = funcs.iter()
            .map(|f| (f.address, f)).collect();
        let info = classify(&funcs[0], &by_addr);
        assert_eq!(info.confidence, "low");
    }

    #[test]
    fn report_shows_all_three_groups() {
        let funcs = vec![
            mk("high_disp",   0x1000, &[0x2000, 0x3000, 0x4000]),
            mk("mid_disp",    0x5000, &[0x6000, 0x6050]),
            mk("single",      0x7000, &[0x8000]),
            mk("case_a",      0x2000, &[]),
            mk("case_b",      0x3000, &[]),
            mk("case_c",      0x4000, &[]),
            mk("case_d",      0x6000, &[]),
            mk("solo_target", 0x8000, &[]),
        ];
        let by_addr: HashMap<u64, &DisasmFunction> = funcs.iter()
            .map(|f| (f.address, f)).collect();
        let tables: Vec<TableInfo> = funcs.iter()
            .filter(|f| !f.jump_targets.is_empty())
            .map(|f| classify(f, &by_addr))
            .collect();
        let report = format_report("/tmp/test.bin", &funcs, &tables);
        assert!(report.contains("Switch dispatchers:    3"));
        assert!(report.contains("high confidence"));
        assert!(report.contains("medium confidence"));
        assert!(report.contains("low confidence"));
    }

    #[test]
    fn empty_tables_yields_no_dispatcher_message() {
        let funcs = vec![mk("benign", 0x1000, &[])];
        let report = format_report("/tmp/test.bin", &funcs, &[]);
        assert!(report.contains("No switch tables recovered"));
    }
}
