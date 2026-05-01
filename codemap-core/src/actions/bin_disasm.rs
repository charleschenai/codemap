use crate::types::{Graph, EntityKind};
use crate::disasm::{disasm_binary, DisasmResult};

// ── bin-disasm action ───────────────────────────────────────────────
//
// Invokes the disasm engine, registers a BinaryFunction node per
// detected function, and adds binary→bin_func + bin_func→bin_func
// (intra-binary call) edges.
//
// Heavy operation: never runs during the default scan. Only fires
// on explicit `codemap bin-disasm <file>` (or via composites that
// chain it). Caching of disasm results across CLI runs is handled
// by the existing typed-node-persistence pipeline — once registered,
// BinaryFunction nodes survive in the bincode cache.

pub fn bin_disasm(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap bin-disasm <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    register_into_graph(graph, target, &result);
    format_report(target, &result)
}

fn register_into_graph(graph: &mut Graph, target: &str, r: &DisasmResult) {
    let bin_id = match r.format {
        "elf" => format!("elf:{target}"),
        "pe"  => format!("pe:{target}"),
        _     => format!("bin:{target}"),
    };
    let bin_kind = match r.format {
        "elf" => EntityKind::ElfBinary,
        "pe"  => EntityKind::PeBinary,
        _     => EntityKind::PeBinary,
    };
    let bitness = r.bitness.to_string();
    let entry = format!("{:#x}", r.entry_va);
    graph.ensure_typed_node(&bin_id, bin_kind, &[
        ("path", target),
        ("bitness", &bitness),
        ("arch", r.arch),
        ("entry_va", &entry),
        ("disasm_functions", &r.functions.len().to_string()),
    ]);

    // Build address → name map first so we can resolve internal calls
    use std::collections::HashMap;
    let by_addr: HashMap<u64, &str> = r.functions.iter()
        .map(|f| (f.address, f.name.as_str()))
        .collect();

    for func in &r.functions {
        let display = crate::demangle::demangle(&func.name).unwrap_or_else(|| func.name.clone());
        let func_id = format!("bin_func:{target}::{:#x}", func.address);
        let addr = format!("{:#x}", func.address);
        let size = func.size.to_string();
        let icnt = func.instruction_count.to_string();
        let icalls = func.indirect_calls.to_string();
        let jt_count = func.jump_targets.len().to_string();
        let mut attrs: Vec<(&str, &str)> = vec![
            ("name", display.as_str()),
            ("address", &addr),
            ("size", &size),
            ("instruction_count", &icnt),
            ("indirect_calls", &icalls),
            ("binary_format", r.arch),
        ];
        // Annotate functions whose switch tables we recovered. Useful
        // for `pagerank --type bin_func`-style queries — high jump-target
        // counts mark real switch-heavy code (parsers, dispatchers).
        if !func.jump_targets.is_empty() {
            attrs.push(("jump_targets", &jt_count));
        }
        if func.is_entry { attrs.push(("is_entry", "true")); }
        // Always include the raw mangled name as fallback if demangling changed it
        if display != func.name {
            attrs.push(("mangled", &func.name));
        }
        graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &attrs);
        graph.add_edge(&bin_id, &func_id);

        // Intra-binary call edges (resolved via address map)
        for callee_addr in &func.calls {
            if by_addr.contains_key(callee_addr) {
                let callee_id = format!("bin_func:{target}::{:#x}", callee_addr);
                graph.add_edge(&func_id, &callee_id);
            }
        }

        // Jump-table edges (Ship 1 #7). For each resolved switch-table
        // target, if it lands at another function's entry point we
        // emit an edge — this catches tail-call style switch dispatchers
        // (e.g. interpreter big-switch handlers each implemented as a
        // standalone function). Targets that fall into the middle of
        // the same function are intra-function basic-block jumps and
        // don't get edges (we don't have BB nodes in v1).
        for jt in &func.jump_targets {
            if by_addr.contains_key(jt) && *jt != func.address {
                let target_id = format!("bin_func:{target}::{:#x}", jt);
                graph.add_edge(&func_id, &target_id);
            }
        }
    }
}

fn format_report(target: &str, r: &DisasmResult) -> String {
    let mut lines = vec![
        format!("=== Binary Disassembly: {} ===", target),
        format!("Format:        {}", r.format),
        format!("Bitness:       {}-bit", r.bitness),
        format!("Image base:    {:#x}", r.image_base),
        format!("Entry point:   {:#x}", r.entry_va),
        format!(".text @ {:#x}, {} bytes", r.text_start_va, r.text_size),
        format!("Boundary src:  {}", if r.from_symbols { "symbol table" } else { "linear (entry only — stripped)" }),
        format!("Functions:     {}", r.functions.len()),
        String::new(),
    ];

    // Top by size
    let mut by_size: Vec<&_> = r.functions.iter().collect();
    by_size.sort_by_key(|f| std::cmp::Reverse(f.size));
    let n_show = 25.min(by_size.len());
    if n_show > 0 {
        lines.push(format!("── Top {n_show} functions by size ──"));
        for f in by_size.iter().take(n_show) {
            let demangled = crate::demangle::demangle(&f.name).unwrap_or_else(|| f.name.clone());
            let entry_marker = if f.is_entry { " (ENTRY)" } else { "" };
            let jt_marker = if f.jump_targets.is_empty() {
                String::new()
            } else {
                format!("  jt={}", f.jump_targets.len())
            };
            lines.push(format!(
                "  {:#012x}  size={:>6}  insns={:>5}  calls={:>3}+{:<3} ind{}  {}{}",
                f.address, f.size, f.instruction_count,
                f.calls.len(), f.indirect_calls,
                jt_marker,
                truncate(&demangled, 60),
                entry_marker,
            ));
        }
        if by_size.len() > n_show {
            lines.push(format!("  ... and {} more", by_size.len() - n_show));
        }
    }

    // Internal call graph stats
    let total_calls: usize = r.functions.iter().map(|f| f.calls.len()).sum();
    let total_indirect: usize = r.functions.iter().map(|f| f.indirect_calls).sum();
    let total_jt: usize = r.functions.iter().map(|f| f.jump_targets.len()).sum();
    let funcs_with_jt: usize = r.functions.iter().filter(|f| !f.jump_targets.is_empty()).count();
    let entries_found = r.functions.iter().filter(|f| f.is_entry).count();
    lines.push(String::new());
    lines.push(format!("Internal direct calls:    {total_calls}"));
    lines.push(format!("Indirect/imported calls:  {total_indirect}"));
    lines.push(format!("Jump-table targets:       {total_jt} resolved across {funcs_with_jt} functions"));
    lines.push(format!("Entry point matched in functions: {}", if entries_found > 0 { "yes" } else { "no" }));
    lines.push(String::new());
    lines.push("Try: codemap pagerank --type bin_func  (rank functions inside the binary)".to_string());
    lines.push("     codemap fiedler                    (find natural function-level partitions)".to_string());

    lines.join("\n")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let cut: String = s.chars().take(max - 1).collect();
    format!("{cut}…")
}
