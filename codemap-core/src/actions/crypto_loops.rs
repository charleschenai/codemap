// ── Crypto-Loop Detector (Ship 3 #9b) ──────────────────────────────
//
// Identifies functions that contain XOR-decryption loops — a strong
// signal for malware string/payload decryption, custom symmetric
// crypto, or shellcode unpacking. Detection runs as a side-effect of
// the existing disassembly pass: each XOR instruction with a known
// constant key (immediate OR const-tracked register from the bounded
// backward propagator in disasm_jt.rs) is recorded along with all
// back-edges in the function. A function is flagged "crypto-loop" if
// any XOR-const site falls inside any back-edge range.
//
// The propagator is the second consumer (after Ship 1 #7's jump-table
// resolver) — it's now justified to extract to dataflow_local.rs as
// the original handoff plan called for. Doing that as a follow-on
// since this v1 reuses the propagator inline; refactor doesn't change
// behavior.
//
// What v1 does:
//   - Runs full bin-disasm (re-uses its work via the disasm engine).
//   - For each function, reports crypto_xor_in_loop count + ratio.
//   - Emits CryptoConstant graph nodes (re-using Ship 1 #9a's
//     EntityKind) with attrs:
//       algorithm = "XOR-loop"
//       constant_name = "key in loop body"
//       offset = function's address
//       confidence = high (≥3 XOR-const sites in loop) / medium / low
//   - Sorts functions by signal strength.
//
// What v1 does NOT do:
//   - Recover the actual XOR key. The propagator knows the value but
//     v1 only counts; v2 will surface the key bytes.
//   - Distinguish XOR-byte-stream-decrypt vs RC4-style PRGA. Both
//     show up as "XOR with const-tracked register inside a loop".
//     The crypto-const scanner already flags RC4 init via its S-box
//     fingerprint; this action complements it for custom XOR variants.
//   - ARM/AArch64. The disasm pass for those architectures uses the
//     symbol-table-only fallback and never sees XOR mnemonics.

use crate::types::{Graph, EntityKind};
use crate::disasm::{disasm_binary, DisasmFunction};

pub fn crypto_loops(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap crypto-loops <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    // Collect functions with non-zero crypto signal
    let mut hits: Vec<&DisasmFunction> = result.functions.iter()
        .filter(|f| f.crypto_xor_in_loop > 0)
        .collect();
    hits.sort_by(|a, b| b.crypto_xor_in_loop.cmp(&a.crypto_xor_in_loop));

    register_into_graph(graph, target, &hits);
    format_report(target, &result.functions, &hits)
}

fn confidence_for(count: usize) -> &'static str {
    if count >= 3 { "high" }
    else if count == 2 { "medium" }
    else { "low" }
}

fn register_into_graph(graph: &mut Graph, target: &str, hits: &[&DisasmFunction]) {
    if hits.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    const MAX_NODES: usize = 1_000;
    for h in hits.iter().take(MAX_NODES) {
        let node_id = format!("crypto:XOR-loop:{}::{:#x}", target, h.address);
        let off = format!("{:#x}", h.address);
        let count_str = h.crypto_xor_in_loop.to_string();
        let conf = confidence_for(h.crypto_xor_in_loop);
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());
        graph.ensure_typed_node(&node_id, EntityKind::CryptoConstant, &[
            ("algorithm", "XOR-loop"),
            ("constant_name", "key in loop body"),
            ("offset", &off),
            ("endian", "n/a"),
            ("confidence", conf),
            ("function_name", display.as_str()),
            ("xor_count", count_str.as_str()),
        ]);
        graph.add_edge(&bin_id, &node_id);
    }
}

fn format_report(target: &str, all: &[DisasmFunction], hits: &[&DisasmFunction]) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Crypto-Loop Detection: {} ===\n\n", target));

    let total_xor = all.iter().map(|f| f.crypto_xor_in_loop).sum::<usize>();
    let funcs_with_hits = hits.len();
    let funcs_with_loops = all.iter().filter(|f| f.back_edge_count > 0).count();
    out.push_str(&format!("Functions disasmed:  {}\n", all.len()));
    out.push_str(&format!("Functions w/ loops:  {}\n", funcs_with_loops));
    out.push_str(&format!("Functions flagged:   {}\n", funcs_with_hits));
    out.push_str(&format!("Total XOR-in-loop:   {}\n", total_xor));
    out.push('\n');

    if hits.is_empty() {
        out.push_str("No XOR-decryption loops detected.\n");
        out.push_str("(Note: x86/x64 only — ARM/AArch64 disasm path doesn't emit XOR sites.)\n");
        return out;
    }

    out.push_str("── Top crypto-loop candidates ──\n");
    let n_show = 30.min(hits.len());
    for (i, h) in hits.iter().take(n_show).enumerate() {
        let display = crate::demangle::demangle(&h.name).unwrap_or_else(|| h.name.clone());
        let conf = confidence_for(h.crypto_xor_in_loop);
        out.push_str(&format!(
            "  {:>2}. [{:<6}] {:#012x}  xor-in-loop={}  back-edges={}  {}\n",
            i + 1, conf,
            h.address, h.crypto_xor_in_loop, h.back_edge_count,
            truncate(&display, 60),
        ));
    }
    if hits.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", hits.len() - n_show));
    }
    out.push('\n');
    out.push_str("Try: codemap callers <function-name>     (find who invokes the decryptor)\n");
    out.push_str("     codemap meta-path \"pe->crypto\"      (cross-binary crypto inventory)\n");
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

    fn mk(name: &str, addr: u64, xor: usize, be: usize) -> DisasmFunction {
        DisasmFunction {
            name: name.into(),
            address: addr,
            size: 100,
            instruction_count: 25,
            calls: vec![],
            indirect_calls: 0,
            jump_targets: vec![],
            crypto_xor_in_loop: xor,
            back_edge_count: be,
            cff_dispatcher_va: None,
            cff_dispatcher_hits: 0,
            cff_score: 0.0,
            opaque_pred_count: 0,
            is_entry: false,
        }
    }

    #[test]
    fn confidence_levels() {
        assert_eq!(confidence_for(0), "low");
        assert_eq!(confidence_for(1), "low");
        assert_eq!(confidence_for(2), "medium");
        assert_eq!(confidence_for(3), "high");
        assert_eq!(confidence_for(50), "high");
    }

    #[test]
    fn report_distinguishes_hit_levels() {
        let funcs = vec![
            mk("decrypt_strings", 0x1000, 5, 2),  // high
            mk("normal_func",     0x2000, 0, 0),  // not flagged
            mk("encode_packet",   0x3000, 2, 1),  // medium
            mk("xor_byte",        0x4000, 1, 1),  // low
        ];
        let hits: Vec<&DisasmFunction> = funcs.iter().filter(|f| f.crypto_xor_in_loop > 0).collect();
        let report = format_report("/tmp/test.bin", &funcs, &hits);
        assert!(report.contains("Functions flagged:   3"));
        assert!(report.contains("xor-in-loop=5"));
        assert!(report.contains("[high  ]"));
        assert!(report.contains("[medium]"));
        assert!(report.contains("[low   ]"));
    }

    #[test]
    fn empty_hits_reports_no_detection() {
        let funcs = vec![mk("benign", 0x1000, 0, 0)];
        let hits: Vec<&DisasmFunction> = vec![];
        let report = format_report("/tmp/test.bin", &funcs, &hits);
        assert!(report.contains("No XOR-decryption loops"));
    }
}
