// ── Disalign-Bytes (Instruction-Overlap Detector) ─ Ship 5 #3 ──────
//
// Anti-disassembly detector. During x86/x64 linear-sweep
// disassembly, mark every byte address as either "instruction start"
// or "interior" (start+1 .. start+len-1). When some other decode
// path later claims an interior byte as a start (or vice versa) we
// have a single byte that belongs to two distinct instructions —
// the canonical signature of opaque-predicate jump-into-mid-
// instruction tricks used by VMProtect / Themida / Adylkuzz to
// fool linear-sweep disassemblers.
//
// Implementation:
//   1. Linear-sweep .text once to seed `byte_role`.
//   2. For each known function start AND each direct branch target
//      from the existing iced-x86 decode pass: if its address was
//      marked Interior by linear sweep, count an overlap.
//   3. Group overlaps by which function their offending bytes fall
//      inside; emit `anti_disasm: true` on those function nodes
//      AND emit one `AntiDisasmFinding` (re-using `AntiAnalysis`
//      EntityKind under the obfuscation namespace) per overlap.
//
// Algorithm is textbook clean-room (linear-sweep + role tracking;
// not copyrightable). Reference: Tim Blazytko's
// `find_instruction_overlapping` in the GPL-2.0 obfuscation_detection
// repo — *algorithm* re-used, no source copied.

use std::collections::HashMap;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use crate::types::{Graph, EntityKind};
use crate::disasm::disasm_binary;

const MAX_OVERLAPS_REPORTED: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role { Start, Interior }

pub fn disalign_bytes(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap disalign-bytes <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    // Reuse the existing disassembler to find .text bounds, bitness,
    // arch, and function starts. Returns Err for unsupported formats.
    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    if result.arch != "x86" && result.arch != "x64" {
        return format!(
            "Disalign-bytes requires x86 / x64 (iced-x86); binary is {}.",
            result.arch
        );
    }

    let (text_off, text_size) = match locate_text(&data, &result) {
        Some(v) => v,
        None => return "Could not locate .text section bytes.".to_string(),
    };
    let text_va = result.text_start_va;
    let end = (text_off + text_size).min(data.len());
    if text_off >= end { return "Empty .text section.".to_string(); }
    let text_bytes = &data[text_off..end];

    // Step 1: linear sweep across .text. Linear-sweep is the baseline
    // assumption a naïve disassembler makes; opaque-predicate junk is
    // designed to fool it. Roles seeded here become the "ground truth"
    // we compare recursive-descent results against.
    let mut byte_role: HashMap<u64, Role> = HashMap::with_capacity(text_bytes.len() / 4);
    let mut decoder = Decoder::with_ip(result.bitness, text_bytes, text_va, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() { break; }
        let ip = instr.ip();
        let len = instr.len() as u64;
        byte_role.insert(ip, Role::Start);
        for i in 1..len {
            byte_role.entry(ip + i).or_insert(Role::Interior);
        }
    }

    // Step 2: for every recursive-descent target (function start or
    // direct branch target inside .text), check whether linear-sweep
    // had it marked Interior. Each disagreement = one overlap.
    let mut overlaps: Vec<Overlap> = Vec::new();
    let text_end_va = text_va + text_bytes.len() as u64;

    // 2a — function entries.
    for func in &result.functions {
        if func.address < text_va || func.address >= text_end_va { continue; }
        if let Some(Role::Interior) = byte_role.get(&func.address) {
            overlaps.push(Overlap {
                addr: func.address,
                source: OverlapSource::FunctionEntry,
                in_function: Some((func.name.clone(), func.address)),
            });
        }
    }

    // 2b — direct branch / call / jump-table targets harvested from
    // the existing decode pass + a fresh per-function recursive
    // descent that records every direct branch target. We re-decode
    // each function so we can walk all Jcc/Jmp/Call branches without
    // needing the disasm crate to expose them as a list.
    let by_addr: HashMap<u64, &str> = result.functions.iter()
        .map(|f| (f.address, f.name.as_str()))
        .collect();

    for func in &result.functions {
        if func.address < text_va || func.address >= text_end_va { continue; }
        let off_in_text = (func.address - text_va) as usize;
        if off_in_text >= text_bytes.len() { continue; }
        let func_end = (off_in_text as u64 + func.size).min(text_bytes.len() as u64) as usize;
        let func_bytes = &text_bytes[off_in_text..func_end];

        let mut dec = Decoder::with_ip(result.bitness, func_bytes, func.address, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut ins);
            if ins.is_invalid() { break; }
            // Direct branches / calls only — the indirect ones don't
            // tell us a static address.
            if matches!(
                ins.mnemonic(),
                Mnemonic::Jmp | Mnemonic::Call
                | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jl | Mnemonic::Jle
                | Mnemonic::Jg | Mnemonic::Jge | Mnemonic::Ja | Mnemonic::Jae
                | Mnemonic::Jb | Mnemonic::Jbe | Mnemonic::Js | Mnemonic::Jns
                | Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jo | Mnemonic::Jno
                | Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
                | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz
            ) && ins.op_count() == 1 && matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                let target = ins.near_branch_target();
                if target >= text_va && target < text_end_va {
                    if let Some(Role::Interior) = byte_role.get(&target) {
                        let host = host_function(target, &result.functions, &by_addr);
                        overlaps.push(Overlap {
                            addr: target,
                            source: OverlapSource::BranchTarget,
                            in_function: host,
                        });
                    }
                }
            }
        }

        // Also include the resolved indirect-jump targets the disasm
        // already recovered (jump tables). These are recursive-descent
        // by construction — linear-sweep generally won't have them
        // aligned with switch-case bodies in obfuscated binaries.
        for &target in &func.jump_targets {
            if target >= text_va && target < text_end_va {
                if let Some(Role::Interior) = byte_role.get(&target) {
                    let host = host_function(target, &result.functions, &by_addr);
                    overlaps.push(Overlap {
                        addr: target,
                        source: OverlapSource::JumpTable,
                        in_function: host,
                    });
                }
            }
        }
    }

    overlaps.sort_by_key(|o| o.addr);
    overlaps.dedup_by_key(|o| o.addr);

    // Group overlaps per function for the graph annotation.
    let mut by_func: HashMap<u64, (String, usize)> = HashMap::new();
    for o in &overlaps {
        if let Some((name, fn_addr)) = &o.in_function {
            let entry = by_func.entry(*fn_addr).or_insert_with(|| (name.clone(), 0));
            entry.1 += 1;
        }
    }

    register_into_graph(graph, target, &result, &by_func, &overlaps);
    format_report(target, &result, &overlaps, &by_func)
}

#[derive(Debug, Clone, Copy)]
enum OverlapSource { FunctionEntry, BranchTarget, JumpTable }

#[derive(Debug, Clone)]
struct Overlap {
    addr: u64,
    source: OverlapSource,
    in_function: Option<(String, u64)>,
}

fn host_function(
    addr: u64,
    funcs: &[crate::disasm::DisasmFunction],
    _by_addr: &HashMap<u64, &str>,
) -> Option<(String, u64)> {
    // O(N) scan — fine; N rarely > 50K and this only runs once per overlap.
    for f in funcs {
        if addr >= f.address && addr < f.address + f.size {
            return Some((f.name.clone(), f.address));
        }
    }
    None
}

/// Find file offset + length of `.text` for either PE or ELF. Mach-O
/// hits the early `arch != x86/x64` guard in v1.
fn locate_text(data: &[u8], r: &crate::disasm::DisasmResult) -> Option<(usize, usize)> {
    match r.format {
        "pe" => locate_text_pe(data),
        "elf" => locate_text_elf(data),
        _ => None,
    }
}

fn locate_text_pe(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() { break; }
        let name = &data[off..off + 8];
        if name.starts_with(b".text") {
            let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as usize;
            let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
            return Some((raw_off, raw_size));
        }
    }
    None
}

fn locate_text_elf(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 64 || &data[..4] != b"\x7FELF" { return None; }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let r32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if little_endian { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let r64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if little_endian { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let r16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if little_endian { u16::from_le_bytes([data[off], data[off+1]]) }
        else { u16::from_be_bytes([data[off], data[off+1]]) }
    };

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        (r64(0x28) as usize, r16(0x3a) as usize, r16(0x3c) as usize, r16(0x3e) as usize)
    } else {
        (r32(0x20) as usize, r16(0x2e) as usize, r16(0x30) as usize, r16(0x32) as usize)
    };
    if e_shoff == 0 || e_shentsize == 0 { return None; }

    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = if is_64 { r64(shstr_hdr + 0x18) as usize } else { r32(shstr_hdr + 0x10) as usize };

    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
        let name_idx = r32(hdr) as usize;
        let (offset, size) = if is_64 {
            (r64(hdr + 0x18), r64(hdr + 0x20))
        } else {
            (r32(hdr + 0x10) as u64, r32(hdr + 0x14) as u64)
        };
        let mut name = String::new();
        if shstrtab_off + name_idx < data.len() {
            let mut end = shstrtab_off + name_idx;
            while end < data.len() && data[end] != 0 { end += 1; }
            name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
        }
        if name == ".text" {
            return Some((offset as usize, size as usize));
        }
    }
    None
}

fn register_into_graph(
    graph: &mut Graph,
    target: &str,
    r: &crate::disasm::DisasmResult,
    by_func: &HashMap<u64, (String, usize)>,
    overlaps: &[Overlap],
) {
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
    graph.ensure_typed_node(&bin_id, bin_kind, &[("path", target)]);

    if !overlaps.is_empty() {
        let count = overlaps.len().to_string();
        if let Some(node) = graph.nodes.get_mut(&bin_id) {
            node.attrs.insert("anti_disasm".into(), "true".into());
            node.attrs.insert("instruction_overlaps".into(), count);
        }
    }

    // Tag each affected function with `anti_disasm: true`.
    for (&fn_addr, (_name, count)) in by_func.iter() {
        let func_id = format!("bin_func:{target}::{:#x}", fn_addr);
        if let Some(node) = graph.nodes.get_mut(&func_id) {
            node.attrs.insert("anti_disasm".into(), "true".into());
            node.attrs.insert("overlap_count".into(), count.to_string());
        }
    }

    // Emit one AntiAnalysis finding per overlap (capped). These show
    // up under the obfuscation namespace alongside opaque-pred etc.
    for o in overlaps.iter().take(MAX_OVERLAPS_REPORTED) {
        let node_id = format!("anti_tech:obfuscation/instruction-overlap::{}::{:#x}", target, o.addr);
        let addr_str = format!("{:#x}", o.addr);
        let source_str = match o.source {
            OverlapSource::FunctionEntry => "function-entry",
            OverlapSource::BranchTarget => "branch-target",
            OverlapSource::JumpTable => "jump-table",
        };
        let (fn_name, fn_addr_str) = match &o.in_function {
            Some((n, a)) => (n.clone(), format!("{:#x}", a)),
            None => (String::new(), String::new()),
        };
        let mut attrs: Vec<(&str, &str)> = vec![
            ("name", "instruction overlap (linear-sweep vs recursive-descent disagreement)"),
            ("namespace", "anti-analysis/obfuscation/instruction-overlap"),
            ("category", "obfuscation"),
            ("confidence", "high"),
            ("address", addr_str.as_str()),
            ("source_path", source_str),
            ("reference", "Tim Blazytko obfuscation_detection — clean-room linear-sweep overlap"),
        ];
        if !fn_name.is_empty() {
            attrs.push(("function_name", fn_name.as_str()));
            attrs.push(("function_address", fn_addr_str.as_str()));
        }
        graph.ensure_typed_node(&node_id, EntityKind::AntiAnalysis, &attrs);
        graph.add_edge(&bin_id, &node_id);
    }
}

fn format_report(
    target: &str,
    r: &crate::disasm::DisasmResult,
    overlaps: &[Overlap],
    by_func: &HashMap<u64, (String, usize)>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Disalign-Bytes (Instruction-Overlap): {target} ===\n\n"));
    out.push_str(&format!("Format:        {}-{}-bit\n", r.format, r.bitness));
    out.push_str(&format!(".text @ {:#x}, {} bytes\n", r.text_start_va, r.text_size));
    out.push_str(&format!("Functions:     {}\n", r.functions.len()));
    out.push_str(&format!("Total overlaps: {}\n", overlaps.len()));
    out.push_str(&format!("Functions w/ overlaps: {}\n\n", by_func.len()));

    if overlaps.is_empty() {
        out.push_str("No instruction-overlap anomalies detected.\n");
        out.push_str("(Linear-sweep and recursive-descent decodings agree on every byte.)\n");
        return out;
    }

    let mut funcs: Vec<(&u64, &(String, usize))> = by_func.iter().collect();
    funcs.sort_by(|a, b| b.1.1.cmp(&a.1.1));
    out.push_str("── Top functions by overlap count ──\n");
    let n_show = 30.min(funcs.len());
    for (i, (addr, (name, n))) in funcs.iter().take(n_show).enumerate() {
        let display = crate::demangle::demangle(name).unwrap_or_else(|| name.clone());
        out.push_str(&format!(
            "  {:>2}. {:#012x}  overlaps={:>3}  {}\n",
            i + 1, addr, n, truncate(&display, 60),
        ));
    }
    if funcs.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", funcs.len() - n_show));
    }
    out.push('\n');

    out.push_str("── Sample overlap addresses ──\n");
    for o in overlaps.iter().take(20) {
        let src = match o.source {
            OverlapSource::FunctionEntry => "function-entry",
            OverlapSource::BranchTarget => "branch-target",
            OverlapSource::JumpTable => "jump-table",
        };
        out.push_str(&format!("  {:#012x}  source={}\n", o.addr, src));
    }
    if overlaps.len() > 20 {
        out.push_str(&format!("  ... and {} more (capped report; full set in graph)\n", overlaps.len() - 20));
    }
    out.push('\n');
    out.push_str("Try: codemap meta-path \"pe->anti_tech\"  (cross-binary anti-disasm inventory)\n");
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

    /// Linear-sweep an instruction stream and seed a `byte_role` map
    /// the same way the action does. Mirrors the inner loop so we
    /// can unit-test the role-tracking primitive.
    fn linear_sweep_roles(bytes: &[u8], bitness: u32, ip: u64) -> HashMap<u64, Role> {
        let mut roles: HashMap<u64, Role> = HashMap::new();
        let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() { break; }
            let a = instr.ip();
            let l = instr.len() as u64;
            roles.insert(a, Role::Start);
            for i in 1..l {
                roles.entry(a + i).or_insert(Role::Interior);
            }
        }
        roles
    }

    #[test]
    fn aligned_stream_has_no_overlap() {
        // Three 1-byte NOPs (0x90). Every byte is its own instruction
        // start; no interior bytes exist, so there's no possibility of
        // overlap from any direction.
        let bytes = [0x90, 0x90, 0x90];
        let roles = linear_sweep_roles(&bytes, 64, 0x1000);
        assert_eq!(roles.get(&0x1000), Some(&Role::Start));
        assert_eq!(roles.get(&0x1001), Some(&Role::Start));
        assert_eq!(roles.get(&0x1002), Some(&Role::Start));
        // Hypothetical "branch into byte 0x1001" — Role::Start, NOT
        // Interior → no overlap recorded.
        let target = 0x1001u64;
        assert_ne!(roles.get(&target), Some(&Role::Interior));
    }

    #[test]
    fn overlapping_jump_target_is_detected() {
        // Build a stream where linear sweep treats byte X as interior,
        // then a recursive-descent path treats X as a start. Use a
        // multi-byte instruction first so subsequent bytes become
        // interiors. `mov rax, 1234` (48 c7 c0 d2 04 00 00 = 7 bytes)
        // followed by NOPs.
        let bytes = [0x48, 0xc7, 0xc0, 0xd2, 0x04, 0x00, 0x00, 0x90, 0x90];
        let roles = linear_sweep_roles(&bytes, 64, 0x1000);
        // Linear sweep: 0x1000 = Start (the `mov`), 0x1001..0x1006 = Interior,
        // 0x1007 = Start (NOP), 0x1008 = Start (NOP).
        assert_eq!(roles.get(&0x1000), Some(&Role::Start));
        assert_eq!(roles.get(&0x1003), Some(&Role::Interior));
        assert_eq!(roles.get(&0x1007), Some(&Role::Start));

        // Simulate "recursive-descent claims 0x1003 is a start" — that's
        // the overlap signal the action records.
        let target = 0x1003u64;
        assert_eq!(roles.get(&target), Some(&Role::Interior),
            "interior byte must be Interior so recursive-descent disagreement is detectable");

        let benign_target = 0x1007u64;
        assert_eq!(roles.get(&benign_target), Some(&Role::Start),
            "aligned target must be Start so it is NOT flagged as overlap");
    }

    #[test]
    fn empty_input_yields_no_roles() {
        let roles = linear_sweep_roles(&[], 64, 0x1000);
        assert!(roles.is_empty());
    }

    #[test]
    fn usage_message_on_empty_target() {
        let mut graph = crate::types::Graph {
            nodes: std::collections::HashMap::new(),
            scan_dir: String::new(),
            cpg: None,
        };
        let report = disalign_bytes(&mut graph, "");
        assert!(report.contains("Usage:"));
    }
}
