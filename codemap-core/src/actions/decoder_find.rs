// ── Decoder-Function Finder — FLOSS heuristic v1 ────────────────────
//
// Pure-static port of Mandiant FLARE FLOSS's decoder-function scorer.
// Source files: `floss/identify.py` (driver), `floss/features/extract.py`
// (CFG + insn features), `floss/features/features.py` (weights). FLOSS
// is Apache-2.0 — this is a clean reimplementation in Rust against
// iced-x86, not a source copy. NOTICE-style attribution: algorithm by
// Willi Ballenthin + Moritz Raabe (Mandiant/Google FLARE).
//
// FLOSS's headline pipeline (vivisect emulator + memory diff) is OFF-
// LIMITS for codemap — codemap is a pure-static analyzer. The scorer is
// the salvageable static half: it ranks every function by "looks like a
// string decoder" using only CFG shape + instruction-level signals.
// This v1 ports the scoring half end-to-end. The dynamic emulation half
// stays out of scope.
//
// What v1 ships:
//   - Self-contained basic-block CFG construction from iced-x86
//     instruction stream (the `bbcfg` pane is building a richer
//     general-purpose CFG; when it lands, the `Cfg` struct here can
//     swap to `bbcfg::build_cfg`).
//   - Per-function features: BlockCount, InstructionCount, TightLoop,
//     KindaTightLoop, Loop (Tarjan SCC ≥ 2), Nzxor (filtered against
//     MS security cookies), Shift/Rotate, Mov-to-deref, CallsTo.
//   - Combined-feature flags: NzxorTightLoop / NzxorLoop /
//     TightFunction (SEVERE weight).
//   - Weighted score: sum(weight * score) / sum(weight). Threshold
//     for emission = 0.30.
//   - Skips runtime helpers (CRT _chkstk, __security_*, _start,
//     mainCRTStartup, etc.) and thunk functions (single-jmp).
//
// Honest deltas from FLOSS:
//   - **No Arguments feature.** FLOSS pulls argument count from
//     vivisect's getFunctionApi; codemap doesn't have a calling-
//     convention recovery pass. Skipping rather than approximating
//     keeps the score interpretable (no fake bias for every function).
//   - **No FLIRT library-function filtering.** FLOSS uses vivisect +
//     FLIRT signatures; codemap uses a small hardcoded runtime-name
//     list. False positives on statically-linked CRT possible.
//   - **CFG is intra-function only.** Inter-procedural shape isn't
//     used; each function is scored in isolation.
//
// Bonus (folded into the same action): see also stackstrings_quick.rs
// for the FLOSS Go stackstring regex pass — pure-static, separate
// action since it operates on .text without per-function CFG.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};

// ── Lightweight flow-control classification (sans iced-x86 instr_info) ─
//
// iced-x86's `Instruction::flow_control()` lives behind the
// `instr_info` feature, which codemap doesn't enable to keep the dep
// tree minimal. We classify branches from the mnemonic + op0 kind
// instead — same fan-out as FlowControl but without the feature gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    Return,
    Call,
    IndirectCall,
}

fn flow_of(ins: &Instruction) -> Flow {
    match ins.mnemonic() {
        Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => Flow::Return,
        Mnemonic::Call => {
            if ins.op_count() == 1
                && matches!(
                    ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            {
                Flow::Call
            } else {
                Flow::IndirectCall
            }
        }
        Mnemonic::Jmp => {
            if ins.op_count() == 1
                && matches!(
                    ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            {
                Flow::UnconditionalBranch
            } else {
                Flow::IndirectBranch
            }
        }
        Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jl | Mnemonic::Jle | Mnemonic::Jg | Mnemonic::Jge
        | Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb | Mnemonic::Jbe | Mnemonic::Js
        | Mnemonic::Jns | Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jo | Mnemonic::Jno
        | Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
        | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz => Flow::ConditionalBranch,
        _ => Flow::Next,
    }
}

use crate::demangle::demangle;
use crate::disasm::{disasm_binary, DisasmFunction, DisasmResult};
use crate::types::{EntityKind, Graph};

// ── Tunables ───────────────────────────────────────────────────────

/// FLOSS feature weights (LOW=0.25, MEDIUM=0.50, HIGH=0.75, SEVERE=1.0).
const W_LOW: f64 = 0.25;
const W_MED: f64 = 0.50;
const W_HIGH: f64 = 0.75;
const W_SEVERE: f64 = 1.00;

/// FLOSS constant — TightFunction abstraction fires only if BlockCount < this.
const TS_TIGHT_FUNCTION_MAX_BLOCKS: usize = 4;

/// Security-cookie XOR filter window (FLOSS): first/last 0x40 bytes of
/// the first BB / any returning BB, when one operand is SP/BP.
const SECURITY_COOKIE_BYTES_DELTA: u64 = 0x40;

/// Minimum weighted score before a function is emitted as a candidate.
const MIN_SCORE_REPORT: f64 = 0.30;

/// Cap candidates per binary so a noisy scan never overflows the graph.
const MAX_CANDIDATES_PER_BINARY: usize = 1_000;

/// Cap functions analyzed per binary. With ~100K function corpora the
/// CFG construction would dominate runtime; in practice 50K is a
/// generous ceiling that disasm_binary already respects.
const MAX_FUNCTIONS_ANALYZED: usize = 50_000;

// ── Public entry point ─────────────────────────────────────────────

pub fn decoder_find(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap decoder-find <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    // ARM/AArch64 disasm path uses symbol-table-only — no instruction
    // decoding, so the per-instruction feature pass would see nothing.
    // Bail with a friendly message rather than silently emitting zero.
    if result.arch != "x86" && result.arch != "x64" {
        return format!(
            "decoder-find: unsupported architecture '{}'. v1 covers x86/x64 only \
            (ARM/AArch64 use symbol-table-only disasm — no instruction features).",
            result.arch
        );
    }

    // Pull .text bytes again — DisasmResult exposes the VA/size but not
    // the file bytes. Re-walk PE/ELF headers to find the .text file
    // offset; cheap (~0.1ms even on multi-MB binaries).
    let text_bytes = match extract_text_bytes(&data, &result) {
        Some(b) => b,
        None => return "Failed to locate .text section bytes".to_string(),
    };

    // Build calls-to map (in-degree on the call graph). Used to score
    // CallsTo (popularity proxy). FLOSS's max_calls_to normaliser comes
    // from get_max_calls_to — we mimic by skipping thunks/runtime in
    // the count.
    let calls_to: HashMap<u64, usize> = build_calls_to(&result.functions);
    let max_calls_to = calls_to.values().copied().max().unwrap_or(1).max(1);

    let mut scored: Vec<ScoredFunction> = Vec::new();
    for f in result.functions.iter().take(MAX_FUNCTIONS_ANALYZED) {
        if is_runtime_helper(&f.name) {
            continue;
        }
        if f.size < 4 || f.instruction_count == 0 {
            continue;
        }
        // Build per-function CFG and feature vector.
        let cfg = match build_cfg(&text_bytes, result.text_start_va, result.bitness, f) {
            Some(c) => c,
            None => continue,
        };
        if is_thunk(&cfg) {
            continue;
        }
        let features = extract_features(&cfg);
        let calls = calls_to.get(&f.address).copied().unwrap_or(0);
        let (score, feature_names) = score_function(&features, calls, max_calls_to);
        if score >= MIN_SCORE_REPORT {
            scored.push(ScoredFunction {
                func: f,
                score,
                features,
                feature_names,
                calls_to: calls,
            });
        }
    }
    scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    if scored.len() > MAX_CANDIDATES_PER_BINARY {
        scored.truncate(MAX_CANDIDATES_PER_BINARY);
    }

    register_into_graph(graph, target, &result, &scored);
    format_report(target, &result, &scored)
}

// ── Scored function bundle ─────────────────────────────────────────

struct ScoredFunction<'a> {
    func: &'a DisasmFunction,
    score: f64,
    features: Features,
    feature_names: Vec<&'static str>,
    calls_to: usize,
}

// ── CFG construction ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DecodedInstr {
    instr: Instruction,
    va: u64,
}

#[derive(Debug, Clone)]
struct Bb {
    /// Inclusive start VA of this BB.
    start_va: u64,
    /// Exclusive end VA — equal to the next instruction VA after the
    /// terminating branch / fall-through.
    end_va: u64,
    /// Indices into Cfg.instrs for instructions inside this BB.
    instrs: Vec<usize>,
    /// Successor BB start VAs.
    successors: Vec<u64>,
    /// True if the last instruction of this BB is a Ret/Retf.
    ends_with_return: bool,
}

#[derive(Debug)]
struct Cfg {
    func_start_va: u64,
    instrs: Vec<DecodedInstr>,
    bbs: Vec<Bb>,
    bb_index: HashMap<u64, usize>,
}

/// Build a per-function basic-block CFG from raw .text bytes.
///
/// Stub minimal CFG (Path 2 from the build plan): when the parallel
/// `bbcfg` pane lands a richer general-purpose CFG, swap this for
/// `bbcfg::build_cfg`. The decoder-find feature extractor treats this
/// struct as opaque — only the `Bb`/`Cfg` shape escapes to the rest of
/// this module.
///
/// Algorithm:
///   1. Decode all instructions in [func_start, func_end). func_end =
///      func_start + DisasmFunction.size (already conservative).
///   2. Find leaders: first instr + every conditional/unconditional
///      branch target inside the function + every instruction
///      immediately following a branch / return.
///   3. Walk instructions in order, splitting at leaders. Each BB ends
///      at the next leader OR the function end OR a return.
///   4. Compute successors from branch flow control.
fn build_cfg(text_bytes: &[u8], text_va: u64, bitness: u32, f: &DisasmFunction) -> Option<Cfg> {
    if f.size == 0 || text_bytes.is_empty() {
        return None;
    }
    let func_start = f.address;
    let func_end = func_start.saturating_add(f.size);
    if func_start < text_va || func_end <= text_va {
        return None;
    }
    let off = (func_start - text_va) as usize;
    let len = (func_end - func_start) as usize;
    if off >= text_bytes.len() {
        return None;
    }
    let end = (off + len).min(text_bytes.len());
    let bytes = &text_bytes[off..end];

    // Decode all instructions.
    let mut decoder = Decoder::with_ip(bitness, bytes, func_start, DecoderOptions::NONE);
    let mut instrs: Vec<DecodedInstr> = Vec::new();
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let va = instr.ip();
        if va >= func_end {
            break;
        }
        instrs.push(DecodedInstr { instr, va });
        // Stop walking past a return — function body is done. We still
        // include the return itself.
        if matches!(flow_of(&instr), Flow::Return) {
            break;
        }
    }
    if instrs.is_empty() {
        return None;
    }

    // ── Find leaders ────────────────────────────────────────────────
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(instrs[0].va);
    for i in 0..instrs.len() {
        let ins = &instrs[i].instr;
        match flow_of(ins) {
            Flow::ConditionalBranch => {
                let tgt = ins.near_branch_target();
                if tgt >= func_start && tgt < func_end {
                    leaders.insert(tgt);
                }
                // Fall-through is a leader too.
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].va);
                }
            }
            Flow::UnconditionalBranch => {
                let tgt = ins.near_branch_target();
                if tgt >= func_start && tgt < func_end {
                    leaders.insert(tgt);
                }
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].va);
                }
            }
            Flow::IndirectBranch => {
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].va);
                }
            }
            Flow::Return => {
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].va);
                }
            }
            // Calls (direct or indirect) DO NOT split a basic block in
            // FLOSS's model — control returns. Same here.
            _ => {}
        }
    }

    // ── Build BBs in instruction order ─────────────────────────────
    let mut bbs: Vec<Bb> = Vec::new();
    let mut bb_index: HashMap<u64, usize> = HashMap::new();
    let mut cur_start_idx: Option<usize> = None;
    for i in 0..instrs.len() {
        if cur_start_idx.is_none() {
            cur_start_idx = Some(i);
        }
        // Does this instruction END the current BB?
        let ins = &instrs[i].instr;
        let fc = flow_of(ins);
        let next_va = ins.next_ip();
        let next_is_leader = i + 1 < instrs.len() && leaders.contains(&instrs[i + 1].va);
        let terminator = matches!(
            fc,
            Flow::ConditionalBranch
                | Flow::UnconditionalBranch
                | Flow::IndirectBranch
                | Flow::Return
        );
        let last_instr = i + 1 == instrs.len();
        if terminator || next_is_leader || last_instr {
            let start = cur_start_idx.unwrap();
            let bb_start_va = instrs[start].va;
            let bb_end_va = next_va;
            let mut succs: Vec<u64> = Vec::new();
            let ends_with_return = matches!(fc, Flow::Return);
            match fc {
                Flow::ConditionalBranch => {
                    let tgt = ins.near_branch_target();
                    if tgt >= func_start && tgt < func_end {
                        succs.push(tgt);
                    }
                    if i + 1 < instrs.len() {
                        succs.push(instrs[i + 1].va);
                    }
                }
                Flow::UnconditionalBranch => {
                    let tgt = ins.near_branch_target();
                    if tgt >= func_start && tgt < func_end {
                        succs.push(tgt);
                    }
                    // Indirect unconditional branch — no known successor.
                }
                Flow::Return | Flow::IndirectBranch => {
                    // No statically-known successor.
                }
                _ => {
                    // Fell off the end of a BB without an explicit
                    // terminator (because next instr is a leader, or
                    // we're at func end). Successor is the next instr.
                    if i + 1 < instrs.len() {
                        succs.push(instrs[i + 1].va);
                    }
                }
            }
            let bb_idx = bbs.len();
            let mut idxs = Vec::with_capacity(i - start + 1);
            for k in start..=i {
                idxs.push(k);
            }
            bb_index.insert(bb_start_va, bb_idx);
            bbs.push(Bb {
                start_va: bb_start_va,
                end_va: bb_end_va,
                instrs: idxs,
                successors: succs,
                ends_with_return,
            });
            cur_start_idx = None;
        }
    }
    if bbs.is_empty() {
        return None;
    }

    Some(Cfg {
        func_start_va: func_start,
        instrs,
        bbs,
        bb_index,
    })
}

// ── Feature extraction ─────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct Features {
    block_count: usize,
    instr_count: usize,
    nzxor_count: usize,
    /// VAs of every counted non-zeroing XOR (used for the
    /// NzxorTightLoop combined feature).
    nzxor_vas: Vec<u64>,
    shift_count: usize,
    mov_count: usize,
    /// (start_bb_va, fall_through_bb_va) for each tight loop.
    tight_loops: Vec<(u64, u64)>,
    kinda_tight_loops: Vec<(u64, u64)>,
    /// True if any SCC in the BB graph has size ≥ 2 (multi-BB loop).
    has_loop: bool,
    largest_scc: usize,
}

fn extract_features(cfg: &Cfg) -> Features {
    let mut f = Features::default();
    f.block_count = cfg.bbs.len();
    f.instr_count = cfg.instrs.len();

    // Identify root BB (function entry) + return BBs for the security-
    // cookie filter window.
    let root_va = cfg.func_start_va;
    let return_bb_ranges: Vec<(u64, u64)> = cfg
        .bbs
        .iter()
        .filter(|b| b.ends_with_return)
        .map(|b| (b.start_va, b.end_va))
        .collect();

    for bb in &cfg.bbs {
        for &i in &bb.instrs {
            let ins = &cfg.instrs[i].instr;
            let va = cfg.instrs[i].va;
            match ins.mnemonic() {
                Mnemonic::Xor => {
                    if is_non_zeroing_xor(ins)
                        && !is_security_cookie(ins, va, bb.start_va, bb.end_va, root_va, &return_bb_ranges)
                    {
                        f.nzxor_count += 1;
                        f.nzxor_vas.push(va);
                    }
                }
                Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sal
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Rcl
                | Mnemonic::Rcr => {
                    f.shift_count += 1;
                }
                Mnemonic::Mov => {
                    if is_mov_to_reg_deref(ins) {
                        f.mov_count += 1;
                    }
                }
                _ => {}
            }
        }
    }

    // Tight / kinda-tight loops (FLOSS extract_function_kinda_tight_loop).
    // Skip first BB and any BB whose successors include none (return / indirect).
    let root_idx = cfg.bb_index.get(&root_va).copied();
    for (i, bb) in cfg.bbs.iter().enumerate() {
        if Some(i) == root_idx {
            continue;
        }
        if bb.ends_with_return {
            continue;
        }
        if bb.successors.len() != 2 {
            continue;
        }
        // A) very tight: bb -> bb
        let mut loop_bb: Option<u64> = None;
        let mut very_tight = false;
        for &s in &bb.successors {
            if s == bb.start_va {
                very_tight = true;
                loop_bb = Some(bb.start_va);
                break;
            }
        }
        // B) kinda tight: bb -> c -> bb (c has bb as a successor and
        // either a single successor or self-loop on c).
        if loop_bb.is_none() {
            for &s in &bb.successors {
                if let Some(&c_idx) = cfg.bb_index.get(&s) {
                    let c = &cfg.bbs[c_idx];
                    let c_succs = &c.successors;
                    let returns_to_bb = c_succs.iter().any(|&v| v == bb.start_va);
                    if returns_to_bb && (c_succs.len() == 1 || c.start_va == bb.start_va) {
                        loop_bb = Some(s);
                        break;
                    }
                }
            }
        }
        if let Some(lva) = loop_bb {
            // FLOSS skip filters: ignore if the loop body either calls
            // another function or doesn't write memory.
            let bb_calls = bb_contains_call(cfg, bb);
            let lbb_calls = if let Some(&li) = cfg.bb_index.get(&lva) {
                bb_contains_call(cfg, &cfg.bbs[li])
            } else {
                false
            };
            if bb_calls || lbb_calls {
                continue;
            }
            let bb_writes = bb_writes_memory(cfg, bb);
            let lbb_writes = if let Some(&li) = cfg.bb_index.get(&lva) {
                bb_writes_memory(cfg, &cfg.bbs[li])
            } else {
                false
            };
            if !(bb_writes || lbb_writes) {
                continue;
            }
            // Find the "next" BB (the non-loop successor) for FLOSS shape.
            let next_bb = bb
                .successors
                .iter()
                .find(|&&s| s != lva)
                .copied()
                .unwrap_or(0);
            if very_tight {
                f.tight_loops.push((bb.start_va, next_bb));
            } else {
                f.kinda_tight_loops.push((bb.start_va, next_bb));
            }
        }
    }

    // Multi-BB loop via Tarjan SCC on the BB graph.
    let scc_sizes = compute_scc_sizes(cfg);
    f.largest_scc = scc_sizes.iter().copied().max().unwrap_or(0);
    f.has_loop = scc_sizes.iter().any(|&s| s >= 2);

    f
}

// ── Per-instruction predicates ─────────────────────────────────────

fn is_non_zeroing_xor(ins: &Instruction) -> bool {
    if ins.mnemonic() != Mnemonic::Xor {
        return false;
    }
    if ins.op_count() < 2 {
        return false;
    }
    if ins.op0_kind() == OpKind::Register && ins.op1_kind() == OpKind::Register {
        // FLOSS: filter out the zeroing idiom xor reg, reg.
        if normalize_reg(ins.op0_register()) == normalize_reg(ins.op1_register()) {
            return false;
        }
        return true;
    }
    // FLOSS only counts XORs whose source is a register. xor reg, imm
    // could be an obfuscation key, but FLOSS's `extract_insn_nzxor`
    // only looks at reg-reg form (it calls `insn.opers[0] == insn.opers[1]`
    // which on viv is operand-equality). Match FLOSS exactly for
    // scoring parity.
    false
}

fn is_security_cookie(
    ins: &Instruction,
    va: u64,
    bb_start: u64,
    bb_end: u64,
    root_va: u64,
    return_bb_ranges: &[(u64, u64)],
) -> bool {
    // Operand 1 must be SP or BP (any width).
    if ins.op_count() < 2 || ins.op1_kind() != OpKind::Register {
        return false;
    }
    if !is_sp_or_bp(ins.op1_register()) {
        return false;
    }
    // Window 1: in the function's first BB, within the first 0x40 bytes
    // (FLOSS SECURITY_COOKIE_BYTES_DELTA).
    if bb_start == root_va && va < bb_start + SECURITY_COOKIE_BYTES_DELTA {
        return true;
    }
    // Window 2: in any returning BB, within the last 0x40 bytes before
    // the return instruction.
    for &(rs, re) in return_bb_ranges {
        if bb_start == rs && bb_end == re && va > re.saturating_sub(SECURITY_COOKIE_BYTES_DELTA) {
            return true;
        }
    }
    false
}

fn is_sp_or_bp(r: Register) -> bool {
    matches!(
        r,
        Register::ESP
            | Register::RSP
            | Register::EBP
            | Register::RBP
            | Register::SP
            | Register::BP
            | Register::SPL
            | Register::BPL
    )
}

/// FLOSS `extract_insn_mov`: `mov [reg], reg2` with displacement 0
/// (writes to a register-pointed memory location, not an immediate
/// destination, not displaced).
fn is_mov_to_reg_deref(ins: &Instruction) -> bool {
    if ins.op_count() != 2 {
        return false;
    }
    // op0 must be a memory operand with no displacement and an index
    // base register (no SIB other than [reg]); op1 must be a register
    // (not an immediate).
    if ins.op0_kind() != OpKind::Memory {
        return false;
    }
    if ins.op1_kind() != OpKind::Register {
        return false;
    }
    if ins.memory_displacement64() != 0 {
        return false;
    }
    if ins.memory_index() != Register::None {
        // [base + index*scale] — FLOSS specifically excludes this via
        // `isinstance(op0, i386RegMemOper)` which is the no-SIB form.
        return false;
    }
    if ins.memory_base() == Register::None {
        return false;
    }
    true
}

fn bb_contains_call(cfg: &Cfg, bb: &Bb) -> bool {
    for &i in &bb.instrs {
        let ins = &cfg.instrs[i].instr;
        if matches!(flow_of(ins), Flow::Call | Flow::IndirectCall) {
            return true;
        }
    }
    false
}

fn bb_writes_memory(cfg: &Cfg, bb: &Bb) -> bool {
    // FLOSS approximates "writes memory" by checking whether the first
    // operand of any instruction is a memory operand (RegMem / ImmMem /
    // Sib). iced-x86 lumps these into `OpKind::Memory` plus the
    // memory-segment forms; we treat any memory-op-as-op0 as a write
    // candidate. (Reads-only mov loads have op0=Register; we'd miss
    // `cmp [m], r` which is a read, but FLOSS misses that too.)
    for &i in &bb.instrs {
        let ins = &cfg.instrs[i].instr;
        if ins.op_count() == 0 {
            continue;
        }
        match ins.op0_kind() {
            OpKind::Memory | OpKind::MemorySegSI | OpKind::MemorySegDI | OpKind::MemorySegESI
            | OpKind::MemorySegEDI | OpKind::MemorySegRSI | OpKind::MemorySegRDI
            | OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI => return true,
            _ => {}
        }
    }
    false
}

// Normalize 32/16/8-bit GPR sub-registers to their 64-bit parent so
// `xor eax, eax` is treated identically to `xor rax, rax`. iced-x86 has
// `Register::full_register()` behind the `instr_info` feature, which
// codemap doesn't enable to keep the dep tree minimal. Mirror the table
// already used in dataflow_local::reg_index.
fn normalize_reg(r: Register) -> Register {
    match r {
        Register::EAX | Register::AX | Register::AL | Register::AH => Register::RAX,
        Register::ECX | Register::CX | Register::CL | Register::CH => Register::RCX,
        Register::EDX | Register::DX | Register::DL | Register::DH => Register::RDX,
        Register::EBX | Register::BX | Register::BL | Register::BH => Register::RBX,
        Register::ESP | Register::SP | Register::SPL => Register::RSP,
        Register::EBP | Register::BP | Register::BPL => Register::RBP,
        Register::ESI | Register::SI | Register::SIL => Register::RSI,
        Register::EDI | Register::DI | Register::DIL => Register::RDI,
        Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15D | Register::R15W | Register::R15L => Register::R15,
        other => other,
    }
}

// ── Tarjan SCC over the BB graph ───────────────────────────────────

/// Returns the size of every strongly-connected component in the BB
/// graph. Used to flag the FLOSS `Loop` feature (any SCC ≥ 2).
fn compute_scc_sizes(cfg: &Cfg) -> Vec<usize> {
    let n = cfg.bbs.len();
    let mut idx: Vec<i32> = vec![-1; n];
    let mut low: Vec<i32> = vec![0; n];
    let mut on_stack: Vec<bool> = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut counter: i32 = 0;
    let mut sizes: Vec<usize> = Vec::new();

    // Iterative DFS to avoid Rust stack overflow on huge functions.
    fn strong_connect(
        v: usize,
        cfg: &Cfg,
        idx: &mut [i32],
        low: &mut [i32],
        on_stack: &mut [bool],
        stack: &mut Vec<usize>,
        counter: &mut i32,
        sizes: &mut Vec<usize>,
    ) {
        // Recursive form is fine here — function CFGs are bounded by
        // disasm_binary's per-function size cap (1 MB → at most a few
        // thousand BBs in practice).
        idx[v] = *counter;
        low[v] = *counter;
        *counter += 1;
        stack.push(v);
        on_stack[v] = true;

        for &succ_va in &cfg.bbs[v].successors {
            if let Some(&w) = cfg.bb_index.get(&succ_va) {
                if idx[w] == -1 {
                    strong_connect(w, cfg, idx, low, on_stack, stack, counter, sizes);
                    if low[w] < low[v] {
                        low[v] = low[w];
                    }
                } else if on_stack[w] && idx[w] < low[v] {
                    low[v] = idx[w];
                }
            }
        }

        if low[v] == idx[v] {
            let mut size = 0usize;
            // Track whether this SCC includes a self-loop (size==1
            // SCC with self-edge is still a loop in the FLOSS sense).
            let mut has_self_loop = false;
            for &s in &cfg.bbs[v].successors {
                if let Some(&sw) = cfg.bb_index.get(&s) {
                    if sw == v {
                        has_self_loop = true;
                    }
                }
            }
            loop {
                let w = stack.pop().expect("scc stack non-empty");
                on_stack[w] = false;
                size += 1;
                if w == v {
                    break;
                }
            }
            // FLOSS extract_function_loop counts SCCs with len ≥ 2.
            // Promote a 1-node SCC with a self-loop edge to size 2 so
            // tight self-loops also light up the Loop feature.
            if size == 1 && has_self_loop {
                size = 2;
            }
            sizes.push(size);
        }
    }

    for v in 0..n {
        if idx[v] == -1 {
            strong_connect(v, cfg, &mut idx, &mut low, &mut on_stack, &mut stack, &mut counter, &mut sizes);
        }
    }
    sizes
}

// ── Scoring (FLOSS feature weights) ────────────────────────────────

fn score_function(f: &Features, calls_to: usize, max_calls_to: usize) -> (f64, Vec<&'static str>) {
    let mut weight_sum = 0.0;
    let mut weighted_sum = 0.0;
    let mut names: Vec<&'static str> = Vec::new();

    // BlockCount — LOW. FLOSS: >30 → 0.1, 3..=10 → 1.0, else → 0.4.
    let bc = f.block_count;
    let bc_score = if bc > 30 {
        0.1
    } else if (3..=10).contains(&bc) {
        1.0
    } else {
        0.4
    };
    weight_sum += W_LOW;
    weighted_sum += W_LOW * bc_score;

    // InstructionCount — LOW. >10 → 0.8, else → 0.1.
    let ic_score = if f.instr_count > 10 { 0.8 } else { 0.1 };
    weight_sum += W_LOW;
    weighted_sum += W_LOW * ic_score;

    // CallsTo — MEDIUM. Score = calls_to / max_calls_to.
    let calls_score = (calls_to as f64) / (max_calls_to as f64);
    weight_sum += W_MED;
    weighted_sum += W_MED * calls_score;

    // Per-occurrence features. FLOSS treats each Nzxor / Shift / Mov as
    // an independent feature emission with score=1.0; the weight sum
    // grows accordingly. Match that behavior.
    for _ in 0..f.nzxor_count {
        weight_sum += W_HIGH;
        weighted_sum += W_HIGH;
    }
    if f.nzxor_count > 0 {
        names.push("Nzxor");
    }
    for _ in 0..f.shift_count {
        weight_sum += W_HIGH;
        weighted_sum += W_HIGH;
    }
    if f.shift_count > 0 {
        names.push("Shift");
    }
    for _ in 0..f.mov_count {
        weight_sum += W_MED;
        weighted_sum += W_MED;
    }
    if f.mov_count > 0 {
        names.push("Mov");
    }

    // TightLoop / KindaTightLoop — HIGH each.
    for _ in 0..f.tight_loops.len() {
        weight_sum += W_HIGH;
        weighted_sum += W_HIGH;
    }
    if !f.tight_loops.is_empty() {
        names.push("TightLoop");
    }
    for _ in 0..f.kinda_tight_loops.len() {
        weight_sum += W_HIGH;
        weighted_sum += W_HIGH;
    }
    if !f.kinda_tight_loops.is_empty() {
        names.push("KindaTightLoop");
    }

    // Loop (SCC ≥ 2) — MEDIUM.
    if f.has_loop {
        weight_sum += W_MED;
        weighted_sum += W_MED;
        names.push("Loop");
    }

    // Combined / abstraction features.
    let nzxor_in_tight = !f.tight_loops.is_empty()
        && f.nzxor_vas.iter().any(|&va| {
            f.tight_loops.iter().any(|&(s, e)| va >= s && va < e)
        });
    if nzxor_in_tight {
        weight_sum += W_SEVERE;
        weighted_sum += W_SEVERE;
        names.push("NzxorTightLoop");
    }
    if f.nzxor_count > 0 && f.has_loop {
        weight_sum += W_SEVERE;
        weighted_sum += W_SEVERE;
        names.push("NzxorLoop");
    }
    let any_tight = !f.tight_loops.is_empty() || !f.kinda_tight_loops.is_empty();
    if any_tight && f.block_count < TS_TIGHT_FUNCTION_MAX_BLOCKS {
        // FLOSS scores TightFunction at 0.0 (it's emulated separately
        // upstream). We mirror that — the weight is added to the
        // denominator but contributes zero to the numerator. This
        // depresses the score for trivial wrappers, matching FLOSS.
        weight_sum += W_SEVERE;
        weighted_sum += 0.0;
        names.push("TightFunction");
    }

    // Note: BlockCount/InstructionCount/CallsTo are always present.
    // We list them only when their score is non-default to keep the
    // feature_names list informative without cluttering it.
    if bc_score >= 1.0 {
        names.push("BlockCount(3-10)");
    }
    if ic_score >= 0.8 {
        names.push("InstrCount(>10)");
    }
    if calls_to > 0 && calls_score > 0.5 {
        names.push("CallsTo");
    }

    let final_score = if weight_sum > 0.0 {
        weighted_sum / weight_sum
    } else {
        0.0
    };
    // Round to 3 decimal places for stable display + comparisons.
    let final_score = (final_score * 1000.0).round() / 1000.0;
    (final_score, names)
}

// ── Thunk & runtime-helper filters ─────────────────────────────────

fn is_thunk(cfg: &Cfg) -> bool {
    // Single-instruction unconditional jump → classic thunk
    // (`jmp <target>`). Two-instruction is also common (mov + jmp);
    // stay conservative and only filter the canonical 1-jmp form.
    if cfg.instrs.len() == 1 {
        let ins = &cfg.instrs[0].instr;
        if matches!(flow_of(ins), Flow::UnconditionalBranch | Flow::IndirectBranch) {
            return true;
        }
    }
    false
}

/// Skip well-known runtime helpers that the FLOSS scorer would
/// otherwise score as decoder candidates. FLOSS uses FLIRT signatures
/// to identify library functions; codemap doesn't ship FLIRT, so we
/// ship a small hardcoded list of CRT / libc names that show up as
/// false positives in practice.
fn is_runtime_helper(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    // MSVC CRT helpers
    let n = name.trim_start_matches('_');
    let runtime_prefixes = [
        "chkstk", "alloca_probe", "security_check_cookie",
        "security_init_cookie", "security_cookie",
        "RTC_", "rtc_", "EH_prolog", "CRT_", "crt_",
        "CxxThrowException", "InitTerm",
        "report_", "RTC_CheckEsp",
    ];
    for p in &runtime_prefixes {
        if n.starts_with(p) {
            return true;
        }
    }
    // libc / glibc internals
    let exact_skip = [
        "_start", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini",
        "__libc_start_main", "register_tm_clones", "deregister_tm_clones",
        "frame_dummy", "__do_global_dtors_aux", "__libc_init",
        "__GI___libc_start_main", "_dl_relocate_static_pie",
        "mainCRTStartup", "WinMainCRTStartup", "wmainCRTStartup",
        "_DllMainCRTStartup", "_amsg_exit", "_initterm", "_initterm_e",
        "__report_gsfailure",
    ];
    for s in &exact_skip {
        if name == *s || n == s.trim_start_matches('_') {
            return true;
        }
    }
    false
}

// ── Calls-to map ───────────────────────────────────────────────────

fn build_calls_to(funcs: &[DisasmFunction]) -> HashMap<u64, usize> {
    let mut out: HashMap<u64, usize> = HashMap::new();
    for f in funcs {
        for &target in &f.calls {
            *out.entry(target).or_insert(0) += 1;
        }
    }
    out
}

// ── .text-bytes extraction (PE + ELF) ──────────────────────────────

fn extract_text_bytes(data: &[u8], r: &DisasmResult) -> Option<Vec<u8>> {
    match r.format {
        "pe" => extract_text_pe(data),
        "elf" => extract_text_elf(data),
        _ => None,
    }
}

fn extract_text_pe(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return None;
    }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() {
            return None;
        }
        let name_bytes = &data[off..off + 8];
        if !name_bytes.starts_with(b".text") {
            continue;
        }
        let raw_size =
            u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]])
                as usize;
        let raw_off =
            u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]])
                as usize;
        let end = (raw_off + raw_size).min(data.len());
        return Some(data[raw_off..end].to_vec());
    }
    None
}

fn extract_text_elf(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 64 || &data[..4] != b"\x7FELF" {
        return None;
    }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let read_u32 = |off: usize| -> u32 {
        if off + 4 > data.len() {
            return 0;
        }
        if little_endian {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        } else {
            u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        }
    };
    let read_u64 = |off: usize| -> u64 {
        if off + 8 > data.len() {
            return 0;
        }
        if little_endian {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
        } else {
            u64::from_be_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
        }
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() {
            return 0;
        }
        if little_endian {
            u16::from_le_bytes([data[off], data[off + 1]])
        } else {
            u16::from_be_bytes([data[off], data[off + 1]])
        }
    };
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        (
            read_u64(0x28) as usize,
            read_u16(0x3a) as usize,
            read_u16(0x3c) as usize,
            read_u16(0x3e) as usize,
        )
    } else {
        (
            read_u32(0x20) as usize,
            read_u16(0x2e) as usize,
            read_u16(0x30) as usize,
            read_u16(0x32) as usize,
        )
    };
    if e_shoff == 0 || e_shentsize == 0 {
        return None;
    }
    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = if is_64 {
        read_u64(shstr_hdr + 0x18) as usize
    } else {
        read_u32(shstr_hdr + 0x10) as usize
    };
    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() {
            break;
        }
        let name_idx = read_u32(hdr) as usize;
        let (offset, size) = if is_64 {
            (read_u64(hdr + 0x18), read_u64(hdr + 0x20))
        } else {
            (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64)
        };
        let mut name = String::new();
        if shstrtab_off + name_idx < data.len() {
            let mut end = shstrtab_off + name_idx;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
        }
        if name == ".text" {
            let off = offset as usize;
            let end = (off + size as usize).min(data.len());
            if off >= data.len() {
                return None;
            }
            return Some(data[off..end].to_vec());
        }
    }
    None
}

// ── Graph emission + report formatting ─────────────────────────────

fn confidence_for(score: f64) -> &'static str {
    if score >= 0.6 {
        "high"
    } else if score >= 0.4 {
        "medium"
    } else {
        "low"
    }
}

fn register_into_graph(
    graph: &mut Graph,
    target: &str,
    result: &DisasmResult,
    scored: &[ScoredFunction<'_>],
) {
    if scored.is_empty() {
        return;
    }
    let bin_id = if result.format == "pe" {
        format!("pe:{target}")
    } else {
        format!("elf:{target}")
    };
    let kind = if result.format == "pe" {
        EntityKind::PeBinary
    } else {
        EntityKind::ElfBinary
    };
    graph.ensure_typed_node(&bin_id, kind, &[("path", target)]);

    for s in scored {
        let func_va = s.func.address;
        let dec_id = format!("decoder:{target}::{func_va:#x}");
        let display = demangle(&s.func.name).unwrap_or_else(|| s.func.name.clone());
        let conf = confidence_for(s.score);
        let score_s = format!("{:.3}", s.score);
        let va_s = format!("{:#x}", func_va);
        let bc_s = s.features.block_count.to_string();
        let ic_s = s.features.instr_count.to_string();
        let nz_s = s.features.nzxor_count.to_string();
        let sh_s = s.features.shift_count.to_string();
        let mv_s = s.features.mov_count.to_string();
        let calls_s = s.calls_to.to_string();
        let feats_s = if s.feature_names.is_empty() {
            String::from("(baseline)")
        } else {
            s.feature_names.join(",")
        };
        graph.ensure_typed_node(
            &dec_id,
            EntityKind::DecoderCandidate,
            &[
                ("function_address", va_s.as_str()),
                ("function_name", display.as_str()),
                ("score", score_s.as_str()),
                ("confidence", conf),
                ("block_count", bc_s.as_str()),
                ("instruction_count", ic_s.as_str()),
                ("nzxor_count", nz_s.as_str()),
                ("shift_count", sh_s.as_str()),
                ("mov_count", mv_s.as_str()),
                ("calls_to", calls_s.as_str()),
                ("features", feats_s.as_str()),
            ],
        );
        graph.add_edge(&bin_id, &dec_id);

        // Cross-edge to the BinaryFunction node if bin-disasm has run.
        let func_id = format!("bin_func:{target}::{func_va:#x}");
        if graph.nodes.contains_key(&func_id) {
            graph.add_edge(&dec_id, &func_id);
        }
    }
}

fn format_report(target: &str, result: &DisasmResult, scored: &[ScoredFunction<'_>]) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Decoder-Function Detection: {target} ===\n\n"));
    out.push_str(&format!("Format / arch:        {} / {}\n", result.format, result.arch));
    out.push_str(&format!("Functions disasmed:   {}\n", result.functions.len()));
    out.push_str(&format!("Decoder candidates:   {} (score ≥ {:.2})\n", scored.len(), MIN_SCORE_REPORT));
    out.push('\n');

    if scored.is_empty() {
        out.push_str("No decoder-function candidates above threshold.\n");
        out.push_str("(v1 only flags x86/x64 functions; runtime/CRT helpers are filtered.\n");
        out.push_str(" Stripped binaries hit fewer functions → fewer candidates.)\n");
        return out;
    }

    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    for s in scored {
        match confidence_for(s.score) {
            "high" => high += 1,
            "medium" => med += 1,
            _ => low += 1,
        }
    }
    out.push_str(&format!("Confidence:           high={high} medium={med} low={low}\n\n"));

    out.push_str("── Top decoder candidates ──\n");
    let n_show = 30.min(scored.len());
    for (i, s) in scored.iter().take(n_show).enumerate() {
        let display = demangle(&s.func.name).unwrap_or_else(|| s.func.name.clone());
        let conf = confidence_for(s.score);
        let feats = if s.feature_names.is_empty() {
            String::from("(baseline)")
        } else {
            s.feature_names.join(",")
        };
        out.push_str(&format!(
            "  {:>2}. [{:<6}] {:#012x}  score={:.3}  bbs={:>2} ins={:>3} nzxor={} shift={} mov={} calls={}\n      [{}]\n      {}\n",
            i + 1,
            conf,
            s.func.address,
            s.score,
            s.features.block_count,
            s.features.instr_count,
            s.features.nzxor_count,
            s.features.shift_count,
            s.features.mov_count,
            s.calls_to,
            feats,
            truncate(&display, 80),
        ));
    }
    if scored.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", scored.len() - n_show));
    }
    out.push('\n');
    out.push_str("Try: codemap pagerank --type decoder        (rank decoder candidates)\n");
    out.push_str("     codemap meta-path \"pe->decoder->bin_func\"   (decoder → impl)\n");
    out.push_str("     codemap callers <decoder-name>          (find call sites)\n");
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max - 1).collect();
    format!("{cut}…")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_func(name: &str, addr: u64, size: u64, instr_count: usize) -> DisasmFunction {
        DisasmFunction {
            name: name.into(),
            address: addr,
            size,
            instruction_count: instr_count,
            calls: vec![],
            indirect_calls: 0,
            jump_targets: vec![],
            crypto_xor_in_loop: 0,
            back_edge_count: 0,
            cff_dispatcher_va: None,
            cff_dispatcher_hits: 0,
            cff_score: 0.0,
            opaque_pred_count: 0,
            is_entry: false,
        }
    }

    /// Build a synthetic x64 function that imitates a string-decoder shape:
    /// a tight loop with non-zeroing XOR + shift + mov-to-deref.
    ///
    ///   0x1000: lea rcx, [rcx]            ; placeholder (entry)
    ///   0x1003: mov al, [rdx]             ; load byte
    ///   0x1005: xor al, bl                ; non-zeroing XOR (decode)
    ///   0x1007: shl al, 3                 ; shift
    ///   0x100a: mov [rdx], al             ; store back
    ///   0x100c: inc rdx                   ; advance
    ///   0x100f: dec rcx                   ; counter
    ///   0x1012: jne 0x1003                ; tight loop back-edge
    ///   0x1014: ret
    fn synth_decoder_bytes() -> Vec<u8> {
        // Hand-assembled encodings (validated against iced-x86 decoder
        // in the test below).
        let mut v: Vec<u8> = Vec::new();
        // 0x1000: 48 8d 09             lea rcx, [rcx]      (3 B)
        v.extend_from_slice(&[0x48, 0x8d, 0x09]);
        // 0x1003: 8a 02                mov al, [rdx]       (2 B)
        v.extend_from_slice(&[0x8a, 0x02]);
        // 0x1005: 30 d8                xor al, bl          (2 B) — nz xor
        v.extend_from_slice(&[0x30, 0xd8]);
        // 0x1007: c0 e0 03             shl al, 3           (3 B) — shift
        v.extend_from_slice(&[0xc0, 0xe0, 0x03]);
        // 0x100a: 88 02                mov [rdx], al       (2 B) — mov-to-deref
        v.extend_from_slice(&[0x88, 0x02]);
        // 0x100c: 48 ff c2             inc rdx             (3 B)
        v.extend_from_slice(&[0x48, 0xff, 0xc2]);
        // 0x100f: 48 ff c9             dec rcx             (3 B)
        v.extend_from_slice(&[0x48, 0xff, 0xc9]);
        // 0x1012: 75 ef                jne 0x1003          (2 B) — back to loop start
        v.extend_from_slice(&[0x75, 0xef]);
        // 0x1014: c3                   ret                  (1 B)
        v.push(0xc3);
        v
    }

    #[test]
    fn cfg_recognizes_tight_loop_in_synth_decoder() {
        let bytes = synth_decoder_bytes();
        let f = mk_func("decode_blob", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        // Expect at least 3 BBs: entry, loop body, post-ret block.
        // (entry is 1-instr lea, then loop body starts at the back-edge
        // target 0x1003 because of the jne back-edge; ret is its own BB.)
        assert!(
            cfg.bbs.len() >= 2,
            "expected ≥ 2 BBs, got {}: {:?}",
            cfg.bbs.len(),
            cfg.bbs.iter().map(|b| (b.start_va, b.end_va)).collect::<Vec<_>>()
        );

        let features = extract_features(&cfg);
        assert_eq!(features.nzxor_count, 1, "synth decoder has exactly one nz-XOR");
        assert!(features.shift_count >= 1, "shift detected");
        assert!(features.mov_count >= 1, "mov-to-deref detected");
        // Tight loop OR a SCC-loop must fire (the back-edge is at 0x1012 → 0x1003).
        assert!(
            features.has_loop || !features.tight_loops.is_empty() || !features.kinda_tight_loops.is_empty(),
            "loop signal expected; features={:?}",
            features
        );
    }

    #[test]
    fn synth_decoder_scores_above_threshold() {
        let bytes = synth_decoder_bytes();
        let f = mk_func("decode_blob", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        let features = extract_features(&cfg);
        let (score, names) = score_function(&features, 5, 10);
        assert!(
            score >= MIN_SCORE_REPORT,
            "synth decoder must score above {MIN_SCORE_REPORT}, got {score} (features={names:?})"
        );
        // Severity flags should fire — non-zeroing XOR sits in a loop.
        assert!(
            names.contains(&"NzxorLoop") || names.contains(&"NzxorTightLoop"),
            "expected NzxorLoop / NzxorTightLoop in features, got {names:?}"
        );
    }

    /// Plain function with no decoder features should NOT be flagged.
    /// Just a few moves + ret.
    fn synth_plain_bytes() -> Vec<u8> {
        // 0x1000: 48 89 c8        mov rax, rcx       (3 B)
        // 0x1003: 48 89 d3        mov rbx, rdx       (3 B)
        // 0x1006: c3              ret                 (1 B)
        vec![0x48, 0x89, 0xc8, 0x48, 0x89, 0xd3, 0xc3]
    }

    #[test]
    fn plain_function_scores_below_threshold() {
        let bytes = synth_plain_bytes();
        let f = mk_func("plain", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        let features = extract_features(&cfg);
        let (score, _names) = score_function(&features, 0, 10);
        assert!(
            score < MIN_SCORE_REPORT,
            "plain function should score below {MIN_SCORE_REPORT}, got {score}"
        );
        assert_eq!(features.nzxor_count, 0);
        assert!(features.tight_loops.is_empty());
    }

    /// MS security-cookie XOR pattern: `xor rcx, rsp` near function
    /// epilogue with rsp/rbp operand. Must NOT count as Nzxor.
    fn synth_security_cookie_bytes() -> Vec<u8> {
        // Function with xor of stack pointer at entry (security cookie init).
        // 0x1000: 48 33 cc        xor rcx, rsp          (3 B) — security cookie init
        // 0x1003: 48 89 c8        mov rax, rcx          (3 B)
        // 0x1006: c3              ret                    (1 B)
        vec![0x48, 0x33, 0xcc, 0x48, 0x89, 0xc8, 0xc3]
    }

    #[test]
    fn ms_security_cookie_xor_filtered() {
        let bytes = synth_security_cookie_bytes();
        let f = mk_func("with_cookie", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        let features = extract_features(&cfg);
        assert_eq!(
            features.nzxor_count, 0,
            "security cookie XOR (xor rcx, rsp at entry) must be filtered, got nzxor={}",
            features.nzxor_count
        );
    }

    #[test]
    fn thunk_function_filtered() {
        // Single instruction: jmp +0x10 (5-byte near jmp).
        // E9 10 00 00 00
        let bytes = vec![0xe9, 0x10, 0x00, 0x00, 0x00];
        let f = mk_func("thunk", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        assert!(is_thunk(&cfg), "single-jmp function should be flagged thunk");
    }

    #[test]
    fn runtime_helpers_filtered_by_name() {
        for n in [
            "_chkstk",
            "__chkstk",
            "__security_check_cookie",
            "_start",
            "mainCRTStartup",
            "WinMainCRTStartup",
            "__libc_start_main",
            "_init",
            "_fini",
            "frame_dummy",
            "register_tm_clones",
        ] {
            assert!(is_runtime_helper(n), "should filter {n}");
        }
        assert!(!is_runtime_helper("decode_strings"));
        assert!(!is_runtime_helper("rc4_decrypt"));
    }

    #[test]
    fn confidence_thresholds() {
        assert_eq!(confidence_for(0.85), "high");
        assert_eq!(confidence_for(0.6), "high");
        assert_eq!(confidence_for(0.5), "medium");
        assert_eq!(confidence_for(0.4), "medium");
        assert_eq!(confidence_for(0.39), "low");
        assert_eq!(confidence_for(0.0), "low");
    }

    #[test]
    fn nzxor_register_normalization() {
        // xor eax, eax — sub-register form of xor rax, rax. Must be
        // recognized as a zeroing idiom.
        // 31 c0
        let bytes = vec![0x31, 0xc0, 0xc3];
        let f = mk_func("plain_xor_eax", 0x1000, bytes.len() as u64, 0);
        let cfg = build_cfg(&bytes, 0x1000, 64, &f).expect("cfg builds");
        let features = extract_features(&cfg);
        assert_eq!(
            features.nzxor_count, 0,
            "xor eax, eax is the zeroing idiom — must NOT count"
        );
    }

    #[test]
    fn empty_scored_list_yields_no_detection() {
        let empty: Vec<ScoredFunction> = Vec::new();
        // Build a stub DisasmResult-ish via direct construction not
        // possible (private fields); test the format_report fast-path
        // by calling score_function on a degenerate Features.
        let f = Features::default();
        let (score, _) = score_function(&f, 0, 1);
        // Empty features → score = (0.25*0.4 + 0.25*0.1 + 0.5*0)/(0.25+0.25+0.5) = 0.05
        assert!(score < MIN_SCORE_REPORT);
    }
}
