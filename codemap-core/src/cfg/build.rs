// ── Basic-Block construction from a flat iced-x86 instruction stream
//
// Two-pass algorithm:
//
//   Pass 1: collect *leader* addresses — the first instruction of
//           every basic block. A leader is:
//             - the first instruction of the input
//             - the target of any direct branch (Jcc/Jmp)
//             - the instruction immediately following any branch,
//               call, ret, or interrupt-style terminator
//           This is the textbook leader-set algorithm (Aho/ASU
//           Dragon book §9.4).
//
//   Pass 2: walk the instruction stream and split into BBs at every
//           leader. Emit edges as we close each BB:
//             - Fall-through edge to the next BB if the terminator
//               doesn't unconditionally divert control
//             - Direct branch target as a Cond / Uncond / Indir /
//               Call edge
//
// The taxonomy (BbKind / EdgeKind) tracks Quokka's Block.BlockType
// and Edge.EdgeType — close enough that v2 detectors written
// against Quokka research notes port over without re-mapping.

use iced_x86::{Instruction, Mnemonic, OpKind};

// We classify control-flow ourselves rather than enabling iced-x86's
// `instr_info` feature. The codebase deliberately keeps that feature
// off (see dataflow_local.rs preamble + Cargo.toml) — it pulls in
// large tables we don't need for the rest of codemap. The set of
// mnemonics that affect intra-procedural CFG construction is small
// and stable enough to enumerate by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fc {
    Next,
    UncondBranch,
    CondBranch,
    IndirectBranch,
    Call,
    IndirectCall,
    Return,
    Interrupt,
}

fn flow_control(ins: &Instruction) -> Fc {
    match ins.mnemonic() {
        // Direct/indirect unconditional jump — disambiguated by the
        // operand kind.
        Mnemonic::Jmp => {
            if ins.op_count() == 1 && matches!(ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                | OpKind::FarBranch16 | OpKind::FarBranch32) {
                Fc::UncondBranch
            } else {
                Fc::IndirectBranch
            }
        }
        // All Jcc + JCXZ variants + LOOP*. JCXZ and LOOP* are
        // technically conditional too — they fall through if the
        // count register is zero / non-zero respectively.
        Mnemonic::Je   | Mnemonic::Jne  | Mnemonic::Jl   | Mnemonic::Jle
        | Mnemonic::Jg | Mnemonic::Jge  | Mnemonic::Ja   | Mnemonic::Jae
        | Mnemonic::Jb | Mnemonic::Jbe  | Mnemonic::Js   | Mnemonic::Jns
        | Mnemonic::Jp | Mnemonic::Jnp  | Mnemonic::Jo   | Mnemonic::Jno
        | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz
        | Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => Fc::CondBranch,
        Mnemonic::Call => {
            if ins.op_count() == 1 && matches!(ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                | OpKind::FarBranch16 | OpKind::FarBranch32) {
                Fc::Call
            } else {
                Fc::IndirectCall
            }
        }
        Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd
        | Mnemonic::Iretq => Fc::Return,
        // Hard / soft interrupts + UD2 + HLT. UD2 raises #UD which
        // the OS turns into a fatal signal — in user-space code,
        // execution does not return. We classify it as Interrupt.
        Mnemonic::Int | Mnemonic::Int1 | Mnemonic::Int3 | Mnemonic::Into
        | Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2 | Mnemonic::Hlt => Fc::Interrupt,
        _ => Fc::Next,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbKind {
    /// Falls through or branches to a known successor inside the function.
    Normal,
    /// Terminator is an indirect JMP (e.g., jump-table dispatch).
    IndJump,
    /// Terminator is a RET / RETF.
    Ret,
    /// Terminator is a no-return call (UD2, INT3, HLT etc.) followed
    /// by no fallthrough.
    NoRet,
    /// Conditional branch where one side returns. Tracked separately
    /// so detectors can recognise `if (err) ret; ...` shapes.
    CndRet,
    /// Block ends in a tail-call (JMP to an external symbol / outside
    /// the function range). Treated like a return for CFG purposes.
    ENoRet,
    /// Block belongs to an external (imported) symbol — appears only
    /// when callers stitch CFGs across functions.
    Extern,
    /// Decoder failed inside this block — kept so visualisations
    /// don't silently drop instructions.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Direct unconditional jump (JMP rel).
    JumpUncond,
    /// Conditional branch (Jcc, JCXZ, LOOP*).
    JumpCond,
    /// Indirect jump — successor list comes from a side channel
    /// (jump-table resolver), not the JMP operand.
    JumpIndir,
    /// CALL with a near-branch immediate.
    Call,
    /// CALL via a register or memory operand.
    CallIndir,
    /// Implicit fall-through to the next block.
    Fall,
}

#[derive(Debug, Clone)]
pub struct Bb {
    /// Virtual address of the first instruction in this block.
    pub start: u64,
    /// Virtual address one past the last instruction in this block
    /// (i.e., next_ip of the terminator).
    pub end: u64,
    /// Indices into the input `insns` slice.
    pub insns: Vec<usize>,
    pub kind: BbKind,
}

#[derive(Debug, Clone, Default)]
pub struct BbCfg {
    pub bbs: Vec<Bb>,
    pub edges: Vec<(usize, usize, EdgeKind)>,
}

impl BbCfg {
    /// O(log n) lookup: BB containing the given VA, or None.
    pub fn block_at(&self, va: u64) -> Option<usize> {
        // bbs are emitted in source order; binary-search by start
        // VA, then verify the hit's range covers `va`.
        let probe = self.bbs.binary_search_by(|b| b.start.cmp(&va));
        let idx = match probe {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let b = &self.bbs[idx];
        if va >= b.start && va < b.end { Some(idx) } else { None }
    }

    /// Successors of `bb_idx` along with the edge kind. Cheap for
    /// the small fan-outs typical of decompiled code (≤2 for most
    /// BBs, larger only at indirect dispatch).
    pub fn succs(&self, bb_idx: usize) -> Vec<(usize, EdgeKind)> {
        self.edges.iter()
            .filter(|(s, _, _)| *s == bb_idx)
            .map(|(_, d, k)| (*d, *k))
            .collect()
    }

    /// Predecessors — symmetric helper for backward analyses.
    pub fn preds(&self, bb_idx: usize) -> Vec<(usize, EdgeKind)> {
        self.edges.iter()
            .filter(|(_, d, _)| *d == bb_idx)
            .map(|(s, _, k)| (*s, *k))
            .collect()
    }
}

/// Build a basic-block CFG from a flat instruction stream. The
/// caller owns the instruction slice; we only store indices into
/// it. Any near-branch target that lands outside the input range
/// becomes an `ENoRet` (tail-call-style exit) — those edges are
/// dropped, so the resulting CFG is closed under successor walks.
pub fn build_cfg(insns: &[Instruction]) -> BbCfg {
    if insns.is_empty() {
        return BbCfg::default();
    }

    // ── Pass 1: leader set ─────────────────────────────────────
    let mut leaders = std::collections::BTreeSet::<u64>::new();
    leaders.insert(insns[0].ip());

    for (i, ins) in insns.iter().enumerate() {
        let fc = flow_control(ins);
        match fc {
            Fc::UncondBranch | Fc::CondBranch | Fc::IndirectBranch => {
                if let Some(next) = insns.get(i + 1) {
                    leaders.insert(next.ip());
                }
                if matches!(fc, Fc::UncondBranch | Fc::CondBranch)
                    && ins.op_count() == 1
                    && matches!(ins.op0_kind(),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
                {
                    let t = ins.near_branch_target();
                    if in_range(insns, t) {
                        leaders.insert(t);
                    }
                }
            }
            Fc::Return | Fc::Interrupt => {
                if let Some(next) = insns.get(i + 1) {
                    leaders.insert(next.ip());
                }
            }
            Fc::Call | Fc::IndirectCall => {
                // Call falls through; the next instruction is a
                // leader so call-site metadata can attach to a
                // discrete BB and post-call back-edge targets land
                // cleanly.
                if let Some(next) = insns.get(i + 1) {
                    leaders.insert(next.ip());
                }
            }
            Fc::Next => {}
        }
    }

    // ── Pass 2: split into BBs ─────────────────────────────────
    let mut bbs: Vec<Bb> = Vec::new();
    let mut cur_insns: Vec<usize> = Vec::new();
    let mut cur_start: u64 = insns[0].ip();

    for (i, ins) in insns.iter().enumerate() {
        let ip = ins.ip();
        // Hit a leader (not the very first instruction, that's
        // already cur_start) → close the previous BB as Normal,
        // then open a new one.
        if !cur_insns.is_empty() && leaders.contains(&ip) {
            let prev = &insns[*cur_insns.last().unwrap()];
            bbs.push(Bb {
                start: cur_start,
                end: prev.next_ip(),
                insns: std::mem::take(&mut cur_insns),
                kind: BbKind::Normal, // overwritten below if real terminator
            });
            cur_start = ip;
        }

        cur_insns.push(i);

        let fc = flow_control(ins);
        let terminator = matches!(fc,
            Fc::UncondBranch | Fc::CondBranch | Fc::IndirectBranch
            | Fc::Return | Fc::Interrupt);

        if terminator {
            let kind = classify_terminator(ins, insns, fc);
            bbs.push(Bb {
                start: cur_start,
                end: ins.next_ip(),
                insns: std::mem::take(&mut cur_insns),
                kind,
            });
            // Set up the next block's start (or end of stream).
            if let Some(next) = insns.get(i + 1) {
                cur_start = next.ip();
            }
        }
    }

    // Trailing BB: instructions after the last terminator (or the
    // whole function if it has no explicit terminator). This
    // happens in malformed / probe inputs and in unit tests.
    if !cur_insns.is_empty() {
        let last = &insns[*cur_insns.last().unwrap()];
        bbs.push(Bb {
            start: cur_start,
            end: last.next_ip(),
            insns: std::mem::take(&mut cur_insns),
            kind: BbKind::Normal,
        });
    }

    // ── Edges ─────────────────────────────────────────────────
    let mut edges: Vec<(usize, usize, EdgeKind)> = Vec::new();
    let mut start_to_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, b) in bbs.iter().enumerate() {
        start_to_idx.insert(b.start, i);
    }

    for (bi, b) in bbs.iter().enumerate() {
        let last_idx = match b.insns.last() { Some(i) => *i, None => continue };
        let last = &insns[last_idx];
        let fc = flow_control(last);
        let direct_branch_target = if matches!(fc, Fc::UncondBranch | Fc::CondBranch)
            && last.op_count() == 1
            && matches!(last.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
        {
            Some(last.near_branch_target())
        } else { None };

        match fc {
            Fc::UncondBranch => {
                if let Some(t) = direct_branch_target {
                    if let Some(&di) = start_to_idx.get(&t) {
                        edges.push((bi, di, EdgeKind::JumpUncond));
                    }
                }
                // No fallthrough.
            }
            Fc::CondBranch => {
                if let Some(t) = direct_branch_target {
                    if let Some(&di) = start_to_idx.get(&t) {
                        edges.push((bi, di, EdgeKind::JumpCond));
                    }
                }
                if let Some(&fi) = start_to_idx.get(&b.end) {
                    edges.push((bi, fi, EdgeKind::Fall));
                }
            }
            Fc::IndirectBranch => {
                // Successor list comes from a side channel
                // (jump-table resolver). Callers splice them in
                // post-hoc with EdgeKind::JumpIndir.
            }
            Fc::Call | Fc::IndirectCall => {
                if let Some(&fi) = start_to_idx.get(&b.end) {
                    edges.push((bi, fi, EdgeKind::Fall));
                }
            }
            Fc::Return | Fc::Interrupt => {
                // No intra-procedural successors.
            }
            Fc::Next => {
                // Trailing BB or probe input — fall to the next BB
                // by VA if there is one.
                if let Some(&fi) = start_to_idx.get(&b.end) {
                    edges.push((bi, fi, EdgeKind::Fall));
                }
            }
        }
    }

    BbCfg { bbs, edges }
}

fn in_range(insns: &[Instruction], va: u64) -> bool {
    if insns.is_empty() { return false; }
    let lo = insns.first().unwrap().ip();
    let hi = insns.last().unwrap().next_ip();
    va >= lo && va < hi
}

fn classify_terminator(ins: &Instruction, insns: &[Instruction], fc: Fc) -> BbKind {
    match fc {
        Fc::Return => BbKind::Ret,
        Fc::Interrupt => BbKind::NoRet,
        Fc::IndirectBranch => BbKind::IndJump,
        Fc::UncondBranch => {
            if ins.op_count() == 1
                && matches!(ins.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
            {
                let t = ins.near_branch_target();
                if !in_range(insns, t) { BbKind::ENoRet } else { BbKind::Normal }
            } else {
                BbKind::IndJump
            }
        }
        Fc::CondBranch => BbKind::Normal,
        _ => BbKind::Normal,
    }
}

// ── Tests ──────────────────────────────────────────────────────────
//
// We assemble tiny synthetic instruction sequences with
// iced_x86::Decoder + raw byte vectors. The encodings are chosen so
// that every BB shape we care about (linear, if-then, if-then-else,
// while, nested-loop, switch-style indirect, unreachable) has a
// fixed-size fixture.

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_all(bytes: &[u8], ip: u64) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let mut out = Vec::new();
        while d.can_decode() {
            let i = d.decode();
            if i.is_invalid() { break; }
            out.push(i);
        }
        out
    }

    #[test]
    fn linear_block_one_bb() {
        // mov eax, 1
        // mov ebx, 2
        // ret
        // Encoding: B8 01 00 00 00  BB 02 00 00 00  C3
        let bytes = [0xB8, 0x01, 0x00, 0x00, 0x00,
                     0xBB, 0x02, 0x00, 0x00, 0x00,
                     0xC3];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        assert_eq!(cfg.bbs.len(), 1);
        assert_eq!(cfg.bbs[0].kind, BbKind::Ret);
        assert!(cfg.edges.is_empty());
    }

    #[test]
    fn if_then_three_bbs() {
        // 1000: cmp eax, 0          83 F8 00
        // 1003: je 100A             74 05
        // 1005: mov ebx, 1          BB 01 00 00 00
        // 100A: ret                 C3
        let bytes = [0x83, 0xF8, 0x00,        // cmp eax, 0
                     0x74, 0x05,              // je +5 -> 100A
                     0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx, 1
                     0xC3];                   // ret
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        // Expect 3 BBs:
        //   #0 [1000..1005)  cmp + je
        //   #1 [1005..100A)  mov ebx,1     (then-branch fallthrough)
        //   #2 [100A..100B)  ret           (target of je + fallthrough of #1)
        assert_eq!(cfg.bbs.len(), 3, "bbs={:?}", cfg.bbs);
        assert_eq!(cfg.bbs[0].kind, BbKind::Normal);
        assert_eq!(cfg.bbs[2].kind, BbKind::Ret);
        // Edges: 0->2 (JumpCond), 0->1 (Fall), 1->2 (Fall).
        assert!(cfg.edges.iter().any(|e| e.0 == 0 && e.1 == 2 && e.2 == EdgeKind::JumpCond));
        assert!(cfg.edges.iter().any(|e| e.0 == 0 && e.1 == 1 && e.2 == EdgeKind::Fall));
        assert!(cfg.edges.iter().any(|e| e.0 == 1 && e.1 == 2 && e.2 == EdgeKind::Fall));
    }

    #[test]
    fn if_then_else_four_bbs() {
        // 1000: cmp eax, 0
        // 1003: je 100C
        // 1005: mov ebx, 1
        // 100A: jmp 1011
        // 100C: mov ebx, 2
        // 1011: ret
        let bytes = [
            0x83, 0xF8, 0x00,                  // cmp eax, 0
            0x74, 0x07,                         // je +7 -> 100C
            0xBB, 0x01, 0x00, 0x00, 0x00,      // mov ebx, 1
            0xEB, 0x05,                         // jmp +5 -> 1011
            0xBB, 0x02, 0x00, 0x00, 0x00,      // mov ebx, 2
            0xC3,                               // ret
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        assert_eq!(cfg.bbs.len(), 4, "bbs={:?}", cfg.bbs);
        // Verify: 0->2 (Cond), 0->1 (Fall), 1->3 (Uncond), 2->3 (Fall).
        assert!(cfg.edges.iter().any(|e| e.0 == 0 && e.1 == 2 && e.2 == EdgeKind::JumpCond));
        assert!(cfg.edges.iter().any(|e| e.0 == 0 && e.1 == 1 && e.2 == EdgeKind::Fall));
        assert!(cfg.edges.iter().any(|e| e.0 == 1 && e.1 == 3 && e.2 == EdgeKind::JumpUncond));
        assert!(cfg.edges.iter().any(|e| e.0 == 2 && e.1 == 3 && e.2 == EdgeKind::Fall));
    }

    #[test]
    fn while_loop_back_edge() {
        // 1000: xor ecx, ecx
        // 1002: cmp ecx, 10
        // 1005: jge 100D
        // 1007: inc ecx
        // 1009: jmp 1002
        // 100B: ret  (placed at 100D below)
        // Layout reflowed below to avoid hand-tweaking offsets:
        //
        // 1000: 31 C9                  xor ecx, ecx
        // 1002: 83 F9 0A               cmp ecx, 10
        // 1005: 7D 04                  jge +4  -> 100B
        // 1007: FF C1                  inc ecx
        // 1009: EB F7                  jmp -9  -> 1002
        // 100B: C3                     ret
        let bytes = [
            0x31, 0xC9,
            0x83, 0xF9, 0x0A,
            0x7D, 0x04,
            0xFF, 0xC1,
            0xEB, 0xF7,
            0xC3,
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        // BBs:
        //   #0 [1000..1002)  xor          (Fall to header)
        //   #1 [1002..1007)  cmp+jge      (header)
        //   #2 [1007..100B)  inc+jmp      (latch -> back-edge to #1)
        //   #3 [100B..100C)  ret
        assert_eq!(cfg.bbs.len(), 4, "bbs={:?}", cfg.bbs);
        // Back-edge: latch (#2) jumps to header (#1).
        assert!(cfg.edges.iter().any(|e| e.0 == 2 && e.1 == 1 && e.2 == EdgeKind::JumpUncond),
                "expected back-edge 2->1, got {:?}", cfg.edges);
        // Exit edge: header (#1) Jcc to ret (#3).
        assert!(cfg.edges.iter().any(|e| e.0 == 1 && e.1 == 3 && e.2 == EdgeKind::JumpCond));
    }

    #[test]
    fn nested_loop_two_back_edges() {
        // outer:
        //   inner_setup
        //   inner_back_edge -> inner header
        //   outer_back_edge -> outer header
        //
        // 1000: 31 C9               xor ecx, ecx           ; init outer
        // 1002: 83 F9 03            cmp ecx, 3             ; outer header
        // 1005: 7D 0E               jge +14 -> 1015 (exit)
        // 1007: 31 D2               xor edx, edx           ; init inner
        // 1009: 83 FA 03            cmp edx, 3             ; inner header
        // 100C: 7D 03               jge +3 -> 1011 (after inner)
        // 100E: FF C2               inc edx
        // 1010: EB F7               jmp -9 -> 1009 (inner back-edge) -> WAIT, 0x1010+2-9 = 0x1009 ✓
        // 1012: FF C1               inc ecx                ; after inner
        // 1014: EB EC               jmp -20 -> 1002 (outer back-edge) -> 0x1014+2-20 = 0x1002 ✓
        // Wait — the ENC for jmp +0xEC (sign-extended -20) is EB EC ⇒ next_ip=0x1014+2=0x1016, +(-20)=0x1002 ✓
        // 1016: C3                  ret
        //
        // Re-layout: I'll just place ret at 1011 to keep the inner-after fall flow simple.
        // Actually the flow above has inner-after at 1011 and the outer-back-edge at 1013.
        //
        // Let me rewrite cleanly with explicit byte offsets:
        //
        //  off  bytes              ASM
        //  +00  31 C9              xor ecx, ecx
        //  +02  83 F9 03           cmp ecx, 3
        //  +05  7D 0C              jge +12  -> +0x13 = 1013
        //  +07  31 D2              xor edx, edx
        //  +09  83 FA 03           cmp edx, 3
        //  +0C  7D 03              jge +3   -> +0x11 = 1011
        //  +0E  FF C2              inc edx
        //  +10  EB F7              jmp -9   -> +0x09 = 1009  (inner back-edge)
        //  +12  FF C1              inc ecx
        //  Wait — 0x12 doesn't equal the 0x11 the inner Jcc points to.
        //
        // The simpler correct layout:
        //
        //  +00  31 C9              xor ecx, ecx
        //  +02  83 F9 03           cmp ecx, 3                 ; OUTER HDR
        //  +05  7D 0B              jge +11  -> +0x12 = 1012   ; exit outer
        //  +07  31 D2              xor edx, edx
        //  +09  83 FA 03           cmp edx, 3                 ; INNER HDR
        //  +0C  7D 02              jge +2   -> +0x10 = 1010   ; exit inner (to outer-latch)
        //  +0E  EB F9              jmp -7   -> +0x09 = 1009   ; inner back-edge
        //  +10  EB F0              jmp -16  -> +0x02 = 1002   ; outer back-edge (latch is 1-instruction long)
        //  +12  C3                 ret
        let bytes = [
            0x31, 0xC9,                     // +00 xor ecx, ecx
            0x83, 0xF9, 0x03,               // +02 cmp ecx, 3
            0x7D, 0x0B,                     // +05 jge +11 -> +0x12
            0x31, 0xD2,                     // +07 xor edx, edx
            0x83, 0xFA, 0x03,               // +09 cmp edx, 3
            0x7D, 0x02,                     // +0C jge +2 -> +0x10
            0xEB, 0xF9,                     // +0E jmp -7 -> +0x09
            0xEB, 0xF0,                     // +10 jmp -16 -> +0x02
            0xC3,                           // +12 ret
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        // Two back-edges: inner 1009 and outer 1002 — verify by VA.
        let back_edges_to_outer = cfg.edges.iter().filter(|(s, d, _)| {
            cfg.bbs[*s].start > cfg.bbs[*d].start && cfg.bbs[*d].start == 0x1002
        }).count();
        let back_edges_to_inner = cfg.edges.iter().filter(|(s, d, _)| {
            cfg.bbs[*s].start > cfg.bbs[*d].start && cfg.bbs[*d].start == 0x1009
        }).count();
        assert_eq!(back_edges_to_outer, 1, "outer back-edge missing; edges={:?}", cfg.edges);
        assert_eq!(back_edges_to_inner, 1, "inner back-edge missing; edges={:?}", cfg.edges);
    }

    #[test]
    fn switch_indirect_jump_classified_as_indjump() {
        // 1000: 48 8D 15 00 00 00 00     lea rdx, [rip+0]
        // 1007: FF E2                    jmp rdx
        let bytes = [
            0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE2,
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        assert_eq!(cfg.bbs.len(), 1);
        assert_eq!(cfg.bbs[0].kind, BbKind::IndJump);
        // No outgoing edges — caller is expected to splice in
        // jump-table successors.
        assert!(cfg.edges.is_empty(), "edges={:?}", cfg.edges);
    }

    #[test]
    fn unreachable_block_after_uncond_jump_still_emitted() {
        // 1000: EB 02              jmp +2 -> 1004
        // 1002: 90                 nop      (unreachable)
        // 1003: 90                 nop      (unreachable)
        // 1004: C3                 ret
        let bytes = [0xEB, 0x02, 0x90, 0x90, 0xC3];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        // 3 BBs: [1000..1002) jmp, [1002..1004) nops, [1004..1005) ret.
        assert_eq!(cfg.bbs.len(), 3, "bbs={:?}", cfg.bbs);
        // Only edge: 0 -> 2 (JumpUncond). The nops block (#1) has
        // no incoming edge — that's how callers detect dead code.
        assert!(cfg.edges.iter().any(|e| e.0 == 0 && e.1 == 2 && e.2 == EdgeKind::JumpUncond));
        let preds_of_1 = cfg.preds(1);
        assert!(preds_of_1.is_empty(), "preds of #1 should be empty (unreachable), got {:?}", preds_of_1);
    }

    #[test]
    fn block_at_va_lookup() {
        // Re-use the if-then-else fixture and verify VA → BB index.
        let bytes = [
            0x83, 0xF8, 0x00,
            0x74, 0x07,
            0xBB, 0x01, 0x00, 0x00, 0x00,
            0xEB, 0x05,
            0xBB, 0x02, 0x00, 0x00, 0x00,
            0xC3,
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        assert_eq!(cfg.block_at(0x1000), Some(0));
        assert_eq!(cfg.block_at(0x1003), Some(0)); // mid-block
        assert_eq!(cfg.block_at(0x1005), Some(1));
        assert_eq!(cfg.block_at(0x1011), Some(3));
        assert_eq!(cfg.block_at(0x9999), None);
    }
}
