// ── Natural-loop discovery + SCC helper ──────────────────────────
//
// Natural loop (textbook def): an edge `tail -> header` where
// `header` dominates `tail` is a **back-edge**. The natural loop
// of that back-edge is the set of nodes that can reach `tail`
// without going through `header`, plus `header` itself.
//
// We build the loop body by reverse BFS from `tail` over the
// CFG's predecessor relation, stopping at `header`.
//
// SCC helper is a direct passthrough to `petgraph::algo::tarjan_scc`
// — useful for cyclomatic-complexity / loop-count callers that
// don't care about the dominator-based loop structure.

use super::build::BbCfg;
use super::dominators::{graphmap, DomTree};
use petgraph::algo::tarjan_scc;
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct Loop {
    /// Block index of the loop header (target of the back-edge).
    pub header: usize,
    /// Block indices in the loop body, including `header`.
    pub body: Vec<usize>,
    /// One or more back-edges (tail -> header). A header may have
    /// multiple latches; we group them under the same Loop.
    pub back_edges: Vec<(usize, usize)>,
}

/// Discover all natural loops. One Loop per distinct header — if
/// multiple back-edges target the same header, we union their
/// loop bodies (textbook merge rule).
pub fn natural_loops(cfg: &BbCfg, doms: &DomTree<usize>) -> Vec<Loop> {
    // 1. Identify back-edges: (tail -> header) where header
    //    dominates tail. petgraph's Dominators::dominators() yields
    //    every dominator of a node; checking membership of `header`
    //    in `dominators(tail)` is the textbook test.
    let mut back_edges: Vec<(usize, usize)> = Vec::new();
    for (s, d, _) in &cfg.edges {
        if let Some(mut chain) = doms.dominators(*s) {
            if chain.any(|x| x == *d) {
                back_edges.push((*s, *d));
            }
        }
    }

    // 2. Group back-edges by header.
    let mut by_header: std::collections::BTreeMap<usize, Vec<(usize, usize)>>
        = std::collections::BTreeMap::new();
    for be in &back_edges {
        by_header.entry(be.1).or_default().push(*be);
    }

    // 3. For each header, compute the union of natural-loop bodies.
    let mut loops = Vec::with_capacity(by_header.len());
    for (header, edges) in by_header {
        let mut body: HashSet<usize> = HashSet::new();
        body.insert(header);

        for (tail, _) in &edges {
            // BFS backwards from tail over predecessor edges,
            // stopping at header.
            let mut stack: VecDeque<usize> = VecDeque::new();
            if *tail != header {
                body.insert(*tail);
                stack.push_back(*tail);
            }
            while let Some(n) = stack.pop_front() {
                for (p, _) in cfg.preds(n) {
                    if !body.contains(&p) {
                        body.insert(p);
                        stack.push_back(p);
                    }
                }
            }
        }

        let mut body_vec: Vec<usize> = body.into_iter().collect();
        body_vec.sort_unstable();
        loops.push(Loop { header, body: body_vec, back_edges: edges });
    }

    loops
}

/// Strongly-connected components, in petgraph's reverse-topological
/// order. A trivial single-node SCC with no self-loop is included
/// (one node per such SCC) — callers wanting "real" loops should
/// either use `natural_loops` or filter SCCs by length>1 || self-loop.
pub fn sccs(cfg: &BbCfg) -> Vec<Vec<usize>> {
    let g = graphmap(cfg);
    tarjan_scc(&g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build::build_cfg;
    use crate::cfg::dominators::dominators;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_all(bytes: &[u8], ip: u64) -> Vec<iced_x86::Instruction> {
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
    fn while_loop_detected() {
        // While loop fixture (matches build.rs::while_loop_back_edge).
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
        let doms = dominators(&cfg, 0);
        let loops = natural_loops(&cfg, &doms);
        assert_eq!(loops.len(), 1);
        let header_va = cfg.bbs[loops[0].header].start;
        assert_eq!(header_va, 0x1002);
        // Body should contain header (#1) and latch (#2) — two BBs.
        assert_eq!(loops[0].body.len(), 2);
    }

    #[test]
    fn nested_loop_two_loops() {
        // Same fixture as build.rs::nested_loop_two_back_edges.
        let bytes = [
            0x31, 0xC9,
            0x83, 0xF9, 0x03,
            0x7D, 0x0B,
            0x31, 0xD2,
            0x83, 0xFA, 0x03,
            0x7D, 0x02,
            0xEB, 0xF9,
            0xEB, 0xF0,
            0xC3,
        ];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        let doms = dominators(&cfg, 0);
        let loops = natural_loops(&cfg, &doms);
        assert_eq!(loops.len(), 2, "expected outer+inner loops, got {:?}", loops);
        // Outer header is at 0x1002, inner header at 0x1009.
        let headers_vas: HashSet<u64> = loops.iter().map(|l| cfg.bbs[l.header].start).collect();
        assert!(headers_vas.contains(&0x1002));
        assert!(headers_vas.contains(&0x1009));
    }

    #[test]
    fn linear_function_no_loops() {
        // Just a ret — no back-edges.
        let bytes = [0xC3];
        let insns = decode_all(&bytes, 0x1000);
        let cfg = build_cfg(&insns);
        let doms = dominators(&cfg, 0);
        assert!(natural_loops(&cfg, &doms).is_empty());
    }

    #[test]
    fn scc_count_includes_loop() {
        // While loop: SCC of size 2 = {header, latch}, plus the
        // surrounding BBs each in their own trivial SCC.
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
        let scc_list = sccs(&cfg);
        let big_sccs: Vec<_> = scc_list.iter().filter(|s| s.len() > 1).collect();
        assert_eq!(big_sccs.len(), 1, "expected one non-trivial SCC; got {:?}", scc_list);
        assert_eq!(big_sccs[0].len(), 2);
    }
}
