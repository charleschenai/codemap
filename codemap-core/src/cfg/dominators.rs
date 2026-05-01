// ── Dominator tree wrapper ────────────────────────────────────────
//
// Thin shim over `petgraph::algo::dominators::simple_fast`. We
// translate the BbCfg into a `DiGraphMap<usize, ()>` (BB index is
// already a stable small int — perfect node id), call the algorithm,
// and return the petgraph `Dominators<usize>` for callers to query.
//
// We expose `petgraph::algo::dominators::Dominators` re-export so
// downstream detectors don't need to add petgraph to their own
// Cargo.toml.

use super::build::BbCfg;
use petgraph::algo::dominators::{self, Dominators};
use petgraph::graphmap::DiGraphMap;

pub use petgraph::algo::dominators::Dominators as DomTree;

/// Build a `DiGraphMap` view of the CFG's edges. We ignore EdgeKind
/// for dominator purposes — every edge contributes equally to
/// reachability.
pub(crate) fn graphmap(cfg: &BbCfg) -> DiGraphMap<usize, ()> {
    let mut g = DiGraphMap::<usize, ()>::new();
    for i in 0..cfg.bbs.len() {
        g.add_node(i);
    }
    for (s, d, _) in &cfg.edges {
        g.add_edge(*s, *d, ());
    }
    g
}

/// Compute the dominator tree rooted at `entry`. Returns
/// `petgraph`'s `Dominators<usize>` for direct use with
/// `.immediate_dominator(n)`, `.dominators(n)`, `.strict_dominators(n)`.
///
/// Out-of-range entry returns an empty dominator set (matches
/// petgraph's behaviour on disconnected roots).
pub fn dominators(cfg: &BbCfg, entry: usize) -> Dominators<usize> {
    let g = graphmap(cfg);
    dominators::simple_fast(&g, entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build::build_cfg;
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
    fn diamond_idom_is_entry() {
        // if-then-else: entry = #0, then = #1, else = #2, join = #3.
        // idom(#1) = #0, idom(#2) = #0, idom(#3) = #0.
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
        let doms = dominators(&cfg, 0);
        for i in 1..cfg.bbs.len() {
            assert_eq!(doms.immediate_dominator(i), Some(0),
                       "idom(#{}) expected to be #0", i);
        }
    }

    #[test]
    fn loop_header_dominates_latch() {
        // While loop: header = #1, latch = #2.
        // Latch's idom must be the header (only reachable through it).
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
        // Find header (#1) and latch (#2) by VA.
        let header = cfg.bbs.iter().position(|b| b.start == 0x1002).unwrap();
        let latch = cfg.bbs.iter().position(|b| b.start == 0x1007).unwrap();
        assert_eq!(doms.immediate_dominator(latch), Some(header));
    }
}
