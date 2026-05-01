// ── Basic-Block Control-Flow Graph ────────────────────────────────
//
// Foundational infrastructure for v2 detectors that need real BB
// boundaries + dominator trees + natural-loop discovery rather than
// scanning a flat instruction stream. Today `decode_functions` in
// disasm.rs produces a linear instruction list; this module turns
// such a list into a `BbCfg` and offers thin wrappers over
// petgraph for dominators / SCC / loops.
//
// Vocabulary follows Quokka's Block.BlockType / Edge.EdgeType
// taxonomy (see /tmp/codemap-research-results/08-quokka/summary.md).
//
// Public surface (re-exported here for ergonomics):
//
//   build_cfg(insns)                -> BbCfg
//   dominators(cfg, entry)          -> Dominators<usize>
//   natural_loops(cfg, doms)        -> Vec<Loop>
//   sccs(cfg)                       -> Vec<Vec<usize>>
//
// Downstream consumers (CFF v2, opaque-pred v2, decoder-find,
// duplicate-subgraphs) only need the BB indices + edges; they
// shouldn't have to learn petgraph's NodeIndex types.

pub mod build;
pub mod dominators;
pub mod loops;

pub use build::{Bb, BbCfg, BbKind, EdgeKind, build_cfg};
pub use dominators::dominators;
pub use loops::{Loop, natural_loops, sccs};
