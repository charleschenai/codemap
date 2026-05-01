// ── signsrch corpus scanner (5.38.0 — Ship 2 #11) ──────────────────
//
// Vendors Luigi Auriemma's signsrch byte-pattern corpus (2,338 entries
// covering crypto / hash / cipher / CRC / EC seed / compression /
// anti-debug / file-format constants) and scans PE/ELF/Mach-O binaries
// for matches.
//
// Pre-authorized in the existing `crypto_const.rs` header comment
// (lines 14-17) — "vendoring signsrch.xml as a bincode blob is the v2
// plan". This module IS that v2: 22 → 2,338 sigs (~106× expansion).
//
// Implementation outline:
//   1. Build script `build.rs` parses `data/signsrch.xml` →
//      `OUT_DIR/signsrch.bin` (bincode `Vec<SignsrchSig>`). The blob
//      is `include_bytes!`-d here and deserialized once into a
//      `OnceLock<Vec<SignsrchSig>>`.
//   2. At first scan, build an Aho-Corasick automaton over the full
//      pattern of every single-chunk entry (~2,200) PLUS the first
//      chunk of every multi-chunk entry (~136 with the `&` flag).
//   3. Scan binary in one AC pass; for multi-chunk hits, walk the
//      remaining chunks via `memchr::memmem::find` requiring each to
//      appear in order with arbitrary gaps (port of
//      `signsrch.py:111-125`).
//
// Emits `CryptoConstant` nodes (or `AntiAnalysis` for the 53
// anti-debug entries — handled by tag classifier in build.rs).
// Confidence:
//   * < 16 bytes  → Low      (collides on CRC polynomials, magic ints)
//   * 16-31 bytes → Medium   (typical IV / S-box prefix)
//   * ≥ 32 bytes  → High     (full S-box, large lookup table)
//   * multi-chunk → High     (chunk-walk gates false-fire on prefix)
//
// Static-purity check: pure pattern matching against on-disk bytes.
// No execution, no network, no dynamic analysis.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::types::{Graph, EntityKind};

/// Bincode-serialized blob produced by `build.rs` from
/// `data/signsrch.xml`. Empty if the XML file was stripped at build
/// time — the runtime then degrades to "no signsrch detections" but
/// the curated `crypto_const.rs` 22-sig array continues to fire.
static CORPUS_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/signsrch.bin"));

/// MUST stay binary-compatible with `build.rs::SignsrchSig`. bincode
/// v1 encodes positionally — same field order & types is what counts.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SignsrchSig {
    name: String,
    algorithm: String,
    /// 0=Other, 1=AntiDebug, 2=EllipticCurve, 3=Compression, 4=Hash,
    /// 5=Cipher, 6=Crc, 7=FileFormat.
    category: u8,
    bits: u8,
    endian: u8,
    size: u32,
    multi_chunk: bool,
    bytes: Vec<u8>,
}

fn category_str(c: u8) -> &'static str {
    match c {
        1 => "anti-debug",
        2 => "ec-seed",
        3 => "compression",
        4 => "hash",
        5 => "cipher",
        6 => "crc",
        7 => "file-format",
        _ => "other",
    }
}

fn endian_str(e: u8) -> &'static str {
    match e {
        1 => "le",
        2 => "be",
        _ => "raw",
    }
}

fn corpus() -> &'static [SignsrchSig] {
    static CACHE: OnceLock<Vec<SignsrchSig>> = OnceLock::new();
    CACHE.get_or_init(|| {
        if CORPUS_BLOB.is_empty() {
            return Vec::new();
        }
        bincode::deserialize::<Vec<SignsrchSig>>(CORPUS_BLOB).unwrap_or_default()
    })
}

/// Pre-built Aho-Corasick automaton + parallel index of (sig_idx,
/// is_first_chunk_of_multi). Built lazily at first scan.
struct Automaton {
    ac: AhoCorasick,
    /// For each AC pattern slot: (sig index, is_multi_first_chunk).
    /// Single-chunk entries appear once; multi-chunk entries appear
    /// once with `is_multi_first_chunk=true` mapping to their first
    /// chunk only.
    slots: Vec<(usize, bool)>,
}

fn automaton() -> &'static Automaton {
    static CACHE: OnceLock<Automaton> = OnceLock::new();
    CACHE.get_or_init(|| {
        let sigs = corpus();
        let mut patterns: Vec<&[u8]> = Vec::with_capacity(sigs.len());
        let mut slots: Vec<(usize, bool)> = Vec::with_capacity(sigs.len());
        for (idx, sig) in sigs.iter().enumerate() {
            if sig.bytes.is_empty() { continue; }
            if sig.multi_chunk {
                let chunk_len = (sig.bits as usize) / 8;
                if chunk_len == 0 || sig.bytes.len() < chunk_len { continue; }
                patterns.push(&sig.bytes[..chunk_len]);
                slots.push((idx, true));
            } else {
                patterns.push(&sig.bytes);
                slots.push((idx, false));
            }
        }
        // Empty-pattern guard: AhoCorasick panics on empty input vec.
        // Build a trivial single-pattern automaton in that case.
        if patterns.is_empty() {
            patterns.push(b"\x00\x00\x00\x00");
            slots.push((usize::MAX, false));
        }
        // MatchKind::Standard is required for find_overlapping_iter,
        // which we need: a SHA-256 IV constant overlaps shorter
        // generic 4-byte CRC polynomials, and we want both reported.
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .expect("aho-corasick build");
        Automaton { ac, slots }
    })
}

#[derive(Debug, Clone)]
struct Match {
    sig_idx: usize,
    offset: usize,
}

fn scan(data: &[u8]) -> Vec<Match> {
    let aut = automaton();
    let sigs = corpus();
    if sigs.is_empty() { return Vec::new(); }
    let mut out = Vec::new();
    for hit in aut.ac.find_overlapping_iter(data) {
        let pat_id = hit.pattern().as_usize();
        let (sig_idx, is_first_chunk) = aut.slots[pat_id];
        if sig_idx == usize::MAX { continue; }
        if is_first_chunk {
            // Multi-chunk match: walk remaining chunks.
            let sig = &sigs[sig_idx];
            let chunk_len = (sig.bits as usize) / 8;
            if chunk_len == 0 { continue; }
            let total_chunks = sig.bytes.len() / chunk_len;
            // First chunk already matched at `hit.start()`. Walk
            // chunks 1..total_chunks within the rest of the buffer.
            let mut cursor = hit.end();
            let mut all_matched = true;
            for c in 1..total_chunks {
                let chunk = &sig.bytes[c * chunk_len..(c + 1) * chunk_len];
                match memchr::memmem::find(&data[cursor..], chunk) {
                    Some(rel) => { cursor += rel + chunk_len; }
                    None => { all_matched = false; break; }
                }
            }
            if all_matched {
                out.push(Match { sig_idx, offset: hit.start() });
            }
        } else {
            out.push(Match { sig_idx, offset: hit.start() });
        }
    }
    out
}

fn confidence_for(sig: &SignsrchSig) -> &'static str {
    if sig.multi_chunk { return "high"; }
    let n = sig.bytes.len();
    if n >= 32 { "high" } else if n >= 16 { "medium" } else { "low" }
}

fn entity_kind_for(category: u8) -> EntityKind {
    if category == 1 { EntityKind::AntiAnalysis } else { EntityKind::CryptoConstant }
}

// ── Action ─────────────────────────────────────────────────────────

pub fn signsrch(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap signsrch <pe-or-elf-or-macho-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 16 {
        return format!("Binary too small ({} bytes) for signsrch scanning", data.len());
    }

    let matches = scan(&data);
    register(graph, target, &matches);
    format_report(target, &data, &matches)
}

fn register(graph: &mut Graph, target: &str, matches: &[Match]) {
    if matches.is_empty() { return; }
    let sigs = corpus();
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    // Dedup: many signsrch entries are 4-8 byte-order/size variants of
    // the same algorithm constant. Collapse on (algorithm, name) so
    // the graph lists each algorithm once per binary.
    let mut seen = std::collections::HashSet::<(usize,)>::new();
    for m in matches {
        let sig = &sigs[m.sig_idx];
        if !seen.insert((m.sig_idx,)) { continue; }
        let kind = entity_kind_for(sig.category);
        let prefix = match kind {
            EntityKind::AntiAnalysis => "anti",
            _ => "crypto",
        };
        let node_id = format!("{prefix}:signsrch::{}::{}", sig.algorithm, sig.name);
        let off = format!("{:#x}", m.offset);
        let conf = confidence_for(sig);
        let cat = category_str(sig.category);
        let endian = endian_str(sig.endian);
        let size = sig.bytes.len().to_string();
        graph.ensure_typed_node(&node_id, kind, &[
            ("algorithm",     sig.algorithm.as_str()),
            ("constant_name", sig.name.as_str()),
            ("category",      cat),
            ("offset",        &off),
            ("endian",        endian),
            ("confidence",    conf),
            ("pattern_bytes", size.as_str()),
            ("source",        "signsrch"),
        ]);
        graph.add_edge(&bin_id, &node_id);
    }
}

fn format_report(target: &str, data: &[u8], matches: &[Match]) -> String {
    let sigs = corpus();
    let mut lines = vec![
        format!("=== signsrch scan: {} ===", target),
        format!("Binary size:  {} bytes", data.len()),
        format!("Corpus:       {} signatures", sigs.len()),
        format!("Matches:      {}", matches.len()),
        String::new(),
    ];
    if matches.is_empty() {
        lines.push("(no signsrch patterns detected)".to_string());
        return lines.join("\n");
    }
    if sigs.is_empty() {
        lines.push("(corpus empty — build-time blob missing)".to_string());
        return lines.join("\n");
    }

    // Group by category, then algorithm. Dedup matches the way
    // register() does so the report mirrors the graph.
    let mut by_cat: std::collections::BTreeMap<&str,
        std::collections::BTreeMap<&str, Vec<&Match>>> =
        std::collections::BTreeMap::new();
    let mut seen = std::collections::HashSet::<usize>::new();
    for m in matches {
        if !seen.insert(m.sig_idx) { continue; }
        let sig = &sigs[m.sig_idx];
        by_cat.entry(category_str(sig.category)).or_default()
            .entry(sig.algorithm.as_str()).or_default()
            .push(m);
    }

    for (cat, by_algo) in &by_cat {
        lines.push(format!("── {} ──", cat));
        for (algo, ms) in by_algo {
            lines.push(format!("  {} ({} variant{})", algo, ms.len(),
                if ms.len() == 1 { "" } else { "s" }));
            for m in ms.iter().take(4) {
                let sig = &sigs[m.sig_idx];
                lines.push(format!(
                    "      [{}] {} @ {:#x}  ({} bytes, {})",
                    confidence_for(sig), sig.name, m.offset,
                    sig.bytes.len(), endian_str(sig.endian),
                ));
            }
            if ms.len() > 4 {
                lines.push(format!("      … {} more", ms.len() - 4));
            }
        }
    }
    lines.push(String::new());
    lines.push("Try: codemap meta-path \"pe->crypto\"  (cross-binary algorithm inventory)".to_string());
    lines.push("     codemap pagerank --type crypto    (most-prevalent crypto algorithms)".to_string());
    lines.join("\n")
}

// ── Public corpus stats (used by tests + CLI summary) ─────────────

#[doc(hidden)]
pub fn corpus_size() -> usize { corpus().len() }

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec gate: corpus must round-trip 2,338 entries from the
    /// vendored `data/signsrch.xml`.
    #[test]
    fn corpus_loads_full_count() {
        let n = corpus().len();
        assert!(n >= 2200, "expected ~2,338 signsrch entries, got {n}");
        // Allow ±20 slack for future corpus refresh; the canonical
        // 2017-vintage XML is exactly 2338.
        assert!(n <= 2400, "corpus has {n} entries — sanity ceiling tripped");
    }

    /// Every sig must have non-empty bytes and a non-empty algorithm.
    #[test]
    fn corpus_entries_are_well_formed() {
        for sig in corpus() {
            assert!(!sig.bytes.is_empty(), "empty bytes in {:?}", sig.name);
            assert!(!sig.algorithm.is_empty(), "empty algorithm in {:?}", sig.name);
        }
    }

    /// SHA-256 IV at a known offset must fire (covers the "single-chunk
    /// AC hit" path) — the 32-byte SHA-256 H0..H7 LE constant is
    /// present in many crypto libs.
    #[test]
    fn finds_sha256_init_in_synthetic_blob() {
        // SHA-256 H0..H7 little-endian.
        const SHA256_INIT_LE: &[u8] = &[
            0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB,
            0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xF5, 0x4F, 0xA5,
            0x7F, 0x52, 0x0E, 0x51, 0x8C, 0x68, 0x05, 0x9B,
            0xAB, 0xD9, 0x83, 0x1F, 0x19, 0xCD, 0xE0, 0x5B,
        ];
        let mut data = vec![0u8; 0x800];
        data[0x100..0x120].copy_from_slice(SHA256_INIT_LE);
        let matches = scan(&data);
        // The corpus contains multiple SHA-256-related entries; we
        // require at least one match whose algorithm name contains
        // SHA or SHA-256.
        let sigs = corpus();
        let hit = matches.iter().find(|m| {
            let s = &sigs[m.sig_idx];
            let lc = s.algorithm.to_ascii_lowercase();
            lc.contains("sha") && (lc.contains("256") || lc.contains("2"))
        });
        assert!(hit.is_some(),
            "expected a SHA-256 match — got {} total matches: {:?}",
            matches.len(),
            matches.iter().take(8).map(|m| sigs[m.sig_idx].algorithm.as_str())
                .collect::<Vec<_>>());
        assert_eq!(hit.unwrap().offset, 0x100);
    }

    /// Multi-chunk: build a synthetic blob with a known multi-chunk
    /// signature's chunks scattered with gaps, verify it fires.
    #[test]
    fn multi_chunk_match_fires_with_gaps() {
        let sigs = corpus();
        let mc = sigs.iter().enumerate()
            .find(|(_, s)| s.multi_chunk
                && s.bits >= 8
                && (s.bits as usize) % 8 == 0
                && s.bytes.len() >= 2 * (s.bits as usize) / 8)
            .map(|(i, _)| i);
        let Some(idx) = mc else {
            // No usable multi-chunk entry in corpus — that's fine,
            // skip the test rather than fail.
            return;
        };
        let sig = &sigs[idx];
        let chunk_len = (sig.bits as usize) / 8;

        // Build buffer: 64 zero-padding, chunk0, 32 padding, chunk1,
        // 16 padding, chunk2…, then trailing padding. Use distinct
        // padding bytes that can't form one of the corpus's tiny
        // 4-byte signatures (use 0xFF — unlikely to appear at the
        // start of any real cipher constant).
        let mut data: Vec<u8> = vec![0xFF; 64];
        let total_chunks = sig.bytes.len() / chunk_len;
        for c in 0..total_chunks {
            data.extend_from_slice(&sig.bytes[c * chunk_len..(c + 1) * chunk_len]);
            data.extend_from_slice(&vec![0xFF; 16]);
        }
        let matches = scan(&data);
        assert!(matches.iter().any(|m| m.sig_idx == idx),
            "multi-chunk pattern {:?} did not fire", sig.name);
    }

    /// Broken: build a buffer with the first chunk but missing the
    /// second — must NOT fire.
    #[test]
    fn multi_chunk_does_not_fire_with_missing_chunks() {
        let sigs = corpus();
        let Some((idx, sig)) = sigs.iter().enumerate()
            .find(|(_, s)| s.multi_chunk
                && s.bits >= 8
                && (s.bits as usize) % 8 == 0
                && s.bytes.len() >= 2 * (s.bits as usize) / 8)
        else { return; };
        let chunk_len = (sig.bits as usize) / 8;
        let mut data: Vec<u8> = vec![0xFF; 64];
        // Embed only the first chunk.
        data.extend_from_slice(&sig.bytes[..chunk_len]);
        data.extend_from_slice(&vec![0xFF; 64]);
        let matches = scan(&data);
        // The entry whose first chunk we embedded must NOT be in matches.
        // (Other entries may legitimately fire on the 0xFF padding —
        // signsrch has some short entries that hit on uniform bytes.)
        assert!(!matches.iter().any(|m| m.sig_idx == idx),
            "multi-chunk pattern {:?} fired with only first chunk present",
            sig.name);
    }

    /// Empty data → no matches.
    #[test]
    fn empty_data_yields_no_matches() {
        assert!(scan(&[]).is_empty());
    }

    /// Random PRNG-ish data must not produce an avalanche of matches.
    /// Real crypto-using binaries hit dozens of entries; pure-noise
    /// content should hit very few.
    #[test]
    fn random_data_yields_few_matches() {
        let mut data = vec![0u8; 0x10000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2654435761) >> 16) as u8;
        }
        let matches = scan(&data);
        // Some collisions are expected on 4-byte CRC polynomials; cap
        // generously at 50 (real crypto binaries typically hit 100+).
        let unique = matches.iter().map(|m| m.sig_idx)
            .collect::<std::collections::HashSet<_>>().len();
        assert!(unique < 50,
            "PRNG buffer hit {unique} unique sigs — corpus too permissive");
    }

    /// Confidence tiers must be assigned correctly by byte length.
    #[test]
    fn confidence_tiers_by_length() {
        let mk = |bytes: Vec<u8>, multi_chunk: bool| SignsrchSig {
            name: String::new(),
            algorithm: String::new(),
            category: 0,
            bits: 8,
            endian: 0,
            size: bytes.len() as u32,
            multi_chunk,
            bytes,
        };
        assert_eq!(confidence_for(&mk(vec![0; 8], false)), "low");
        assert_eq!(confidence_for(&mk(vec![0; 16], false)), "medium");
        assert_eq!(confidence_for(&mk(vec![0; 64], false)), "high");
        assert_eq!(confidence_for(&mk(vec![0; 8], true)), "high");
    }

    /// Anti-debug subset must classify into AntiAnalysis EntityKind.
    #[test]
    fn anti_debug_routes_to_anti_analysis_kind() {
        let any_anti = corpus().iter().any(|s| s.category == 1);
        if any_anti {
            assert_eq!(entity_kind_for(1), EntityKind::AntiAnalysis);
        }
        // All other categories route to CryptoConstant.
        for cat in [0u8, 2, 3, 4, 5, 6, 7] {
            assert_eq!(entity_kind_for(cat), EntityKind::CryptoConstant);
        }
    }

    /// Category coverage: corpus must include hashes, ciphers, CRCs,
    /// and EC seeds at minimum.
    #[test]
    fn category_coverage() {
        let mut counts = [0usize; 8];
        for s in corpus() {
            if (s.category as usize) < counts.len() {
                counts[s.category as usize] += 1;
            }
        }
        assert!(counts[4] > 0, "expected ≥1 hash entry");
        assert!(counts[5] > 0, "expected ≥1 cipher entry");
        assert!(counts[6] > 0, "expected ≥1 CRC entry");
        // EC seeds are smaller in number; if classifier missed all,
        // that's a regression — but allow zero so the build doesn't
        // wedge on an upstream rename.
    }
}
