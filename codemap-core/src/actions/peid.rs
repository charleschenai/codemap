// ── PEiD Packer / Protector Identifier (Ship 5 #15/#04/#07) ───────
//
// Ports the Detect-It-Easy PEiD signature corpus (4,445 wildcarded
// byte signatures across packer/protector/installer/compiler/joiner/
// SFX/file_format/overlay/protection categories) into a native
// scanner. Three independent research panes (04-yara-rules, 07-
// unprotect, 15-die) flagged this as the highest-value PE-ID gap.
//
// Corpus license: PEiD's userdb has been a public-domain user-
// contributed file for ~20 years. DiE redistributes the consolidated
// corpus under MIT and ships pre-categorised splits at
// `peid_rules/PE/{packer,protector,...}.userdb.txt` — we vendor those
// directly under `codemap-core/data/peid/`.
//
// The PEiD `userdb.txt` format is a flat INI-like:
//
//     [Detection name -> author/version]
//     signature = HH HH ?? HH HH HH ?? HH ...
//     ep_only = (true|false)
//
// Pattern-byte tokens we accept:
//   * `HH`         — exact byte (two hex digits)
//   * `??`         — single-byte wildcard (any byte)
//   * `H?` / `?H`  — half-byte wildcard (one nibble specified)
//   * `J1` / `J2`  — 1- or 2-byte wildcard run (PEiD jump-tag relic;
//   * `J3`           PEiD treated J3 as a 4-byte relative jump operand)
// Anything else aborts the signature with no error — the corpus has
// a few entries with junk continuation lines that we silently skip
// rather than poisoning the catalogue.
//
// Matching strategy:
//   * `ep_only = true` (~88% of the corpus) — match the pattern at
//     the binary's entry-point file offset (one comparison per sig).
//   * `ep_only = false` — Aho-Corasick over each pattern's longest
//     run of exact bytes (its "anchor literal"). Each anchor hit
//     drives one wildcard-aware verification of the full pattern.
//     Patterns with anchors shorter than 3 bytes are skipped here
//     (none in the current corpus; the cap exists to cap AC arity).

use crate::types::{Graph, EntityKind};
use std::sync::OnceLock;

// ── Pattern representation ─────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct MaskByte {
    /// Required bits — only meaningful within `mask`.
    value: u8,
    /// 1-bits where `value` matters; 0-bits are wildcards.
    mask: u8,
}

impl MaskByte {
    const WILDCARD: MaskByte = MaskByte { value: 0, mask: 0 };
    const fn exact(b: u8) -> MaskByte { MaskByte { value: b, mask: 0xFF } }
    fn matches(&self, b: u8) -> bool { (b & self.mask) == self.value }
    fn is_exact(&self) -> bool { self.mask == 0xFF }
}

#[derive(Debug)]
struct PeidSig {
    /// Full PEiD label, including author/version tag.
    name: String,
    /// Category from the source userdb file (packer / protector / …).
    category: &'static str,
    /// Source userdb stem (e.g. `packer.userdb.txt`).
    source_db: &'static str,
    /// True when the signature matches only at the binary's EP.
    ep_only: bool,
    /// Wildcard-aware byte pattern.
    pattern: Vec<MaskByte>,
    /// (offset, length) of the longest run of exact bytes inside the
    /// pattern. Used as the AC anchor for the non-EP scan path.
    anchor: Option<(usize, usize)>,
}

// ── Vendored corpus ───────────────────────────────────────────────

const DBS: &[(&str, &str, &str)] = &[
    ("packer",      "packer.userdb.txt",      include_str!("../../data/peid/packer.userdb.txt")),
    ("protector",   "protector.userdb.txt",   include_str!("../../data/peid/protector.userdb.txt")),
    ("protection",  "protection.userdb.txt",  include_str!("../../data/peid/protection.userdb.txt")),
    ("installer",   "installer.userdb.txt",   include_str!("../../data/peid/installer.userdb.txt")),
    ("compiler",    "compiler.userdb.txt",    include_str!("../../data/peid/compiler.userdb.txt")),
    ("joiner",      "joiner.userdb.txt",      include_str!("../../data/peid/joiner.userdb.txt")),
    ("sfx_archive", "sfx_archive.userdb.txt", include_str!("../../data/peid/sfx_archive.userdb.txt")),
    ("file_format", "file_format.userdb.txt", include_str!("../../data/peid/file_format.userdb.txt")),
    ("overlay",     "overlay.userdb.txt",     include_str!("../../data/peid/overlay.userdb.txt")),
];

// ── Parser ─────────────────────────────────────────────────────────

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Returns `None` for a token we can't classify — caller treats that
/// as a "broken" signature and drops the whole entry.
fn parse_token(tok: &str) -> Option<Vec<MaskByte>> {
    match tok {
        "??" => Some(vec![MaskByte::WILDCARD]),
        "J1" => Some(vec![MaskByte::WILDCARD]),
        "J2" => Some(vec![MaskByte::WILDCARD; 2]),
        // PEiD's J3 is a 4-byte relative-jump operand.
        "J3" => Some(vec![MaskByte::WILDCARD; 4]),
        _ if tok.len() == 2 => {
            let bytes = tok.as_bytes();
            let hi = hex_nibble(bytes[0]);
            let lo = hex_nibble(bytes[1]);
            match (hi, lo) {
                (Some(h), Some(l)) => Some(vec![MaskByte::exact((h << 4) | l)]),
                (Some(h), None) if bytes[1] == b'?' =>
                    Some(vec![MaskByte { value: h << 4, mask: 0xF0 }]),
                (None, Some(l)) if bytes[0] == b'?' =>
                    Some(vec![MaskByte { value: l, mask: 0x0F }]),
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_db(text: &str, category: &'static str, source_db: &'static str, out: &mut Vec<PeidSig>) {
    let text = text.trim_start_matches('\u{feff}');
    let mut current_name: Option<String> = None;
    let mut current_sig: Option<Vec<MaskByte>> = None;
    let mut current_ep: bool = true;       // PEiD's documented default
    let mut current_broken = false;

    fn flush(
        name: &mut Option<String>, sig: &mut Option<Vec<MaskByte>>,
        ep: bool, broken: bool, category: &'static str, source_db: &'static str,
        out: &mut Vec<PeidSig>,
    ) {
        if let (Some(n), Some(p)) = (name.take(), sig.take()) {
            if !broken && !p.is_empty() {
                let anchor = longest_exact_run(&p);
                out.push(PeidSig {
                    name: n,
                    category,
                    source_db,
                    ep_only: ep,
                    pattern: p,
                    anchor,
                });
            }
        }
    }

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') { continue; }
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush(&mut current_name, &mut current_sig, current_ep, current_broken,
                  category, source_db, out);
            current_name = Some(rest.to_string());
            current_sig = None;
            current_ep = true;
            current_broken = false;
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim();
            let val = line[eq + 1..].trim();
            match key {
                "signature" => {
                    let mut bytes: Vec<MaskByte> = Vec::with_capacity(64);
                    let mut broken = false;
                    for tok in val.split_whitespace() {
                        match parse_token(tok) {
                            Some(mut bs) => bytes.append(&mut bs),
                            None => { broken = true; break; }
                        }
                    }
                    current_sig = Some(bytes);
                    current_broken = broken;
                }
                "ep_only" => {
                    current_ep = matches!(val.to_ascii_lowercase().as_str(),
                        "true" | "1" | "yes");
                }
                _ => {}
            }
        }
    }
    flush(&mut current_name, &mut current_sig, current_ep, current_broken,
          category, source_db, out);
}

fn longest_exact_run(pat: &[MaskByte]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut i = 0usize;
    while i < pat.len() {
        if pat[i].is_exact() {
            let start = i;
            while i < pat.len() && pat[i].is_exact() { i += 1; }
            let len = i - start;
            if best.map_or(true, |(_, l)| len > l) { best = Some((start, len)); }
        } else {
            i += 1;
        }
    }
    best
}

// ── Cached signature catalogue + AC index ─────────────────────────

static SIGS: OnceLock<Vec<PeidSig>> = OnceLock::new();

fn sigs() -> &'static [PeidSig] {
    SIGS.get_or_init(|| {
        let mut out = Vec::with_capacity(4500);
        for (cat, src, text) in DBS { parse_db(text, cat, src, &mut out); }
        out
    })
}

/// Aho-Corasick over the longest exact-byte run of every non-EP
/// signature whose anchor is at least 3 bytes. The companion vector
/// maps AC pattern index → (sig_idx, anchor_offset_within_pattern).
static AC_CACHE: OnceLock<(Option<aho_corasick::AhoCorasick>, Vec<(usize, usize)>)>
    = OnceLock::new();

fn ac_index() -> &'static (Option<aho_corasick::AhoCorasick>, Vec<(usize, usize)>) {
    AC_CACHE.get_or_init(|| {
        let sigs = sigs();
        let mut anchors: Vec<Vec<u8>> = Vec::new();
        let mut idx: Vec<(usize, usize)> = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            if sig.ep_only { continue; }
            let (a_off, a_len) = match sig.anchor { Some(a) => a, None => continue };
            if a_len < 3 { continue; }
            let bytes: Vec<u8> = sig.pattern[a_off..a_off + a_len]
                .iter().map(|m| m.value).collect();
            anchors.push(bytes);
            idx.push((i, a_off));
        }
        if anchors.is_empty() { return (None, idx); }
        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&anchors)
            .ok();
        (ac, idx)
    })
}

// ── PE entry-point file-offset resolution ─────────────────────────

/// Walks DOS → PE → COFF → optional header → section table to convert
/// the optional header's `AddressOfEntryPoint` (an RVA) into a file
/// offset. Returns `None` for non-PE inputs or when the section table
/// is malformed.
fn pe_entry_file_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes(
        data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() { return None; }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = coff + 20;
    if opt_off + 20 > data.len() { return None; }
    let entry_rva = u32::from_le_bytes(
        data.get(opt_off + 16..opt_off + 20)?.try_into().ok()?) as u64;
    let sec_table = opt_off + opt_size;
    rva_to_offset(data, sec_table, n_sections, entry_rva)
}

fn rva_to_offset(data: &[u8], sec_table: usize, n_sections: usize, rva: u64) -> Option<usize> {
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { return None; }
        let virt_size = u32::from_le_bytes(
            [data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as u64;
        let virt_addr = u32::from_le_bytes(
            [data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_off = u32::from_le_bytes(
            [data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64;
        let region = virt_size.max(1);
        if rva >= virt_addr && rva < virt_addr + region {
            return Some((raw_off + (rva - virt_addr)) as usize);
        }
    }
    None
}

// ── Match function ────────────────────────────────────────────────

fn pattern_matches_at(pat: &[MaskByte], data: &[u8], offset: usize) -> bool {
    if offset + pat.len() > data.len() { return false; }
    for (i, p) in pat.iter().enumerate() {
        if !p.matches(data[offset + i]) { return false; }
    }
    true
}

// ── Scan ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Hit {
    sig_idx: usize,
    offset: usize,
}

fn scan(data: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let sigs = sigs();
    let ep_off = pe_entry_file_offset(data);

    // (1) ep_only path — direct comparison at the entry-point offset.
    if let Some(ep) = ep_off {
        for (i, sig) in sigs.iter().enumerate() {
            if !sig.ep_only { continue; }
            if pattern_matches_at(&sig.pattern, data, ep) {
                hits.push(Hit { sig_idx: i, offset: ep });
            }
        }
    }

    // (2) non-EP path — Aho-Corasick over anchor literals.
    let (ac, idx_map) = ac_index();
    if let Some(ac) = ac {
        for m in ac.find_overlapping_iter(data) {
            let pat_idx = m.pattern().as_usize();
            let (sig_idx, anchor_off) = idx_map[pat_idx];
            let m_start = m.start();
            if m_start < anchor_off { continue; }
            let pat_start = m_start - anchor_off;
            let sig = &sigs[sig_idx];
            if pattern_matches_at(&sig.pattern, data, pat_start) {
                hits.push(Hit { sig_idx, offset: pat_start });
            }
        }
    }

    hits
}

// ── Public action ─────────────────────────────────────────────────

pub fn peid_scan(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap peid-scan <pe-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return format!("Not a PE binary: {target}");
    }

    let hits = scan(&data);
    let sigs_ref = sigs();
    register_into_graph(graph, target, sigs_ref, &hits);
    format_report(target, &data, sigs_ref, &hits)
}

fn register_into_graph(graph: &mut Graph, target: &str, sigs: &[PeidSig], hits: &[Hit]) {
    if hits.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    // Dedup by (category, name) — only the first hit per signature
    // becomes a graph node.
    let mut seen = std::collections::HashSet::new();
    for h in hits {
        let sig = &sigs[h.sig_idx];
        let key = (sig.category, sig.name.as_str());
        if !seen.insert(key) { continue; }
        let pid = format!("packer:{}::{}", sig.category, sig.name);
        let off = format!("{:#x}", h.offset);
        let ep = if sig.ep_only { "true" } else { "false" };
        graph.ensure_typed_node(&pid, EntityKind::Packer, &[
            ("name", sig.name.as_str()),
            ("category", sig.category),
            ("offset", &off),
            ("ep_only", ep),
            ("source_db", sig.source_db),
        ]);
        graph.add_edge(&bin_id, &pid);
    }
}

fn format_report(target: &str, data: &[u8], sigs: &[PeidSig], hits: &[Hit]) -> String {
    let mut lines = vec![
        format!("=== PEiD Scan: {} ===", target),
        format!("Binary size:      {} bytes", data.len()),
        format!("Signatures:       {}", sigs.len()),
        format!("Matches:          {}", hits.len()),
        String::new(),
    ];
    if hits.is_empty() {
        lines.push("(no PEiD signature matched — likely uncompressed / unprotected)".to_string());
        return lines.join("\n");
    }

    use std::collections::BTreeMap;
    let mut by_cat: BTreeMap<&str, Vec<&Hit>> = BTreeMap::new();
    for h in hits { by_cat.entry(sigs[h.sig_idx].category).or_default().push(h); }

    for (cat, hs) in &by_cat {
        lines.push(format!("── {} ({}) ──", cat, hs.len()));
        let mut shown = std::collections::HashSet::new();
        for h in hs {
            let sig = &sigs[h.sig_idx];
            if !shown.insert(sig.name.as_str()) { continue; }
            let ep = if sig.ep_only { "EP" } else { "scan" };
            lines.push(format!("  [{}] {} @ {:#x}", ep, sig.name, h.offset));
        }
    }
    lines.push(String::new());
    lines.push("Try: codemap meta-path \"pe->packer\"  (cross-binary packer landscape)".to_string());
    lines.push("     codemap pagerank --type packer    (most-prevalent packers)".to_string());
    lines.join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_loads_full_corpus() {
        let s = sigs();
        // 9 .userdb.txt files total 4,445 named entries; ~50 entries
        // have unparseable junk continuation lines (e.g. trailing prose
        // tokens like "RU", "P_", etc. mid-signature) that we drop on
        // purpose rather than poison the catalogue. We still load >98%.
        assert!(s.len() >= 4350, "expected ≥ 4,350 PEiD signatures, got {}", s.len());
        // Sanity check: all categories represented.
        let cats: std::collections::HashSet<&str> = s.iter().map(|s| s.category).collect();
        for c in ["packer", "protector", "protection", "installer", "compiler",
                  "joiner", "sfx_archive", "file_format", "overlay"] {
            assert!(cats.contains(c), "missing category {c}");
        }
    }

    #[test]
    fn parser_handles_wildcards_and_halfbytes() {
        let mut out = Vec::new();
        let db = "[Test entry]\nsignature = 60 ?? 90 1?\nep_only = true\n";
        parse_db(db, "test", "test.userdb.txt", &mut out);
        assert_eq!(out.len(), 1);
        let sig = &out[0];
        assert_eq!(sig.pattern.len(), 4);
        assert!(sig.pattern[0].is_exact() && sig.pattern[0].value == 0x60);
        assert!(!sig.pattern[1].is_exact() && sig.pattern[1].mask == 0);
        assert!(sig.pattern[2].is_exact() && sig.pattern[2].value == 0x90);
        // 1? matches high nibble 0x10..0x1F
        assert!(sig.pattern[3].matches(0x10));
        assert!(sig.pattern[3].matches(0x1F));
        assert!(!sig.pattern[3].matches(0x20));
    }

    #[test]
    fn parser_handles_jump_tags() {
        let mut out = Vec::new();
        let db = "[J-tag]\nsignature = EB J3 8B\nep_only = true\n";
        parse_db(db, "test", "test.userdb.txt", &mut out);
        assert_eq!(out.len(), 1);
        // EB + 4 wildcard bytes + 8B = 6 bytes total
        assert_eq!(out[0].pattern.len(), 6);
        assert!(out[0].pattern[0].is_exact());
        for i in 1..5 { assert!(!out[0].pattern[i].is_exact()); }
        assert!(out[0].pattern[5].is_exact());
    }

    #[test]
    fn parser_drops_broken_signature() {
        let mut out = Vec::new();
        let db = "[Bad]\nsignature = 60 RU 8B\nep_only = true\n";
        parse_db(db, "test", "test.userdb.txt", &mut out);
        assert_eq!(out.len(), 0, "broken token should drop the entry");
    }

    #[test]
    fn pattern_match_with_wildcards() {
        let pat = vec![
            MaskByte::exact(0x60),
            MaskByte::WILDCARD,
            MaskByte::exact(0x90),
        ];
        let data = [0x00, 0x60, 0xAB, 0x90, 0x00];
        assert!(pattern_matches_at(&pat, &data, 1));
        assert!(!pattern_matches_at(&pat, &data, 0));
        assert!(!pattern_matches_at(&pat, &data, 2));
    }

    #[test]
    fn longest_exact_run_picks_correct_window() {
        let pat = vec![
            MaskByte::WILDCARD,
            MaskByte::exact(0xAA),
            MaskByte::exact(0xBB),
            MaskByte::WILDCARD,
            MaskByte::exact(0x11),
            MaskByte::exact(0x22),
            MaskByte::exact(0x33),
        ];
        let (off, len) = longest_exact_run(&pat).unwrap();
        assert_eq!(off, 4);
        assert_eq!(len, 3);
    }

    /// Build a minimal valid PE32 image with a single section of
    /// `payload.len()` bytes whose entry point lands at the start of
    /// the payload. Just enough structure for `pe_entry_file_offset`
    /// to walk DOS → PE → COFF → optional header → section table.
    fn build_synthetic_pe(payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        data[..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x40;
        data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF header at 0x44, 20 bytes.
        data[0x44..0x46].copy_from_slice(&0x14c_u16.to_le_bytes()); // i386
        data[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());      // 1 section
        let opt_size: u16 = 96;
        data[0x54..0x56].copy_from_slice(&opt_size.to_le_bytes());
        data[0x56..0x58].copy_from_slice(&0x102_u16.to_le_bytes()); // exec | 32-bit
        // Optional header at 0x58. AddressOfEntryPoint at opt+16 = 0x68.
        let entry_rva: u32 = 0x1000;
        data[0x68..0x6c].copy_from_slice(&entry_rva.to_le_bytes());
        // Section table at opt_off + opt_size = 0x58 + 96 = 0xb8.
        let sec_off = 0xb8;
        data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        let raw_off: u32 = 0x200;
        data[sec_off + 20..sec_off + 24].copy_from_slice(&raw_off.to_le_bytes());
        // Pad to raw_off + section size and drop the payload at the EP.
        data.resize(raw_off as usize + 0x200, 0);
        data[raw_off as usize..raw_off as usize + payload.len()]
            .copy_from_slice(payload);
        data
    }

    #[test]
    fn entry_point_offset_resolves() {
        let pe = build_synthetic_pe(&[0xAA; 16]);
        assert_eq!(pe_entry_file_offset(&pe), Some(0x200));
    }

    #[test]
    fn detects_upx_at_entry_point() {
        // [UPX 0.50 - 0.70]  signature = 60 E8 00 00 00 00 58 83 E8 3D
        // ep_only = true. Fully exact, 10 bytes.
        let upx = [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xE8, 0x3D];
        let pe = build_synthetic_pe(&upx);
        let hits = scan(&pe);
        assert!(
            hits.iter().any(|h| sigs()[h.sig_idx].name.contains("UPX")),
            "expected an UPX signature to fire on a synthetic PE with the UPX EP bytes; \
             got {} hits",
            hits.len()
        );
    }

    #[test]
    fn no_match_on_non_pe_input() {
        let mut g = Graph { nodes: std::collections::HashMap::new(),
                            scan_dir: String::new(), cpg: None };
        let report = peid_scan(&mut g, "/dev/null");
        // Either "Failed to read" or "Not a PE binary" — both are fine,
        // we only care that it doesn't panic.
        assert!(report.contains("Not a PE") || report.contains("Failed"));
    }
}
