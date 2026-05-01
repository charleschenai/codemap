// ── DiE Fingerprint Detector — Ship 5 #2 (5.38.0) ──────────────────
//
// Identifies the packer / protector / cryptor / installer / sfx / joiner
// / patcher / compiler / library / format / tool / sign / game / dotnet
// / native / marker that produced a binary, by matching mined byte
// patterns from Detect-It-Easy's hand-curated `.sg` detector scripts.
//
// Source corpus: `tools/die_miner.py` regex-extracts every `compareEP`,
// `isSignaturePresent`, `isSignatureInSectionPresent`, `findSignature`,
// and `compareOverlay` literal from `~/reference/codemap-research-targets/
// 15-die/db/{PE,MSDOS,NE,LE,LX,Binary,...}/*.sg`, paired with each
// script's `meta(type, name)` declaration and the `sVersion` /
// `sOptions` strings assigned in the surrounding logical block. Output
// is bundled at compile time via `include_str!` and parsed once.
//
// Honest v1 limitations:
//   - DiE-DSL `$$/$$$$/$$$$$$$$` (auto-resolved relative-jump tokens)
//     are downgraded to plain `??` byte wildcards by the miner. Patterns
//     where jump-target validation matters will still match the
//     surrounding bytes — usually the discriminating part — but
//     pathological jump-only patterns may false-positive.
//   - Negative wildcards `**/!!/__` are dropped by the miner; the v1
//     matcher has no way to express "must not be these bytes".
//   - `compareEP` offset arguments that aren't compile-time literals
//     (e.g. `PE.compareEP("807C") ? 27 : 0`) collapse to offset 0.
//   - Only x86/x64 PE binaries get full EP recovery for v1; other
//     formats (NE/LE/LX/MSDOS COM) fall through to the section / file
//     scan paths so the corpus's non-PE patterns still match.

use crate::types::{Graph, EntityKind};

const CORPUS_JSON: &str = include_str!("../../data/die-epsig.json");

/// One mined record from `die-epsig.json`. Field order matches the
/// miner's output to keep `serde_json` happy.
#[derive(Debug, Clone, serde::Deserialize)]
struct MinedRecord {
    axis: String,
    #[serde(default, rename = "type")]
    raw_type: String,
    family: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    options: String,
    /// One of `ep` / `sig` / `overlay` — selects the matching strategy.
    kind: String,
    /// Byte offset (relative to EP for `ep`, file-start for `sig`/`overlay`).
    offset: i64,
    /// Hex with `?` nibble wildcards. Always even-length.
    pattern: String,
    /// How many `$$*` runs the miner downgraded — informational, not used
    /// by the matcher.
    #[serde(default)]
    #[allow(dead_code)]
    lossy: u32,
    source: String,
    #[serde(default)]
    #[allow(dead_code)]
    line: u32,
    fixed_bytes: u32,
}

/// Compiled-once compact matcher form: per-byte either `(hi, lo)` nibbles
/// to match exactly, `Some(n) / None` for half-wildcard, or `None / None`
/// for full wildcard.
#[derive(Debug, Clone)]
struct CompiledPattern {
    /// One entry per byte. Each entry is two `Option<u8>` nibbles.
    bytes: Vec<(Option<u8>, Option<u8>)>,
}

impl CompiledPattern {
    fn compile(hex: &str) -> Option<Self> {
        let chars: Vec<char> = hex.chars().collect();
        if chars.len() % 2 != 0 || chars.is_empty() { return None; }
        let mut bytes = Vec::with_capacity(chars.len() / 2);
        for chunk in chars.chunks_exact(2) {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            bytes.push((hi, lo));
        }
        Some(Self { bytes })
    }
    fn len(&self) -> usize { self.bytes.len() }
    fn matches(&self, data: &[u8], at: usize) -> bool {
        if at + self.bytes.len() > data.len() { return false; }
        for (i, &(h, l)) in self.bytes.iter().enumerate() {
            let b = data[at + i];
            if let Some(hv) = h { if (b >> 4) != hv { return false; } }
            if let Some(lv) = l { if (b & 0x0f) != lv { return false; } }
        }
        true
    }
}

fn nibble(c: char) -> Option<Option<u8>> {
    match c {
        '0'..='9' => Some(Some(c as u8 - b'0')),
        'a'..='f' => Some(Some(10 + c as u8 - b'a')),
        'A'..='F' => Some(Some(10 + c as u8 - b'A')),
        '?' => Some(None),
        _ => None,
    }
}

/// Outcome of matching the corpus against one binary.
#[derive(Debug, Clone)]
struct Hit<'a> {
    rec: &'a MinedRecord,
    location: HitLocation,
}

#[derive(Debug, Clone)]
enum HitLocation {
    EntryPoint { file_offset: usize },
    Section { name: String, file_offset: usize },
    Overlay { file_offset: usize },
    File { file_offset: usize },
}

impl HitLocation {
    fn label(&self) -> String {
        match self {
            HitLocation::EntryPoint { file_offset } => format!("EP@{file_offset:#x}"),
            HitLocation::Section { name, file_offset } => format!("{name}@{file_offset:#x}"),
            HitLocation::Overlay { file_offset } => format!("overlay@{file_offset:#x}"),
            HitLocation::File { file_offset } => format!("file@{file_offset:#x}"),
        }
    }
}

pub fn die_fingerprint(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap die-fingerprint <binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let records = match parse_corpus() {
        Ok(r) => r,
        Err(e) => return format!("Bundled DiE corpus failed to parse: {e}"),
    };

    let layout = analyze_layout(&data);
    let hits = scan(&data, &layout, &records);
    let bin_id = layout.binary_id(target);
    let bin_kind = layout.binary_kind();
    register_into_graph(graph, &bin_id, bin_kind, target, &hits);
    format_report(target, &layout, &records, &hits)
}

// ── Layout ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct BinaryLayout {
    format: BinaryFormat,
    /// EP file offset, when known (PE only for v1).
    entry_file_off: Option<usize>,
    /// Sections to scan for `sig` patterns: (name, file_offset, size).
    sections: Vec<(String, usize, usize)>,
    /// Overlay region (everything past the last section's raw end).
    overlay: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Unknown,
}

impl BinaryLayout {
    fn binary_id(&self, target: &str) -> String {
        match self.format {
            BinaryFormat::Pe => format!("pe:{target}"),
            BinaryFormat::Elf => format!("elf:{target}"),
            BinaryFormat::MachO => format!("macho:{target}"),
            BinaryFormat::Unknown => format!("file:{target}"),
        }
    }
    fn binary_kind(&self) -> EntityKind {
        match self.format {
            BinaryFormat::Pe => EntityKind::PeBinary,
            BinaryFormat::Elf => EntityKind::ElfBinary,
            BinaryFormat::MachO => EntityKind::MachoBinary,
            BinaryFormat::Unknown => EntityKind::PeBinary,
        }
    }
}

fn analyze_layout(data: &[u8]) -> BinaryLayout {
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        return BinaryLayout {
            format: BinaryFormat::Elf,
            entry_file_off: None,
            sections: vec![("file".to_string(), 0, data.len())],
            overlay: None,
        };
    }
    if data.len() >= 4 {
        let m = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(m, 0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe) {
            return BinaryLayout {
                format: BinaryFormat::MachO,
                entry_file_off: None,
                sections: vec![("file".to_string(), 0, data.len())],
                overlay: None,
            };
        }
    }
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        if let Some(layout) = analyze_pe(data) {
            return layout;
        }
    }
    BinaryLayout {
        format: BinaryFormat::Unknown,
        entry_file_off: None,
        sections: vec![("file".to_string(), 0, data.len())],
        overlay: None,
    }
}

fn analyze_pe(data: &[u8]) -> Option<BinaryLayout> {
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff = e_lfanew.checked_add(4)?;
    if coff + 20 > data.len() { return None; }
    if &data[e_lfanew..coff] != b"PE\0\0" { return None; }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = coff + 20;
    if opt_off + 28 > data.len() { return None; }
    let entry_rva = u32::from_le_bytes([
        data[opt_off + 16], data[opt_off + 17], data[opt_off + 18], data[opt_off + 19],
    ]) as u64;
    let sec_table = opt_off + opt_size;

    let mut sections = Vec::new();
    let mut max_raw_end: usize = 0;
    let mut entry_file_off: Option<usize> = None;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() { break; }
        let raw_name = &data[off..off + 8];
        let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).to_string();
        let virt_size = u32::from_le_bytes([
            data[off + 8], data[off + 9], data[off + 10], data[off + 11],
        ]) as u64;
        let virt_addr = u32::from_le_bytes([
            data[off + 12], data[off + 13], data[off + 14], data[off + 15],
        ]) as u64;
        let raw_size = u32::from_le_bytes([
            data[off + 16], data[off + 17], data[off + 18], data[off + 19],
        ]) as u64;
        let raw_off = u32::from_le_bytes([
            data[off + 20], data[off + 21], data[off + 22], data[off + 23],
        ]) as u64 as usize;
        let mapped = virt_size.min(raw_size).max(0) as usize;
        if mapped == 0 || raw_off >= data.len() { continue; }
        let actual = mapped.min(data.len().saturating_sub(raw_off));
        sections.push((name.clone(), raw_off, actual));
        max_raw_end = max_raw_end.max(raw_off + actual);
        // EP within this section?
        if entry_rva >= virt_addr && entry_rva < virt_addr + virt_size.max(raw_size) {
            let in_sec_off = (entry_rva - virt_addr) as usize;
            let candidate = raw_off + in_sec_off;
            if candidate < data.len() {
                entry_file_off = Some(candidate);
            }
        }
    }
    let overlay = if max_raw_end < data.len() {
        Some((max_raw_end, data.len() - max_raw_end))
    } else {
        None
    };
    Some(BinaryLayout {
        format: BinaryFormat::Pe,
        entry_file_off,
        sections,
        overlay,
    })
}

// ── Scanner ───────────────────────────────────────────────────────

fn parse_corpus() -> Result<Vec<MinedRecord>, String> {
    serde_json::from_str(CORPUS_JSON).map_err(|e| e.to_string())
}

fn scan<'a>(data: &[u8], layout: &BinaryLayout, records: &'a [MinedRecord]) -> Vec<Hit<'a>> {
    let mut hits = Vec::new();
    for rec in records {
        let pat = match CompiledPattern::compile(&rec.pattern) {
            Some(p) => p,
            None => continue,
        };
        match rec.kind.as_str() {
            "ep" => {
                if let Some(ep) = layout.entry_file_off {
                    let target_off = ep as i64 + rec.offset;
                    if target_off >= 0 {
                        let off = target_off as usize;
                        if pat.matches(data, off) {
                            hits.push(Hit {
                                rec,
                                location: HitLocation::EntryPoint { file_offset: off },
                            });
                        }
                    }
                }
            }
            "sig" => {
                // Scan every section. For v1 we don't restrict by which
                // section the DiE script targeted (`isSignatureInSectionPresent(0,
                // ...)` etc.) because the section index doesn't survive
                // mining. Require ≥ 6 fixed bytes for non-EP-anchored
                // matches — short patterns are too noisy when scanned
                // across hundreds of KB.
                if rec.fixed_bytes < 6 { continue; }
                if !layout.sections.is_empty() {
                    for (name, off, size) in &layout.sections {
                        if let Some(hit_off) = scan_window(data, *off, *size, &pat) {
                            hits.push(Hit {
                                rec,
                                location: HitLocation::Section {
                                    name: name.clone(),
                                    file_offset: hit_off,
                                },
                            });
                            break;
                        }
                    }
                } else if let Some(hit_off) = scan_window(data, 0, data.len(), &pat) {
                    hits.push(Hit {
                        rec,
                        location: HitLocation::File { file_offset: hit_off },
                    });
                }
            }
            "overlay" => {
                if rec.fixed_bytes < 6 { continue; }
                if let Some((off, size)) = layout.overlay {
                    if let Some(hit_off) = scan_window(data, off, size, &pat) {
                        hits.push(Hit {
                            rec,
                            location: HitLocation::Overlay { file_offset: hit_off },
                        });
                    }
                }
            }
            _ => {}
        }
    }
    hits
}

/// Naive but adequate window scanner. We're matching ≤ ~50-byte
/// patterns inside ≤ a few-MB binary in v1; classic 1-mismatch-then-
/// shift loop is fine. If profiling shows hot spots we can layer
/// Boyer-Moore or two-byte hash buckets later.
fn scan_window(data: &[u8], off: usize, size: usize, pat: &CompiledPattern) -> Option<usize> {
    let end = (off + size).min(data.len());
    if pat.len() > end.saturating_sub(off) { return None; }
    let stop = end - pat.len();
    let mut i = off;
    while i <= stop {
        if pat.matches(data, i) { return Some(i); }
        i += 1;
    }
    None
}

// ── Graph registration ───────────────────────────────────────────

const SEVEN_AXIS: &[&str] = &[
    "packer", "protector", "cryptor", "installer", "sfx", "joiner", "patcher",
    "compiler", "library", "format", "tool", "sign", "game", "dotnet",
    "native", "marker",
];

fn register_into_graph(
    graph: &mut Graph,
    bin_id: &str,
    bin_kind: EntityKind,
    target: &str,
    hits: &[Hit<'_>],
) {
    if hits.is_empty() { return; }
    graph.ensure_typed_node(bin_id, bin_kind, &[("path", target)]);
    // De-dup at the (axis, family, version, options) level so multiple
    // mined patterns matching the same family don't spawn N nodes.
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String, String, String)> = HashSet::new();
    for h in hits {
        let key = (
            h.rec.axis.clone(),
            h.rec.family.clone(),
            h.rec.version.clone(),
            h.rec.options.clone(),
        );
        if !seen.insert(key) { continue; }
        let fp_id = format!("fingerprint:{target}::{}::{}", h.rec.axis, h.rec.family);
        let location = h.location.label();
        let confidence = if h.rec.fixed_bytes >= 8 || matches!(h.location, HitLocation::EntryPoint{..}) {
            "high"
        } else {
            "medium"
        };
        graph.ensure_typed_node(&fp_id, EntityKind::BinaryFingerprint, &[
            ("axis", h.rec.axis.as_str()),
            ("type", h.rec.raw_type.as_str()),
            ("family", h.rec.family.as_str()),
            ("version", h.rec.version.as_str()),
            ("options", h.rec.options.as_str()),
            ("source", h.rec.source.as_str()),
            ("location", location.as_str()),
            ("confidence", confidence),
        ]);
        graph.add_edge(bin_id, &fp_id);
    }
}

// ── Reporting ────────────────────────────────────────────────────

fn format_report(
    target: &str,
    layout: &BinaryLayout,
    records: &[MinedRecord],
    hits: &[Hit<'_>],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== DiE Fingerprint: {} ===\n\n", target));
    out.push_str(&format!("Format:           {:?}\n", layout.format));
    out.push_str(&format!("Sections:         {}\n", layout.sections.len()));
    if let Some(ep) = layout.entry_file_off {
        out.push_str(&format!("Entry-point off:  {ep:#x}\n"));
    } else {
        out.push_str("Entry-point off:  (unknown — non-PE / v1)\n");
    }
    if let Some((off, size)) = layout.overlay {
        out.push_str(&format!("Overlay:          {size} bytes @ {off:#x}\n"));
    }
    out.push_str(&format!("Corpus patterns:  {}\n", records.len()));
    out.push_str(&format!("Hits:             {}\n\n", hits.len()));

    if hits.is_empty() {
        out.push_str("No DiE-mined patterns matched. The binary is either:\n");
        out.push_str("  - cleanly compiled with no recognised packer/protector\n");
        out.push_str("  - using a packer not represented in the DiE corpus\n");
        out.push_str("  - hitting v1 limitations (non-PE binary, see code header)\n");
        return out;
    }

    // Group by 7-axis, then unique (family, version) pairs.
    use std::collections::BTreeMap;
    let mut by_axis: BTreeMap<&str, BTreeMap<(String, String, String), Vec<&Hit<'_>>>> =
        BTreeMap::new();
    for h in hits {
        let bucket = by_axis.entry(h.rec.axis.as_str()).or_default();
        let k = (h.rec.family.clone(), h.rec.version.clone(), h.rec.options.clone());
        bucket.entry(k).or_default().push(h);
    }

    out.push_str("── 7-axis fingerprint ──\n");
    for axis in SEVEN_AXIS {
        let key: &str = axis;
        let group = match by_axis.get(key) { Some(g) => g, None => continue };
        out.push_str(&format!("  {:<10} ({})\n", axis, group.len()));
        for ((fam, ver, opts), hs) in group.iter().take(8) {
            let h0 = hs[0];
            let mut line = format!("    • {fam}");
            if !ver.is_empty() { line.push_str(&format!(" {ver}")); }
            if !opts.is_empty() { line.push_str(&format!(" [{opts}]")); }
            line.push_str(&format!("    {}\n", h0.location.label()));
            out.push_str(&line);
        }
        if group.len() > 8 {
            out.push_str(&format!("    … and {} more\n", group.len() - 8));
        }
    }

    // Show non-7-axis buckets we ended up with too (archive/format/etc.)
    let mut shown_extras = false;
    for (axis, group) in &by_axis {
        if SEVEN_AXIS.contains(axis) { continue; }
        if !shown_extras {
            out.push_str("\n── extra axes ──\n");
            shown_extras = true;
        }
        out.push_str(&format!("  {:<10} ({})\n", axis, group.len()));
        for ((fam, ver, _opts), _) in group.iter().take(4) {
            out.push_str(&format!("    • {fam} {ver}\n"));
        }
    }

    out.push('\n');
    out.push_str("Try: codemap pagerank --type fingerprint   (most-shared families)\n");
    out.push_str("     codemap meta-path \"pe->fingerprint\"   (every fingerprint per binary)\n");
    out
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_loads_and_meets_minimum_size() {
        let recs = parse_corpus().expect("corpus must parse");
        // Reality check after mining 1731 PE/MSDOS/NE/LE/LX/Binary scripts
        // and dedup. The research summary suggested 3000-5000 but actual
        // DiE corpus tops out near ~2200 unique patterns. Keep the floor
        // at a healthy >= 2000 and document the discrepancy here.
        assert!(
            recs.len() >= 2000,
            "expected ≥ 2000 mined patterns, got {}",
            recs.len()
        );
        // Spot-check: every record has a non-empty axis + family.
        for r in recs.iter().take(50) {
            assert!(!r.axis.is_empty(), "record missing axis: {:?}", r);
            assert!(!r.family.is_empty(), "record missing family: {:?}", r);
            assert!(!r.pattern.is_empty(), "record missing pattern: {:?}", r);
            assert!(r.fixed_bytes >= 4, "fixed_bytes too low: {:?}", r);
        }
    }

    #[test]
    fn corpus_covers_seven_axis_taxonomy() {
        let recs = parse_corpus().unwrap();
        let mut found: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for r in &recs {
            found.insert(r.axis.as_str());
        }
        // We expect to cover at least packer / protector / compiler /
        // installer — DiE's bread-and-butter axes.
        for required in &["packer", "protector", "compiler", "installer"] {
            assert!(found.contains(required), "missing axis {required} in corpus");
        }
    }

    #[test]
    fn pattern_compile_handles_wildcards() {
        let p = CompiledPattern::compile("AB??CD").unwrap();
        assert_eq!(p.len(), 3);
        // byte 0: AB exact
        assert_eq!(p.bytes[0], (Some(0xa), Some(0xb)));
        // byte 1: full wildcard
        assert_eq!(p.bytes[1], (None, None));
        // byte 2: CD exact
        assert_eq!(p.bytes[2], (Some(0xc), Some(0xd)));
    }

    #[test]
    fn pattern_matches_bytes() {
        // Classic UPX 32-bit EP head: 60 BE xx xx xx xx 8D BE = 8 bytes
        let p = CompiledPattern::compile("60BE????????8DBE").unwrap();
        assert_eq!(p.len(), 8);
        let bytes = [0x60, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x8D, 0xBE, 0xff];
        assert!(p.matches(&bytes, 0));
        // Should not match if first byte changes
        let bytes2 = [0x61, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x8D, 0xBE];
        assert!(!p.matches(&bytes2, 0));
    }

    #[test]
    fn scan_window_finds_offset() {
        let p = CompiledPattern::compile("DEADBEEF").unwrap();
        let mut data = vec![0u8; 100];
        data[42] = 0xde;
        data[43] = 0xad;
        data[44] = 0xbe;
        data[45] = 0xef;
        assert_eq!(scan_window(&data, 0, data.len(), &p), Some(42));
        assert_eq!(scan_window(&data, 50, 50, &p), None);
    }

    #[test]
    fn empty_target_emits_usage() {
        let mut g = Graph {
            nodes: std::collections::HashMap::new(),
            scan_dir: String::new(),
            cpg: None,
        };
        let r = die_fingerprint(&mut g, "");
        assert!(r.contains("Usage"));
    }

    #[test]
    fn synthetic_upx_binary_triggers_upx_detection() {
        // Build a tiny PE with EP byte sequence matching UPX 32-bit's
        // canonical signature: `60 BE xx xx xx xx 8D BE xx xx xx xx 57`.
        // We don't need a fully-valid PE — just enough for `analyze_pe`
        // to find the EP file offset, which means: MZ + e_lfanew + PE\0\0
        // header + optional header + 1 section.
        let pe = build_synthetic_upx_pe();

        let tmp = std::env::temp_dir().join("codemap_die_synth_upx.exe");
        std::fs::write(&tmp, &pe).unwrap();

        let mut g = Graph {
            nodes: std::collections::HashMap::new(),
            scan_dir: String::new(),
            cpg: None,
        };
        let report = die_fingerprint(&mut g, tmp.to_str().unwrap());
        // Cleanup
        let _ = std::fs::remove_file(&tmp);

        assert!(report.contains("DiE Fingerprint"), "report: {report}");
        // UPX is the canonical hand-curated 32-bit packer signature in
        // DiE (`db/PE/packer_UPX.2.sg:137`). The synthetic EP bytes are
        // `60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57` which is exactly
        // that pattern.
        assert!(
            report.contains("UPX"),
            "expected UPX detection in report:\n{report}"
        );
        assert!(
            report.contains("packer"),
            "expected `packer` axis in report:\n{report}"
        );
        // Graph node should have been registered.
        let bin_id = format!("pe:{}", tmp.to_str().unwrap());
        assert!(g.nodes.contains_key(&bin_id), "binary node missing");
        // At least one fingerprint child node.
        let fp_count = g.nodes.values()
            .filter(|n| matches!(n.kind, EntityKind::BinaryFingerprint))
            .count();
        assert!(fp_count >= 1, "expected ≥ 1 fingerprint node, got {fp_count}");
    }

    /// Construct the smallest 32-bit PE that's well-formed enough for
    /// `analyze_pe` to find an EP file offset and walk its single
    /// section. The section's first bytes are the canonical UPX EP
    /// pattern. Total size ≈ 512 bytes.
    fn build_synthetic_upx_pe() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // DOS header
        buf[0] = b'M'; buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature
        let pe_off = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        // COFF
        let coff = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // x86
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        let opt_size: u16 = 224; // PE32 standard
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        // Optional header (PE32, magic 0x10b)
        let opt_off = coff + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        // entry_rva at opt_off + 16
        let entry_rva: u32 = 0x1000;
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
        // image_base at opt_off + 28 (PE32)
        let image_base: u32 = 0x0040_0000;
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
        // Section table
        let sec_table = opt_off + opt_size as usize;
        // Name `.text`
        buf[sec_table..sec_table + 5].copy_from_slice(b".text");
        // virt_size
        buf[sec_table + 8..sec_table + 12].copy_from_slice(&0x100u32.to_le_bytes());
        // virt_addr = entry_rva
        buf[sec_table + 12..sec_table + 16].copy_from_slice(&entry_rva.to_le_bytes());
        // raw_size
        buf[sec_table + 16..sec_table + 20].copy_from_slice(&0x100u32.to_le_bytes());
        // raw_off = 0x200
        let raw_off: u32 = 0x200;
        buf[sec_table + 20..sec_table + 24].copy_from_slice(&raw_off.to_le_bytes());

        // Plant UPX 32-bit EP bytes at raw_off:
        // 60 BE 00 00 00 00 8D BE 00 00 00 00 57
        let upx_ep = [
            0x60, 0xBE, 0x00, 0x00, 0x00, 0x00,
            0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00,
            0x57,
        ];
        buf[raw_off as usize..raw_off as usize + upx_ep.len()].copy_from_slice(&upx_ep);
        buf
    }
}
