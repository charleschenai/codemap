// ── COM CLSID/IID Scanner (Ship 5 #1) ──────────────────────────────
//
// Detects which Windows COM component classes (CLSIDs) and interfaces
// (IIDs) a binary instantiates / implements. Two passes over file
// bytes:
//
//   1. ASCII GUID regex — for binaries (or their resources) that store
//      GUIDs as text, e.g. `{0006F03A-0000-0000-C000-000000000046}`.
//      We accept either bracketed `{…}` or bare 36-char form, case-
//      insensitive.
//   2. Raw 16-byte GUID — Microsoft COM stores GUIDs in a packed
//      binary form where groups 1/2/3 are little-endian-swapped and
//      groups 4/5 are kept as-is. The byte-order rearrangement we
//      undo here is documented in capa/rules/__init__.py:340-376.
//
// Database: 3,639 unique CLSIDs + 25,306 unique IIDs vendored from
// capa (Apache-2.0). Stored as bincode-v1 in `data/com/{classes,
// interfaces}.bin` and embedded into the binary via `include_bytes!`.
// Capa names that share a single GUID are joined with `|`.
//
// Edges emitted: pe → com_class, pe → com_interface.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::types::{Graph, EntityKind};

const CLASSES_BIN: &[u8] = include_bytes!("../../data/com/classes.bin");
const INTERFACES_BIN: &[u8] = include_bytes!("../../data/com/interfaces.bin");

/// One catalog (CLSID or IID) keyed by canonical natural-order GUID
/// bytes. The natural order is the byte sequence implied by reading
/// the ASCII GUID left-to-right (`AABBCCDD-EEFF-…` → `[AA, BB, CC,
/// DD, EE, FF, …]`). The on-disk Microsoft form is recovered by
/// swapping group 1 (4 bytes), group 2 (2 bytes), group 3 (2 bytes).
struct ComCatalog {
    by_guid: HashMap<[u8; 16], String>,
}

impl ComCatalog {
    fn lookup(&self, guid: &[u8; 16]) -> Option<&str> {
        self.by_guid.get(guid).map(|s| s.as_str())
    }
}

fn classes() -> &'static ComCatalog {
    static CELL: OnceLock<ComCatalog> = OnceLock::new();
    CELL.get_or_init(|| parse_catalog(CLASSES_BIN).expect("classes.bin must parse"))
}

fn interfaces() -> &'static ComCatalog {
    static CELL: OnceLock<ComCatalog> = OnceLock::new();
    CELL.get_or_init(|| parse_catalog(INTERFACES_BIN).expect("interfaces.bin must parse"))
}

/// Decode the bincode-v1 Vec<([u8; 16], String)> blob produced by
/// data/com/build.py. Hand-rolled (rather than calling bincode crate)
/// to avoid the runtime overhead of the full deserializer for a hot,
/// known-good input — the format is fixed: little-endian u64 length
/// prefix, then per-entry 16 raw bytes + u64 string-length + UTF-8.
fn parse_catalog(mut data: &[u8]) -> Result<ComCatalog, String> {
    fn read_u64(buf: &mut &[u8]) -> Result<u64, String> {
        if buf.len() < 8 { return Err("short u64".into()); }
        let v = u64::from_le_bytes(buf[..8].try_into().unwrap());
        *buf = &buf[8..];
        Ok(v)
    }

    let n = read_u64(&mut data)? as usize;
    let mut by_guid: HashMap<[u8; 16], String> = HashMap::with_capacity(n);
    for _ in 0..n {
        if data.len() < 16 { return Err("short guid".into()); }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[..16]);
        data = &data[16..];
        let len = read_u64(&mut data)? as usize;
        if data.len() < len { return Err("short name".into()); }
        let name = std::str::from_utf8(&data[..len])
            .map_err(|e| format!("utf-8: {e}"))?
            .to_string();
        data = &data[len..];
        by_guid.insert(guid, name);
    }
    Ok(ComCatalog { by_guid })
}

// ── Byte-order helpers ─────────────────────────────────────────────

/// Convert raw on-disk Microsoft COM bytes into natural (ASCII-read)
/// byte order. Inverse: `natural_to_raw`. Mirrors capa's group
/// rearrangement (capa/rules/__init__.py:340-376):
///   ASCII pairs:   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
///   Raw on disk:   3  2  1  0  5  4  7  6  8  9 10 11 12 13 14 15
fn raw_to_natural(raw: &[u8; 16]) -> [u8; 16] {
    [
        raw[3], raw[2], raw[1], raw[0],
        raw[5], raw[4],
        raw[7], raw[6],
        raw[8], raw[9], raw[10], raw[11],
        raw[12], raw[13], raw[14], raw[15],
    ]
}

#[cfg(test)]
fn natural_to_raw(natural: &[u8; 16]) -> [u8; 16] {
    // The transformation is its own inverse.
    raw_to_natural(natural)
}

/// Parse a 36-char ASCII GUID (`AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE`)
/// into its 16-byte natural form. Returns None on any non-hex byte.
fn parse_ascii_guid(s: &[u8]) -> Option<[u8; 16]> {
    if s.len() != 36 { return None; }
    if s[8] != b'-' || s[13] != b'-' || s[18] != b'-' || s[23] != b'-' {
        return None;
    }
    let mut out = [0u8; 16];
    let mut oi = 0;
    let mut i = 0;
    while i < 36 {
        if s[i] == b'-' { i += 1; continue; }
        let hi = hex_nibble(s[i])?;
        let lo = hex_nibble(s[i + 1])?;
        out[oi] = (hi << 4) | lo;
        oi += 1;
        i += 2;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Format a natural 16-byte GUID back to canonical uppercase ASCII.
fn format_guid(g: &[u8; 16]) -> String {
    let to_hex = |b: u8| -> [u8; 2] {
        let table = b"0123456789ABCDEF";
        [table[(b >> 4) as usize], table[(b & 0x0F) as usize]]
    };
    let mut out = [0u8; 36];
    let groups: [(usize, usize); 5] = [(0, 4), (4, 6), (6, 8), (8, 10), (10, 16)];
    let mut p = 0;
    for (gi, (lo, hi)) in groups.iter().enumerate() {
        for i in *lo..*hi {
            let h = to_hex(g[i]);
            out[p] = h[0]; out[p + 1] = h[1];
            p += 2;
        }
        if gi < 4 { out[p] = b'-'; p += 1; }
    }
    std::str::from_utf8(&out).unwrap().to_string()
}

// ── Scan ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Match {
    /// Natural-order canonical GUID bytes.
    guid: [u8; 16],
    name: String,
    is_class: bool,
    source: &'static str, // "ascii" or "raw"
    offset: usize,
}

pub fn com_scan(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap com-scan <pe-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 16 {
        return format!("Binary too small ({} bytes) for COM scanning", data.len());
    }

    let matches = scan(&data);
    register_into_graph(graph, target, &matches);
    format_report(target, &data, &matches)
}

/// Run both passes (ASCII regex + raw 16-byte) and return de-duped
/// matches. Dedup key: (guid, source) — we keep one entry per GUID
/// per detection mode, even if the same GUID appears many times.
fn scan(data: &[u8]) -> Vec<Match> {
    let cls = classes();
    let ifc = interfaces();
    let mut out: Vec<Match> = Vec::new();
    let mut seen: std::collections::HashSet<([u8; 16], &'static str)> =
        std::collections::HashSet::new();

    let record = |guid: [u8; 16], source: &'static str, offset: usize, out: &mut Vec<Match>, seen: &mut std::collections::HashSet<([u8; 16], &'static str)>| {
        if let Some(name) = cls.lookup(&guid) {
            if seen.insert((guid, source)) {
                out.push(Match { guid, name: name.to_string(), is_class: true, source, offset });
            }
        } else if let Some(name) = ifc.lookup(&guid) {
            if seen.insert((guid, source)) {
                out.push(Match { guid, name: name.to_string(), is_class: false, source, offset });
            }
        }
    };

    // Pass 1: ASCII GUID. Linear scan with cheap first-byte filter.
    // Look for `[hex]{8}-[hex]{4}-[hex]{4}-[hex]{4}-[hex]{12}`.
    // 36-byte fixed window is small enough for naive scan to be fast.
    if data.len() >= 36 {
        for i in 0..=data.len() - 36 {
            // Quick reject: dash positions
            let s = &data[i..i + 36];
            if s[8] != b'-' || s[13] != b'-' || s[18] != b'-' || s[23] != b'-' {
                continue;
            }
            // Reject if surrounding bytes look mid-hex (avoid partial
            // matches inside a longer hex blob — skip if char before
            // is hex and char after is hex). Cheap: just trim by
            // requiring boundaries to be non-hex when in range.
            if i > 0 && hex_nibble(data[i - 1]).is_some() { continue; }
            if i + 36 < data.len() && hex_nibble(data[i + 36]).is_some() { continue; }
            if let Some(guid) = parse_ascii_guid(s) {
                record(guid, "ascii", i, &mut out, &mut seen);
            }
        }
    }

    // Pass 2: Raw 16-byte. Scan every 16-byte window. Apply
    // byte-order swap then look up. This is O(N * hash) which is
    // ~150 ns per byte; for a 10 MB binary that's ~1.5 s. Fine for
    // a triage tool. False-positive rate: ~30K GUIDs * 1/2^128 per
    // window ≈ 0 per binary; in practice we get a handful from
    // structured data sections (timestamps, packed fields), but
    // dedup by GUID + the catalog being so specific keeps noise low.
    if data.len() >= 16 {
        for i in 0..=data.len() - 16 {
            let raw: [u8; 16] = data[i..i + 16].try_into().unwrap();
            // Reject all-zero / mostly-zero windows fast.
            if raw == [0u8; 16] { continue; }
            let nat = raw_to_natural(&raw);
            record(nat, "raw", i, &mut out, &mut seen);
        }
    }

    out
}

fn register_into_graph(graph: &mut Graph, target: &str, matches: &[Match]) {
    if matches.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    // Dedup at registration too: we want one node per (kind, GUID),
    // even if it was matched twice (ascii + raw).
    let mut seen: std::collections::HashSet<(bool, [u8; 16])> =
        std::collections::HashSet::new();
    for m in matches {
        if !seen.insert((m.is_class, m.guid)) { continue; }
        let canonical = format_guid(&m.guid);
        let (kind, prefix, attr_key) = if m.is_class {
            (EntityKind::ComClass, "com_class", "clsid")
        } else {
            (EntityKind::ComInterface, "com_iface", "iid")
        };
        let id = format!("{prefix}:{canonical}");
        // Aggregate sources: if both ascii AND raw matched we want
        // "ascii+raw". Walk all matches with the same (kind, guid).
        let mut has_ascii = false;
        let mut has_raw = false;
        for n in matches {
            if n.is_class == m.is_class && n.guid == m.guid {
                if n.source == "ascii" { has_ascii = true; }
                if n.source == "raw"   { has_raw = true; }
            }
        }
        let source: &str = match (has_ascii, has_raw) {
            (true, true) => "ascii+raw",
            (true, false) => "ascii",
            (false, true) => "raw",
            _ => "unknown",
        };
        let off = format!("{:#x}", m.offset);
        graph.ensure_typed_node(&id, kind, &[
            (attr_key, &canonical),
            ("name", &m.name),
            ("source", source),
            ("offset", &off),
        ]);
        graph.add_edge(&bin_id, &id);
    }
}

fn format_report(target: &str, data: &[u8], matches: &[Match]) -> String {
    let mut lines = vec![
        format!("=== COM GUID Scan: {} ===", target),
        format!("Binary size:        {} bytes", data.len()),
        format!("CLSID database:     {} entries", classes().by_guid.len()),
        format!("IID database:       {} entries", interfaces().by_guid.len()),
        format!("Matches:            {}", matches.len()),
        String::new(),
    ];
    if matches.is_empty() {
        lines.push("(no COM CLSIDs or IIDs detected)".to_string());
        return lines.join("\n");
    }

    // Group by kind (class vs interface) then dedup by GUID for
    // display.
    let mut classes_seen: std::collections::BTreeMap<String, Vec<&Match>> =
        std::collections::BTreeMap::new();
    let mut ifaces_seen: std::collections::BTreeMap<String, Vec<&Match>> =
        std::collections::BTreeMap::new();
    for m in matches {
        let key = format_guid(&m.guid);
        if m.is_class {
            classes_seen.entry(key).or_default().push(m);
        } else {
            ifaces_seen.entry(key).or_default().push(m);
        }
    }

    if !classes_seen.is_empty() {
        lines.push(format!("── Component classes (CLSIDs): {} unique ──", classes_seen.len()));
        for (guid, ms) in &classes_seen {
            let m = ms[0];
            let srcs: std::collections::BTreeSet<&str> =
                ms.iter().map(|m| m.source).collect();
            let src_str = srcs.into_iter().collect::<Vec<_>>().join("+");
            lines.push(format!("  {} {}  ({}, {} hits)", guid, m.name, src_str, ms.len()));
        }
        lines.push(String::new());
    }
    if !ifaces_seen.is_empty() {
        lines.push(format!("── Interfaces (IIDs): {} unique ──", ifaces_seen.len()));
        for (guid, ms) in &ifaces_seen {
            let m = ms[0];
            let srcs: std::collections::BTreeSet<&str> =
                ms.iter().map(|m| m.source).collect();
            let src_str = srcs.into_iter().collect::<Vec<_>>().join("+");
            lines.push(format!("  {} {}  ({}, {} hits)", guid, m.name, src_str, ms.len()));
        }
        lines.push(String::new());
    }
    lines.push("Try: codemap meta-path \"pe->com_class\"      (cross-binary CLSID inventory)".to_string());
    lines.push("     codemap meta-path \"pe->com_interface\"  (cross-binary IID inventory)".to_string());
    lines.push("     codemap pagerank --type com_class        (most-instantiated COM classes)".to_string());
    lines.join("\n")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Graph;
    use std::collections::HashMap;

    fn empty_graph() -> Graph {
        Graph { nodes: HashMap::new(), scan_dir: String::new(), cpg: None }
    }

    #[test]
    fn catalog_loads_and_has_known_entries() {
        // 10 known CLSIDs from capa's classes.py, verified to exist.
        // (Selected from the head of classes.py so the test stays
        // stable as the upstream DB grows.)
        let cls = classes();
        let known_clsids = [
            "24F97150-6689-11D1-9AA7-00C04FB93A80", // ClusAppWiz
            "BB8D141E-C00A-469F-BC5C-ECD814F0BD74", // ClusCfgAddNodesWizard
            "B929818E-F5B0-44DC-8A00-1B5F5F5AA1F0", // ClusCfgCreateClusterWizard
            "6A370489-BB52-4727-B740-08F494163478", // ClusCfgResTypeServices
            "A3C63918-889D-11D1-83E9-00C04FC2C6D4", // ThumbnailUpdater
            "CEFC65D8-66D8-11D1-8D8C-0000F804B057", // ThumbnailFCNHandler
            "0002E006-0000-0000-C000-000000000046", // GblComponentCategoriesMgr
            "0BE35204-8F91-11CE-9DE3-00AA004BB851", // StdPicture
            "0BE35203-8F91-11CE-9DE3-00AA004BB851", // StdFont
            "FB8F0822-0164-101B-84ED-08002B2EC713", // ConvertVBX
        ];
        for guid_str in known_clsids {
            let guid = parse_ascii_guid(guid_str.as_bytes()).expect("parse guid");
            let name = cls.lookup(&guid).unwrap_or_else(
                || panic!("missing CLSID {guid_str} in catalog"));
            assert!(!name.is_empty(), "empty name for {guid_str}");
        }
        assert!(cls.by_guid.len() >= 3000, "CLSID DB shrank? got {}", cls.by_guid.len());
        let ifc = interfaces();
        assert!(ifc.by_guid.len() >= 25_000, "IID DB shrank? got {}", ifc.by_guid.len());
    }

    #[test]
    fn ascii_guid_match_finds_known_clsid() {
        // Embed a known CLSID as ASCII in a synthetic buffer.
        // Use ClusAppWiz (verified above to exist in the catalog).
        let guid_str = b"24F97150-6689-11D1-9AA7-00C04FB93A80";
        let mut buf = vec![0u8; 0x200];
        // Place at an arbitrary offset 0x40, surrounded by NULs so
        // the boundary check passes (NUL is non-hex).
        buf[0x40..0x40 + 36].copy_from_slice(guid_str);
        let matches = scan(&buf);
        let class_match = matches.iter().find(|m| m.is_class && m.source == "ascii");
        assert!(class_match.is_some(),
            "expected ASCII ClusAppWiz CLSID match, got: {:?}",
            matches.iter().map(|m| (m.is_class, m.source, &m.name)).collect::<Vec<_>>());
        let m = class_match.unwrap();
        assert!(m.name.contains("ClusAppWiz"),
            "expected name to contain ClusAppWiz, got {:?}", m.name);
        assert_eq!(m.offset, 0x40);
    }

    #[test]
    fn raw_guid_match_finds_known_clsid() {
        // Same GUID as raw 16 bytes (LE-swapped on disk).
        let guid_str = b"24F97150-6689-11D1-9AA7-00C04FB93A80";
        let natural = parse_ascii_guid(guid_str).unwrap();
        let raw = natural_to_raw(&natural);
        let mut buf = vec![0xAAu8; 0x200];
        buf[0x80..0x80 + 16].copy_from_slice(&raw);
        let matches = scan(&buf);
        let raw_match = matches.iter().find(|m| m.is_class && m.source == "raw");
        assert!(raw_match.is_some(),
            "expected raw ClusAppWiz CLSID match, got {} matches",
            matches.len());
        let m = raw_match.unwrap();
        assert!(m.name.contains("ClusAppWiz"));
        assert_eq!(m.offset, 0x80);
    }

    #[test]
    fn ascii_and_raw_matches_dedup_into_one_node() {
        // Embed BOTH ASCII and raw forms in the same buffer.
        let guid_str = b"24F97150-6689-11D1-9AA7-00C04FB93A80";
        let natural = parse_ascii_guid(guid_str).unwrap();
        let raw = natural_to_raw(&natural);
        let mut buf = vec![0u8; 0x200];
        buf[0x40..0x40 + 36].copy_from_slice(guid_str);
        buf[0x100..0x100 + 16].copy_from_slice(&raw);

        let mut graph = empty_graph();
        com_scan(&mut graph, "/dev/null");
        // Manually invoke since /dev/null has zero bytes.
        let matches = scan(&buf);
        register_into_graph(&mut graph, "fake.exe", &matches);
        // Find the com_class node.
        let com_nodes: Vec<_> = graph.nodes.values()
            .filter(|n| n.kind == EntityKind::ComClass)
            .collect();
        assert_eq!(com_nodes.len(), 1, "should have exactly 1 com_class node");
        assert_eq!(com_nodes[0].attrs.get("source").map(|s| s.as_str()), Some("ascii+raw"));
    }

    #[test]
    fn raw_to_natural_is_self_inverse() {
        let g = [0x12u8, 0x34, 0x56, 0x78,
                 0x9A, 0xBC,
                 0xDE, 0xF0,
                 0x11, 0x22,
                 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(raw_to_natural(&raw_to_natural(&g)), g);
    }

    #[test]
    fn parse_ascii_guid_round_trips() {
        let s = "24F97150-6689-11D1-9AA7-00C04FB93A80";
        let bytes = parse_ascii_guid(s.as_bytes()).unwrap();
        assert_eq!(format_guid(&bytes), s);
    }

    #[test]
    fn parse_ascii_guid_rejects_bad_input() {
        assert!(parse_ascii_guid(b"24F97150_6689-11D1-9AA7-00C04FB93A80").is_none());
        assert!(parse_ascii_guid(b"24F97150-6689-11D1-9AA7-00C04FB93A8X").is_none());
        assert!(parse_ascii_guid(b"too-short").is_none());
    }

    #[test]
    fn empty_data_yields_no_matches() {
        let m = scan(&[]);
        assert!(m.is_empty());
    }

    #[test]
    fn random_data_yields_few_matches() {
        // 16 KB of pseudo-random bytes. With a 28K-entry catalog and
        // 2^128 GUID space, expected matches ≈ 0. Allow up to 2 to
        // tolerate structured patterns landing in the lookup space.
        let mut data = vec![0u8; 0x4000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2654435761) >> 16) as u8;
        }
        let m = scan(&data);
        assert!(m.len() <= 2,
            "expected ≤ 2 spurious matches in PRNG bytes, got {} ({:?})",
            m.len(),
            m.iter().map(|x| (&x.name, x.source)).take(5).collect::<Vec<_>>());
    }

    #[test]
    fn iid_match_works() {
        // IShellWindows IID = 85CB6900-4D95-11CF-960C-0080C7F4EE85.
        let guid_str = b"85CB6900-4D95-11CF-960C-0080C7F4EE85";
        let mut buf = vec![0u8; 0x100];
        buf[0x20..0x20 + 36].copy_from_slice(guid_str);
        let matches = scan(&buf);
        let iface = matches.iter().find(|m| !m.is_class);
        assert!(iface.is_some(), "expected IShellWindows IID match");
        assert!(iface.unwrap().name.contains("IShellWindows"));
    }

    #[test]
    fn graph_emits_binary_to_com_edges() {
        let guid_str = b"85CB6900-4D95-11CF-960C-0080C7F4EE85";
        let mut buf = vec![0u8; 0x100];
        buf[0x20..0x20 + 36].copy_from_slice(guid_str);
        let mut graph = empty_graph();
        let matches = scan(&buf);
        register_into_graph(&mut graph, "test.dll", &matches);
        let bin = graph.nodes.get("pe:test.dll").unwrap();
        assert!(bin.imports.iter().any(|i| i.starts_with("com_iface:")));
    }
}
