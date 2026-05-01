// ── Endpoint Enrichment (5.38.0 — Ship B) ──────────────────────────
//
// Three small data drops sourced from the unprotect-project signature
// repo, all attached to existing nodes (no new EntityKinds):
//
//   1. dyndns provider list (33 suffixes from network_evasion.yar)
//      → tags HttpEndpoint nodes with `dyndns=true` when the host
//        ends in a known dyndns suffix. Used by URL→endpoint promotion
//        in `scanner.rs`.
//
//   2. LOLBin name list (100 entries from signature/lolbin.txt)
//      → scans a PE binary for embedded references to known
//        living-off-the-land binaries; sets `uses_lolbin=true` and
//        `lolbins=<comma-separated>` on the PE node. Standalone
//        action `lolbin-scan <pe>`.
//
//   3. Valid TLD whitelist (1,381 ICANN+ccTLD list from
//      signature/domain_suffixes.txt)
//      → suppresses host-shaped strings whose last dot-segment is
//        not a real TLD (e.g. `config.json`, `weights.bin`). Used
//        by URL→endpoint promotion in `scanner.rs`.
//
// All three lookup tables are bundled at compile-time via include_str!
// and lazily parsed into HashSet<&'static str>.

use crate::types::{Graph, EntityKind};
use std::collections::HashSet;
use std::sync::OnceLock;

// ── bundled data ────────────────────────────────────────────────────

const DYNDNS_TXT: &str = include_str!("../../data/endpoint-enrichment/dyndns.txt");
const LOLBIN_TXT: &str = include_str!("../../data/endpoint-enrichment/lolbins.txt");
const TLDS_TXT:   &str = include_str!("../../data/endpoint-enrichment/tlds.txt");

fn parse_lines(txt: &'static str) -> HashSet<&'static str> {
    txt.lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect()
}

pub fn dyndns_suffixes() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| parse_lines(DYNDNS_TXT))
}

/// LOLBin names without the `.exe` / `.dll` extension. Matching is
/// case-insensitive substring against the binary's raw bytes; storing
/// names without an extension lets the same lookup catch
/// `certutil.exe`, `Certutil.EXE`, `\\Certutil.exe`, etc.
pub fn lolbin_names() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        LOLBIN_TXT
            .lines()
            .map(|s| s.trim().trim_end_matches(".exe").trim_end_matches(".dll").to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

pub fn valid_tlds() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| parse_lines(TLDS_TXT))
}

// ── dyndns suffix match ─────────────────────────────────────────────

/// True when `host` ends with a known dyndns suffix. Match is
/// case-insensitive and requires a dot boundary — `noip.org` only
/// matches `*.noip.org`, not `prefixnoip.org`.
pub fn host_is_dyndns(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    for sfx in dyndns_suffixes() {
        if lower == *sfx { return true; }
        let dotted = format!(".{sfx}");
        if lower.ends_with(&dotted) { return true; }
    }
    false
}

// ── TLD whitelist ───────────────────────────────────────────────────

/// True when the host's last dot-separated segment is a recognized
/// TLD. Hosts without any dot (bare `localhost`) and IP literals
/// short-circuit to true — those are filtered out earlier in the
/// promotion pipeline by the loopback / placeholder skip list.
pub fn host_has_valid_tld(host: &str) -> bool {
    if host.is_empty() { return false; }
    // IP literal: skip TLD check (filtered elsewhere if undesirable).
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') { return true; }
    if host.starts_with('[') && host.ends_with(']') { return true; }  // IPv6
    let last = match host.rsplit('.').next() {
        Some(t) => t.to_ascii_lowercase(),
        None => return false,
    };
    if last.is_empty() { return false; }
    valid_tlds().contains(last.as_str())
}

// ── LOLBin scan ─────────────────────────────────────────────────────

/// Case-insensitive substring scan over `data` for any LOLBin name.
/// Returns matched names sorted, deduped.
pub fn scan_lolbins(data: &[u8]) -> Vec<String> {
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut hits: HashSet<String> = HashSet::new();
    for name in lolbin_names() {
        // Whole-word boundary on the right (next char must be a
        // common terminator) so "rundll32" doesn't match inside
        // "rundll32xyz". Left-side boundary is fuzzier — we accept
        // anything because PE strings often have prefix path bytes.
        if let Some(idx) = find_subslice(&lower, name.as_bytes()) {
            let after = idx + name.len();
            let next = lower.get(after).copied().unwrap_or(0);
            let is_word_char = matches!(next, b'a'..=b'z' | b'0'..=b'9' | b'_');
            if !is_word_char {
                hits.insert(name.clone());
            }
        }
    }
    let mut out: Vec<String> = hits.into_iter().collect();
    out.sort();
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    let first = needle[0];
    let last = needle.len() - 1;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i] == first && haystack[i + last] == needle[last]
            && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn lolbin_scan(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap lolbin-scan <pe-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    let is_pe = data.len() >= 2 && &data[..2] == b"MZ";
    let hits = scan_lolbins(&data);

    let bin_id = format!("pe:{target}");
    if is_pe {
        graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);
    }

    let mut lines = vec![
        format!("=== LOLBin scan: {target} ==="),
        format!("Bytes scanned:   {}", data.len()),
        format!("LOLBin hits:     {}", hits.len()),
    ];
    if !hits.is_empty() {
        lines.push(String::new());
        for name in &hits {
            lines.push(format!("  ⚠ {name}"));
        }
        if is_pe {
            if let Some(node) = graph.nodes.get_mut(&bin_id) {
                node.attrs.insert("uses_lolbin".into(), "true".into());
                node.attrs.insert("lolbins".into(), hits.join(","));
                node.attrs.insert("lolbin_count".into(), hits.len().to_string());
            }
        }
    } else if is_pe {
        if let Some(node) = graph.nodes.get_mut(&bin_id) {
            node.attrs.insert("uses_lolbin".into(), "false".into());
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dyndns_data_loaded() {
        let s = dyndns_suffixes();
        assert!(s.contains("no-ip.org"));
        assert!(s.contains("dynu.com"));
        assert!(s.len() >= 30);
    }

    #[test]
    fn dyndns_match_with_dot_boundary() {
        assert!(host_is_dyndns("foo.no-ip.org"));
        assert!(host_is_dyndns("Foo.No-Ip.Org"));
        assert!(host_is_dyndns("no-ip.org"));         // exact
        assert!(!host_is_dyndns("xno-ip.org"));        // no dot boundary
        assert!(!host_is_dyndns("example.com"));
    }

    #[test]
    fn tld_data_loaded() {
        let t = valid_tlds();
        assert!(t.contains("com"));
        assert!(t.contains("net"));
        assert!(t.contains("org"));
        assert!(t.len() >= 1000);
    }

    #[test]
    fn tld_whitelist_rejects_filename_hostnames() {
        assert!(host_has_valid_tld("example.com"));
        assert!(host_has_valid_tld("api.example.org"));
        assert!(!host_has_valid_tld("config.json"));
        assert!(!host_has_valid_tld("weights.bin"));
        assert!(!host_has_valid_tld("foo.notatld"));
    }

    #[test]
    fn tld_whitelist_short_circuits_for_ips() {
        assert!(host_has_valid_tld("192.168.1.1"));
        assert!(host_has_valid_tld("[::1]"));
    }

    #[test]
    fn lolbin_data_loaded() {
        let l = lolbin_names();
        assert!(l.contains("certutil"));
        assert!(l.contains("bitsadmin"));
        assert!(l.contains("rundll32"));
        assert!(l.len() >= 90);
    }

    #[test]
    fn lolbin_scan_hits_certutil() {
        let blob = b"\x00\x00garbage cmd /c certutil.exe -decode \x00 more bytes";
        let hits = scan_lolbins(blob);
        assert!(hits.contains(&"certutil".to_string()),
            "expected certutil in {hits:?}");
    }

    #[test]
    fn lolbin_scan_no_false_match_inside_word() {
        // "rundll32xyz" should not trigger "rundll32".
        let blob = b"some_rundll32xyz_thing";
        let hits = scan_lolbins(blob);
        assert!(!hits.contains(&"rundll32".to_string()),
            "false-positive on word-boundary: {hits:?}");
    }

    #[test]
    fn lolbin_scan_empty_clean() {
        let hits = scan_lolbins(b"this string has no LOL binaries in it at all.");
        assert!(hits.is_empty(), "expected empty, got {hits:?}");
    }
}
