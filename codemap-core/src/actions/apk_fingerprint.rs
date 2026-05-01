// ── APK Protector / Packer / Library Fingerprint (5.38.0 — Ship A) ─
//
// Identifies Android DRM, anti-tamper, and packaging products by
// matching ZIP archive entry names against signatures mined from
// Detect-It-Easy's APK rule set (~46 families, ~190 distinct paths).
//
// Each DiE detector is a one-liner of the form
//   APK.isArchiveRecordPresent("lib/.../libfoo.so")
// which we regex-mine into a flat (kind, family, paths) table at
// build time (`codemap-core/data/apk-protectors.json`).
//
// Match policy (heuristic, tunable):
//   - Signature path with a `/` → exact match against the full ZIP
//     entry name.
//   - Signature path without `/` (e.g. `libsandhook.so`) → match
//     against the basename of any entry. Some DiE rules use bare
//     filenames because they fire regardless of arch directory.
//
// Output: tags the existing AndroidPackage node with attributes
// keyed by signature kind: `protector`, `packer`, `library`. Value
// is a comma-separated list of detected family names so analysts
// can filter via attribute query.

use crate::types::{Graph, EntityKind};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const PROTECTORS_JSON: &str = include_str!("../../data/apk-protectors.json");

#[derive(Deserialize, Debug)]
struct Family {
    family: String,
    paths: Vec<String>,
}

fn load_signatures() -> BTreeMap<String, Vec<Family>> {
    serde_json::from_str(PROTECTORS_JSON).unwrap_or_default()
}

pub fn apk_fingerprint(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap apk-fingerprint <apk-file>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 4 || &data[..4] != b"PK\x03\x04" {
        return format!("Not an APK/ZIP: {target}");
    }

    let entries = walk_entries(&data);
    let matches = match_signatures(&entries, &load_signatures());

    let apk_id = format!("apk:{target}");
    graph.ensure_typed_node(&apk_id, EntityKind::AndroidPackage, &[
        ("path", target),
        ("zip_entries", &entries.len().to_string()),
    ]);

    let mut lines = vec![
        format!("=== APK Fingerprint: {target} ==="),
        format!("ZIP entries:       {}", entries.len()),
    ];

    if matches.is_empty() {
        lines.push(String::new());
        lines.push("No known protector / packer / library detected.".to_string());
        if let Some(node) = graph.nodes.get_mut(&apk_id) {
            node.attrs.insert("apk_fingerprint".into(), "clean".into());
        }
        return lines.join("\n");
    }

    if let Some(node) = graph.nodes.get_mut(&apk_id) {
        node.attrs.insert("apk_fingerprint".into(), "detected".into());
    }
    for (kind, items) in &matches {
        lines.push(String::new());
        lines.push(format!("── {kind} ({} match{}) ──",
            items.len(), if items.len() == 1 { "" } else { "es" }));
        let mut family_names: Vec<&str> = Vec::new();
        for (family, paths) in items {
            family_names.push(family.as_str());
            lines.push(format!("  {family}"));
            for p in paths.iter().take(5) {
                lines.push(format!("    └── {p}"));
            }
            if paths.len() > 5 {
                lines.push(format!("    └── ... and {} more", paths.len() - 5));
            }
        }
        let joined = family_names.join(",");
        if let Some(node) = graph.nodes.get_mut(&apk_id) {
            node.attrs.insert(kind.clone(), joined);
        }
    }

    lines.join("\n")
}

fn match_signatures(
    entries: &[String],
    sigs: &BTreeMap<String, Vec<Family>>,
) -> BTreeMap<String, Vec<(String, Vec<String>)>> {
    let mut full: BTreeSet<&str> = BTreeSet::new();
    let mut basenames: BTreeSet<&str> = BTreeSet::new();
    for e in entries {
        full.insert(e.as_str());
        let base = match e.rfind('/') {
            Some(i) => &e[i + 1..],
            None => e.as_str(),
        };
        basenames.insert(base);
    }

    let mut out: BTreeMap<String, Vec<(String, Vec<String>)>> = BTreeMap::new();
    for (kind, families) in sigs {
        for fam in families {
            let mut hits = Vec::new();
            for sig_path in &fam.paths {
                let matched = if sig_path.contains('/') {
                    full.contains(sig_path.as_str())
                } else {
                    basenames.contains(sig_path.as_str())
                };
                if matched {
                    hits.push(sig_path.clone());
                }
            }
            if !hits.is_empty() {
                out.entry(kind.clone()).or_default().push((fam.family.clone(), hits));
            }
        }
    }
    out
}

fn walk_entries(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 30 <= data.len() {
        if &data[p..p + 4] != b"PK\x03\x04" { break; }
        let compressed_size = u32::from_le_bytes([data[p + 18], data[p + 19], data[p + 20], data[p + 21]]);
        let name_len = u16::from_le_bytes([data[p + 26], data[p + 27]]);
        let extra_len = u16::from_le_bytes([data[p + 28], data[p + 29]]);
        let name_start = p + 30;
        let name_end = name_start + name_len as usize;
        if name_end > data.len() { break; }
        out.push(String::from_utf8_lossy(&data[name_start..name_end]).to_string());
        let body_start = name_end + extra_len as usize;
        let body_end = body_start + compressed_size as usize;
        p = body_end;
        if out.len() > 50_000 { break; }
        if p + 4 > data.len() { break; }
        if &data[p..p + 4] == b"PK\x01\x02" { break; }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stored ZIP local-file header. Body is zero-length so we
    /// only need name. CRC, sizes are all 0 because we set
    /// compression_method=0 (stored) and compressed_size=0.
    fn make_zip(entries: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for name in entries {
            out.extend_from_slice(b"PK\x03\x04");          // local-file magic
            out.extend_from_slice(&[0u8; 2]);              // version needed
            out.extend_from_slice(&[0u8; 2]);              // flags
            out.extend_from_slice(&[0u8; 2]);              // compression (0 = stored)
            out.extend_from_slice(&[0u8; 2]);              // mod time
            out.extend_from_slice(&[0u8; 2]);              // mod date
            out.extend_from_slice(&[0u8; 4]);              // crc32
            out.extend_from_slice(&[0u8; 4]);              // compressed size
            out.extend_from_slice(&[0u8; 4]);              // uncompressed size
            let nlen = name.len() as u16;
            out.extend_from_slice(&nlen.to_le_bytes());    // name len
            out.extend_from_slice(&[0u8; 2]);              // extra len
            out.extend_from_slice(name.as_bytes());
        }
        // Central-directory sentinel so walk_entries terminates cleanly.
        out.extend_from_slice(b"PK\x01\x02");
        out
    }

    #[test]
    fn signatures_load_nonempty() {
        let sigs = load_signatures();
        assert!(!sigs.is_empty(), "embedded apk-protectors.json failed to parse");
        // Mining target was 46 families; allow drift.
        let total: usize = sigs.values().map(|v| v.len()).sum();
        assert!(total >= 30, "expected ≥30 families, got {total}");
    }

    #[test]
    fn detects_bangcle_by_full_path() {
        let zip = make_zip(&[
            "AndroidManifest.xml",
            "lib/armeabi/libsecexe.so",
            "classes.dex",
        ]);
        let entries = walk_entries(&zip);
        let matches = match_signatures(&entries, &load_signatures());
        let prot = matches.get("protector").expect("protector kind missing");
        assert!(prot.iter().any(|(f, _)| f == "BangcleProtection"),
            "expected BangcleProtection, got: {:?}", prot.iter().map(|(f,_)| f).collect::<Vec<_>>());
    }

    #[test]
    fn detects_dexprotector_by_full_path() {
        let zip = make_zip(&[
            "AndroidManifest.xml",
            "assets/classes.dex.dat",
            "lib/armeabi-v7a/libdexprotector.so",
        ]);
        let entries = walk_entries(&zip);
        let matches = match_signatures(&entries, &load_signatures());
        let prot = matches.get("protector").unwrap();
        assert!(prot.iter().any(|(f, _)| f == "DexProtector"));
    }

    #[test]
    fn detects_kony_by_basename() {
        // Kony's signature is the bare filename `libkonyjsvm.so` — match
        // by basename even when the ZIP entry includes an arch dir.
        let zip = make_zip(&["lib/armeabi-v7a/libkonyjsvm.so"]);
        let entries = walk_entries(&zip);
        let matches = match_signatures(&entries, &load_signatures());
        let pack = matches.get("packer").unwrap();
        assert!(pack.iter().any(|(f, _)| f == "Kony"));
    }

    #[test]
    fn clean_apk_no_match() {
        let zip = make_zip(&[
            "AndroidManifest.xml",
            "classes.dex",
            "resources.arsc",
        ]);
        let entries = walk_entries(&zip);
        let matches = match_signatures(&entries, &load_signatures());
        assert!(matches.is_empty(), "clean APK should have no matches, got {matches:?}");
    }

    #[test]
    fn walk_entries_handles_zero_length() {
        assert_eq!(walk_entries(&[]).len(), 0);
        assert_eq!(walk_entries(b"not-a-zip-at-all").len(), 0);
    }
}
