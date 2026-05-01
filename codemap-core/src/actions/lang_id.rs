// ── Source-Language Identification (Ship 5 — lang-id) ─────────────
//
// Tags PE / ELF / Mach-O binaries with the high-level source
// language they were compiled from: `rust` / `go` / `dotnet` /
// `unknown`. Rust binaries also get a `version` attribute when the
// rustc commit-hash string is present.
//
// Modeled on FLARE FLOSS's `floss/language/identify.py` (Apache-2.0)
// but extended past FLOSS's PE-only scope: the Rust commit-hash
// strings and Go pclntab magic bytes appear identically in ELF /
// Mach-O binaries, so the same detector works cross-OS.
//
// Three independent detectors:
//
//   1. Rust — regex on extracted strings:
//        rustc/<40-hex>/library         → commit-hash → version DB
//        rustc/<x.y.z>/library          → explicit version
//      The DB lives at `data/rustc_versions.toml` (119 entries
//      covering 1.0 .. 1.74). FLOSS-derived; refreshable offline.
//
//   2. Go — pclntab magic-byte scan:
//        \xfb\xff\xff\xff\x00\x00 → 1.12
//        \xfa\xff\xff\xff\x00\x00 → 1.16
//        \xf0\xff\xff\xff\x00\x00 → 1.18
//        \xf1\xff\xff\xff\x00\x00 → 1.20
//      Validated by reading pc_quantum ∈ {1,2,4} and pointer_size ∈
//      {4,8} at offsets +6/+7. Fallback: look for any of 8 known
//      runtime function strings.
//
//   3. .NET — PE only: IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.Size != 0
//      in the optional header (data directory index 14).
//
// Each detection updates the existing PE/ELF/Mach-O binary node in
// place (no new EntityKind) — language is metadata, not structure.

use crate::types::{Graph, EntityKind};
use std::sync::OnceLock;
use std::collections::HashMap;

const RUSTC_VERSIONS_TOML: &str = include_str!("../../data/rustc_versions.toml");

/// Lazily parsed commit-hash → version map. The TOML file is a flat
/// `"hash" = "version"` table — we use a tiny hand-parser to avoid
/// dragging in a TOML crate just for one static lookup.
fn rustc_db() -> &'static HashMap<&'static str, &'static str> {
    static DB: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    DB.get_or_init(|| {
        let mut m = HashMap::new();
        for line in RUSTC_VERSIONS_TOML.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            // Expect: "hash" = "version"
            let eq = match line.find('=') { Some(i) => i, None => continue };
            let key = line[..eq].trim().trim_matches('"');
            let val = line[eq + 1..].trim().trim_matches('"');
            if key.len() == 40 && key.chars().all(|c| c.is_ascii_hexdigit()) {
                m.insert(key, val);
            }
        }
        m
    })
}

// Go pclntab magic bytes (header). Each maps to a Go release line.
const GO_MAGIC_112: &[u8] = b"\xfb\xff\xff\xff\x00\x00";
const GO_MAGIC_116: &[u8] = b"\xfa\xff\xff\xff\x00\x00";
const GO_MAGIC_118: &[u8] = b"\xf0\xff\xff\xff\x00\x00";
const GO_MAGIC_120: &[u8] = b"\xf1\xff\xff\xff\x00\x00";

/// Fallback Go runtime function strings. If the pclntab header has been
/// stripped or patched, these usually survive.
const GO_RUNTIME_FUNCS: &[&[u8]] = &[
    b"runtime.main",
    b"runtime.morestack",
    b"runtime.morestack_noctxt",
    b"runtime.gcWork",
    b"runtime.newproc",
    b"runtime.gcWriteBarrier",
    b"runtime.Gosched",
    b"main.main",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinFmt { Pe, Elf, MachO, Unknown }

impl BinFmt {
    fn detect(data: &[u8]) -> Self {
        if data.len() < 4 { return BinFmt::Unknown; }
        if &data[..4] == b"\x7FELF" { return BinFmt::Elf; }
        if &data[..2] == b"MZ" {
            if data.len() >= 0x40 {
                let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
                if e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                    return BinFmt::Pe;
                }
            }
        }
        let mag_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mag_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if mag_le == 0xFEEDFACE || mag_le == 0xFEEDFACF || mag_be == 0xFEEDFACE || mag_be == 0xFEEDFACF {
            return BinFmt::MachO;
        }
        BinFmt::Unknown
    }
}

#[derive(Debug, Clone, Default)]
pub struct LangResult {
    pub language: String,           // "rust" | "go" | "dotnet" | "unknown"
    pub version: Option<String>,    // rustc 1.x.y or go 1.x; None for dotnet/unknown
    pub evidence: String,           // human-readable reason
}

/// Pure detection — separated from graph wiring for testability.
pub fn detect_language(data: &[u8]) -> LangResult {
    let fmt = BinFmt::detect(data);

    // 1. Rust (cross-OS, string-based)
    if let Some((ver, anchor)) = detect_rust(data) {
        return LangResult {
            language: "rust".to_string(),
            version: Some(ver),
            evidence: format!("rustc anchor: {anchor}"),
        };
    }

    // 2. Go (cross-OS — pclntab on PE/ELF/Mach-O)
    if let Some((ver, anchor)) = detect_go(data) {
        return LangResult {
            language: "go".to_string(),
            version: ver,
            evidence: anchor,
        };
    }

    // 3. .NET (PE-only)
    if fmt == BinFmt::Pe {
        if detect_dotnet_pe(data) {
            return LangResult {
                language: "dotnet".to_string(),
                version: None,
                evidence: "PE COM descriptor data directory non-empty".to_string(),
            };
        }
    }

    LangResult {
        language: "unknown".to_string(),
        version: None,
        evidence: format!("no rust/go/.net signal in {} binary", fmt_name(fmt)),
    }
}

fn fmt_name(f: BinFmt) -> &'static str {
    match f {
        BinFmt::Pe => "PE",
        BinFmt::Elf => "ELF",
        BinFmt::MachO => "Mach-O",
        BinFmt::Unknown => "unknown-format",
    }
}

/// Rust detection — scan for `rustc/<hash>/library` or
/// `rustc/<x.y.z>/library`. Returns (version, anchor-string).
fn detect_rust(data: &[u8]) -> Option<(String, String)> {
    // Cap scan to first 64 MB — these strings always live in .rodata
    // / __TEXT,__const which is well under that on every realistic
    // binary, including stripped 30 MB Rust ones.
    let scan = &data[..data.len().min(64 * 1024 * 1024)];
    let needle = b"rustc/";
    let mut i = 0usize;
    while i + needle.len() < scan.len() {
        if scan[i] == needle[0] && scan[i..i + needle.len()] == *needle {
            // We found "rustc/". Read up to the next "/library" within
            // a reasonable distance (50 chars).
            let after = i + needle.len();
            let lib_search_end = (after + 50).min(scan.len());
            if let Some(rel) = find_subseq(&scan[after..lib_search_end], b"/library") {
                let body = &scan[after..after + rel];
                let body_str = match std::str::from_utf8(body) {
                    Ok(s) => s,
                    Err(_) => { i += 1; continue; }
                };
                // Try commit-hash form first (more common in stripped
                // builds).
                if body_str.len() == 40 && body_str.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
                    let version = rustc_db()
                        .get(body_str)
                        .map(|v| (*v).to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    return Some((version, format!("rustc/{body_str}/library")));
                }
                // Try explicit version form: x.y.z (digits + dots only).
                if !body_str.is_empty()
                    && body_str.split('.').count() >= 2
                    && body_str.chars().all(|c| c.is_ascii_digit() || c == '.')
                {
                    return Some((body_str.to_string(), format!("rustc/{body_str}/library")));
                }
            }
        }
        i += 1;
    }
    None
}

/// Go detection — pclntab magic-byte scan + verify, then fallback to
/// runtime function strings. Returns (version-opt, anchor-description).
fn detect_go(data: &[u8]) -> Option<(Option<String>, String)> {
    let scan = &data[..data.len().min(128 * 1024 * 1024)];
    let magics: [(&[u8], &str); 4] = [
        (GO_MAGIC_112, "1.12"),
        (GO_MAGIC_116, "1.16"),
        (GO_MAGIC_118, "1.18"),
        (GO_MAGIC_120, "1.20"),
    ];
    for (magic, version) in &magics {
        if let Some(off) = find_subseq(scan, magic) {
            // Verify pclntab header: pc_quantum at +6, pointer_size at +7.
            if off + 8 <= scan.len() {
                let pc_quantum = scan[off + 6];
                let pointer_size = scan[off + 7];
                if matches!(pc_quantum, 1 | 2 | 4) && matches!(pointer_size, 4 | 8) {
                    return Some((
                        Some((*version).to_string()),
                        format!("go pclntab magic at offset {off:#x} (pq={pc_quantum},ps={pointer_size})"),
                    ));
                }
            }
        }
    }
    // Fallback: any well-known runtime function string.
    for func in GO_RUNTIME_FUNCS {
        if find_subseq(scan, func).is_some() {
            let s = String::from_utf8_lossy(func).to_string();
            return Some((None, format!("go runtime symbol: {s}")));
        }
    }
    None
}

/// .NET detection — IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14)
/// in the PE optional header has non-zero size and VA. This is the
/// CLR-header pointer, present iff the binary is a managed .NET
/// assembly.
fn detect_dotnet_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 { return false; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() { return false; }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return false; }
    let coff = e_lfanew + 4;
    let opt_off = coff + 20;
    if opt_off + 2 > data.len() { return false; }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    // PE32 (0x10b) → data dirs at +96; PE32+ (0x20b) → data dirs at +112.
    let dd_off = match magic {
        0x10b => opt_off + 96,
        0x20b => opt_off + 112,
        _ => return false,
    };
    // Index 14 = COM_DESCRIPTOR.
    let entry_off = dd_off + 14 * 8;
    if entry_off + 8 > data.len() { return false; }
    let va = u32::from_le_bytes([data[entry_off], data[entry_off + 1], data[entry_off + 2], data[entry_off + 3]]);
    let size = u32::from_le_bytes([data[entry_off + 4], data[entry_off + 5], data[entry_off + 6], data[entry_off + 7]]);
    va != 0 && size != 0
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

// ── Action entrypoint ──────────────────────────────────────────────

pub fn lang_id(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap lang-id <pe-or-elf-or-macho-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 64 {
        return format!("File too small for language ID: {} bytes", data.len());
    }

    let fmt = BinFmt::detect(&data);
    let result = detect_language(&data);

    // Wire into the graph: ensure binary node exists (kind matches the
    // detected format), then set language/version attributes on it.
    let bin_id = match fmt {
        BinFmt::Pe => format!("pe:{target}"),
        BinFmt::Elf => format!("elf:{target}"),
        BinFmt::MachO => format!("macho:{target}"),
        BinFmt::Unknown => format!("bin:{target}"),
    };
    let kind = match fmt {
        BinFmt::Pe => Some(EntityKind::PeBinary),
        BinFmt::Elf => Some(EntityKind::ElfBinary),
        BinFmt::MachO => Some(EntityKind::MachoBinary),
        BinFmt::Unknown => None,
    };
    if let Some(k) = kind {
        graph.ensure_typed_node(&bin_id, k, &[("path", target)]);
    }
    if let Some(node) = graph.nodes.get_mut(&bin_id) {
        node.attrs.insert("language".into(), result.language.clone());
        if let Some(v) = &result.version {
            node.attrs.insert("language_version".into(), v.clone());
        }
    }

    format_report(target, fmt, &result)
}

fn format_report(target: &str, fmt: BinFmt, r: &LangResult) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Language ID: {} ===\n\n", target));
    out.push_str(&format!("Format:    {}\n", fmt_name(fmt)));
    out.push_str(&format!("Language:  {}\n", r.language));
    if let Some(v) = &r.version {
        out.push_str(&format!("Version:   {v}\n"));
    }
    out.push_str(&format!("Evidence:  {}\n", r.evidence));
    if r.language == "unknown" {
        out.push('\n');
        out.push_str("(No rust/go/.net signal found. The binary is likely C/C++/other —\n");
        out.push_str(" try `codemap lang-fingerprint` for the broader compiler/runtime fan-out.)\n");
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ skeleton with the CLR data-directory entry
    /// set. Just enough bytes for `BinFmt::detect` and
    /// `detect_dotnet_pe` to work.
    fn synthetic_pe(with_clr: bool, extra_payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // DOS header
        buf[..2].copy_from_slice(b"MZ");
        let e_lfanew = 0x80usize;
        buf[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        // PE signature
        buf[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        // COFF header (20 bytes after PE\0\0)
        // (machine type / num sections / etc. — left zero, fine for detection)
        let opt_off = e_lfanew + 4 + 20;
        // Optional header magic — PE32+
        buf[opt_off..opt_off + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        // Data directories live at opt_off + 112 for PE32+.
        let dd_off = opt_off + 112;
        // Entry 14 = COM_DESCRIPTOR. 8 bytes per entry: VA(4) + Size(4).
        let com_off = dd_off + 14 * 8;
        if with_clr {
            buf[com_off..com_off + 4].copy_from_slice(&0x2000u32.to_le_bytes());
            buf[com_off + 4..com_off + 8].copy_from_slice(&0x48u32.to_le_bytes());
        }
        // Pad to fit any extra payload (rust/go strings)
        if !extra_payload.is_empty() {
            buf.extend_from_slice(extra_payload);
        }
        buf
    }

    #[test]
    fn rustc_db_loads() {
        let db = rustc_db();
        // The TOML file should produce 119 entries (1.0 .. 1.74 series).
        assert!(db.len() >= 100, "expected ≥100 entries, got {}", db.len());
        // Spot-check known rust 1.56.1 → commit hash from FLOSS.
        assert_eq!(db.get("59eed8a2aac0230a8b53e89d4e99d55912ba6b35").copied(), Some("1.56.1"));
        assert_eq!(db.get("79e9716c980570bfd1f666e3b16ac583f0168962").copied(), Some("1.74.0"));
    }

    #[test]
    fn detects_rust_via_commit_hash() {
        // Embed a hash that maps to a known version.
        let payload = b"some bytes ... rustc/59eed8a2aac0230a8b53e89d4e99d55912ba6b35/library/std ... more";
        let bin = synthetic_pe(false, payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "rust");
        assert_eq!(r.version.as_deref(), Some("1.56.1"));
    }

    #[test]
    fn detects_rust_via_explicit_version() {
        let payload = b"... rustc/1.54.0/library/core ...";
        let bin = synthetic_pe(false, payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "rust");
        assert_eq!(r.version.as_deref(), Some("1.54.0"));
    }

    #[test]
    fn detects_rust_unknown_hash() {
        // 40-char hash that's NOT in the database — language=rust,
        // version="unknown".
        let payload = b"... rustc/0123456789abcdef0123456789abcdef01234567/library/std ...";
        let bin = synthetic_pe(false, payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "rust");
        assert_eq!(r.version.as_deref(), Some("unknown"));
    }

    #[test]
    fn detects_go_via_pclntab_118() {
        // Magic + valid pc_quantum (1) + pointer_size (8) at +6/+7
        let mut payload = Vec::new();
        payload.extend_from_slice(b"prefix bytes....");
        payload.extend_from_slice(GO_MAGIC_118);
        payload.push(1u8); // pc_quantum
        payload.push(8u8); // pointer_size
        payload.extend_from_slice(&[0u8; 32]);
        let bin = synthetic_pe(false, &payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "go");
        assert_eq!(r.version.as_deref(), Some("1.18"));
    }

    #[test]
    fn detects_go_via_pclntab_120() {
        let mut payload = Vec::new();
        payload.extend_from_slice(GO_MAGIC_120);
        payload.push(2u8);
        payload.push(8u8);
        payload.extend_from_slice(&[0u8; 32]);
        let bin = synthetic_pe(false, &payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "go");
        assert_eq!(r.version.as_deref(), Some("1.20"));
    }

    #[test]
    fn rejects_go_with_invalid_pc_quantum() {
        // Magic present but pc_quantum invalid → no match.
        let mut payload = Vec::new();
        payload.extend_from_slice(GO_MAGIC_118);
        payload.push(7u8);  // invalid pc_quantum
        payload.push(8u8);
        payload.extend_from_slice(&[0u8; 32]);
        let bin = synthetic_pe(false, &payload);
        let r = detect_language(&bin);
        // Should fall through to fallback or unknown.
        assert_ne!(r.language, "go", "should not detect go with invalid pc_quantum (got: {:?})", r);
    }

    #[test]
    fn detects_go_via_runtime_fallback() {
        let payload = b"...prefix... runtime.morestack_noctxt ...suffix...";
        let bin = synthetic_pe(false, payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "go");
        assert!(r.version.is_none(), "fallback path doesn't yield a version");
    }

    #[test]
    fn detects_dotnet_via_com_descriptor() {
        let bin = synthetic_pe(true, b"");
        let r = detect_language(&bin);
        assert_eq!(r.language, "dotnet");
        assert!(r.version.is_none());
    }

    #[test]
    fn unknown_when_no_signals() {
        let bin = synthetic_pe(false, b"plain c binary nothing interesting");
        let r = detect_language(&bin);
        assert_eq!(r.language, "unknown");
    }

    #[test]
    fn rust_takes_precedence_over_go() {
        // If both signals exist, Rust wins (checked first; matches FLOSS).
        let mut payload = Vec::new();
        payload.extend_from_slice(b"rustc/1.54.0/library/std ");
        payload.extend_from_slice(GO_MAGIC_118);
        payload.push(1u8);
        payload.push(8u8);
        let bin = synthetic_pe(false, &payload);
        let r = detect_language(&bin);
        assert_eq!(r.language, "rust");
    }

    #[test]
    fn binfmt_detects_pe_elf_macho() {
        let pe = synthetic_pe(false, b"");
        assert_eq!(BinFmt::detect(&pe), BinFmt::Pe);
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7FELF");
        assert_eq!(BinFmt::detect(&elf), BinFmt::Elf);
        let mut mo = vec![0u8; 32];
        mo[..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        assert_eq!(BinFmt::detect(&mo), BinFmt::MachO);
        let other = vec![0u8; 64];
        assert_eq!(BinFmt::detect(&other), BinFmt::Unknown);
    }

    #[test]
    fn lang_id_action_writes_attrs() {
        // End-to-end: write a synthetic Go PE to disk, run the action,
        // then verify the binary node carries language=go.
        let mut payload = Vec::new();
        payload.extend_from_slice(GO_MAGIC_118);
        payload.push(1u8);
        payload.push(8u8);
        payload.extend_from_slice(&[0u8; 32]);
        let bin = synthetic_pe(false, &payload);
        let path = std::env::temp_dir().join(format!("codemap-langid-test-{}.bin", std::process::id()));
        std::fs::write(&path, &bin).unwrap();
        let mut graph = Graph { nodes: std::collections::HashMap::new(), scan_dir: "/tmp".to_string(), cpg: None };
        let target = path.to_string_lossy().to_string();
        let report = lang_id(&mut graph, &target);
        assert!(report.contains("Language:  go"));
        let bin_id = format!("pe:{target}");
        let node = graph.nodes.get(&bin_id).expect("PE binary node was registered");
        assert_eq!(node.attrs.get("language").map(String::as_str), Some("go"));
        assert_eq!(node.attrs.get("language_version").map(String::as_str), Some("1.18"));
        let _ = std::fs::remove_file(&path);
    }
}
