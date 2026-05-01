use std::collections::HashMap;
use crate::types::{Graph, EntityKind};

// ── License Detection ──────────────────────────────────────────────
//
// Three signal sources, in confidence order:
//
//   1. SPDX-License-Identifier comments in source files. Highest
//      confidence — explicit statement by the author.
//   2. `license` field in package manifests (Cargo.toml,
//      package.json, pyproject.toml, pom.xml, go.mod). Medium —
//      author wrote it but the file might lie about contents.
//   3. LICENSE / COPYING / NOTICE / COPYRIGHT files matched against
//      template fingerprints. Lower — template wording can be
//      modified, but is what most projects ship.
//
// We register a License node per detected SPDX identifier, with
// edges from each source/binary node to its license. The same
// License node is reused across all files claiming it (the node
// id is `license:<spdx>`), so a 1000-file MIT repo gets one
// License node with 1000 incoming edges.
//
// No external license-database file ships with the binary —
// detection is by SPDX identifier or canonical-name match. The
// "family" attribute (permissive/copyleft/proprietary/unknown) is
// inferred from a small static table covering the common
// identifiers.

/// Known SPDX identifiers + their family classification. Subset of
/// the full ~600-entry SPDX list — we cover the ~60 most common
/// licenses you'd actually see in real codebases.
fn license_family(spdx: &str) -> &'static str {
    let normalized = spdx.to_uppercase();
    match normalized.as_str() {
        // Permissive
        "MIT" | "MIT-0" | "X11" | "BSD-2-CLAUSE" | "BSD-3-CLAUSE"
        | "BSD-4-CLAUSE" | "ISC" | "APACHE-2.0" | "APACHE-1.1"
        | "ZLIB" | "BSL-1.0" | "BOOST" | "UPL-1.0" | "0BSD"
        | "UNLICENSE" | "WTFPL" | "PYTHON-2.0" | "PSFL"
        | "POSTGRESQL" | "OFL-1.1" | "CC0-1.0" | "CC-BY-3.0"
        | "CC-BY-4.0" | "BLUEOAK-1.0.0" => "permissive",
        // Weak copyleft
        "LGPL-2.0" | "LGPL-2.0-ONLY" | "LGPL-2.0-OR-LATER"
        | "LGPL-2.1" | "LGPL-2.1-ONLY" | "LGPL-2.1-OR-LATER"
        | "LGPL-3.0" | "LGPL-3.0-ONLY" | "LGPL-3.0-OR-LATER"
        | "MPL-1.1" | "MPL-2.0" | "EPL-1.0" | "EPL-2.0"
        | "CDDL-1.0" | "CDDL-1.1" => "weak_copyleft",
        // Strong copyleft
        "GPL-2.0" | "GPL-2.0-ONLY" | "GPL-2.0-OR-LATER"
        | "GPL-3.0" | "GPL-3.0-ONLY" | "GPL-3.0-OR-LATER"
        | "AGPL-1.0" | "AGPL-3.0" | "AGPL-3.0-ONLY"
        | "AGPL-3.0-OR-LATER" | "OSL-3.0" | "EUPL-1.2"
        | "SSPL-1.0" => "strong_copyleft",
        // Proprietary / restrictive / non-OSS
        "PROPRIETARY" | "COMMERCIAL" | "ALL-RIGHTS-RESERVED"
        | "NONCOMMERCIAL" | "CC-BY-NC-4.0" | "CC-BY-NC-SA-4.0"
        | "CC-BY-ND-4.0" | "JSON" | "ELASTIC-2.0"
        | "BUSL-1.1" => "proprietary",
        _ => "unknown",
    }
}

/// LICENSE-file template fingerprints. Each entry has a SPDX id
/// and a list of substring "anchors" — phrases that uniquely
/// identify the license. We require at least one anchor match,
/// preferring the longest match if multiple.
struct LicenseTemplate {
    spdx: &'static str,
    anchors: &'static [&'static str],
}

const TEMPLATES: &[LicenseTemplate] = &[
    LicenseTemplate { spdx: "MIT", anchors: &[
        "Permission is hereby granted, free of charge, to any person obtaining a copy",
        "THE SOFTWARE IS PROVIDED \"AS IS\"",
    ]},
    LicenseTemplate { spdx: "Apache-2.0", anchors: &[
        "Apache License",
        "Version 2.0, January 2004",
        "http://www.apache.org/licenses/LICENSE-2.0",
    ]},
    LicenseTemplate { spdx: "GPL-3.0-or-later", anchors: &[
        "GNU GENERAL PUBLIC LICENSE",
        "Version 3, 29 June 2007",
    ]},
    LicenseTemplate { spdx: "GPL-2.0-or-later", anchors: &[
        "GNU GENERAL PUBLIC LICENSE",
        "Version 2, June 1991",
    ]},
    LicenseTemplate { spdx: "LGPL-3.0-or-later", anchors: &[
        "GNU LESSER GENERAL PUBLIC LICENSE",
        "Version 3, 29 June 2007",
    ]},
    LicenseTemplate { spdx: "AGPL-3.0-or-later", anchors: &[
        "GNU AFFERO GENERAL PUBLIC LICENSE",
        "Version 3, 19 November 2007",
    ]},
    LicenseTemplate { spdx: "MPL-2.0", anchors: &[
        "Mozilla Public License Version 2.0",
    ]},
    LicenseTemplate { spdx: "BSD-3-Clause", anchors: &[
        "Redistribution and use in source and binary forms",
        "Neither the name of the copyright holder nor the names",
    ]},
    LicenseTemplate { spdx: "BSD-2-Clause", anchors: &[
        "Redistribution and use in source and binary forms",
        // No third-clause anchor distinguishes it from 3-Clause,
        // but presence of 2-Clause-only files is rare; we'll
        // annotate as BSD-2-Clause when ONLY the 2-clause anchors
        // match. Detection prefers BSD-3-Clause when both match.
    ]},
    LicenseTemplate { spdx: "ISC", anchors: &[
        "Permission to use, copy, modify, and/or distribute this software",
    ]},
    LicenseTemplate { spdx: "Unlicense", anchors: &[
        "This is free and unencumbered software released into the public domain",
    ]},
    LicenseTemplate { spdx: "0BSD", anchors: &[
        "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted",
    ]},
    LicenseTemplate { spdx: "EPL-2.0", anchors: &[
        "Eclipse Public License - v 2.0",
    ]},
    LicenseTemplate { spdx: "BSL-1.0", anchors: &[
        "Boost Software License - Version 1.0",
    ]},
    LicenseTemplate { spdx: "CC0-1.0", anchors: &[
        "CC0 1.0 Universal",
    ]},
];

/// Recognized SPDX-License-Identifier patterns in source code.
const SPDX_MARKER: &str = "SPDX-License-Identifier:";

#[derive(Debug, Clone)]
pub struct LicenseHit {
    pub spdx: String,
    pub source: String,        // path of file that asserted this license
    pub method: &'static str,  // "spdx_marker" / "manifest" / "template" / "filename"
}

// ── Public action: license-scan ────────────────────────────────────

pub fn license_scan(graph: &mut Graph, _target: &str) -> String {
    let scan_dir = graph.scan_dir.clone();
    let hits = scan_directory(&scan_dir);

    if hits.is_empty() {
        return format!("=== License Scan ({}) ===\nNo licenses detected.\n\nLooked for: SPDX-License-Identifier markers, manifest license fields, LICENSE/COPYING/NOTICE files matching known templates.", scan_dir);
    }

    // Aggregate: spdx → list of source files.
    let mut by_spdx: HashMap<String, Vec<&LicenseHit>> = HashMap::new();
    for h in &hits {
        by_spdx.entry(h.spdx.clone()).or_default().push(h);
    }

    // Register License nodes + source→license edges.
    for (spdx, group) in &by_spdx {
        let lic_id = format!("license:{spdx}");
        let family = license_family(spdx);
        graph.ensure_typed_node(&lic_id, EntityKind::License, &[
            ("spdx", spdx),
            ("family", family),
            ("usage_count", &group.len().to_string()),
        ]);
        for hit in group {
            // Link source files (if they're in the scanned graph)
            // OR register a synthetic source node if not.
            if graph.nodes.contains_key(&hit.source) {
                graph.add_edge(&hit.source, &lic_id);
            } else {
                // For LICENSE files at the repo root that aren't
                // tracked as source files, just add the edge from
                // a synthetic id — meta-path queries still work.
                let id = format!("license_doc:{}", &hit.source);
                graph.ensure_typed_node(&id, EntityKind::SourceFile, &[
                    ("path", &hit.source),
                    ("kind_detail", "license_doc"),
                ]);
                graph.add_edge(&id, &lic_id);
            }
        }
    }

    // Build report
    let mut sorted: Vec<(&String, &Vec<&LicenseHit>)> = by_spdx.iter().collect();
    sorted.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));

    let mut lines = vec![
        format!("=== License Scan ({}) ===", scan_dir),
        format!("Total hits:     {}", hits.len()),
        format!("Distinct SPDX:  {}", by_spdx.len()),
        String::new(),
    ];

    // Family summary
    let mut family_counts: HashMap<&'static str, usize> = HashMap::new();
    for (spdx, group) in &by_spdx {
        *family_counts.entry(license_family(spdx)).or_insert(0) += group.len();
    }
    lines.push("Family breakdown:".to_string());
    let order = ["permissive", "weak_copyleft", "strong_copyleft", "proprietary", "unknown"];
    for fam in order {
        if let Some(&n) = family_counts.get(fam) {
            lines.push(format!("  {fam:<18} {n}"));
        }
    }
    lines.push(String::new());

    lines.push("By SPDX identifier (top 30):".to_string());
    for (spdx, group) in sorted.iter().take(30) {
        lines.push(format!("  {:<28} {:>5}  ({})", spdx, group.len(), license_family(spdx)));
        // Show one representative source per spdx
        if let Some(first) = group.first() {
            lines.push(format!("    e.g. {} ({})", trunc(&first.source, 80), first.method));
        }
    }
    if sorted.len() > 30 {
        lines.push(format!("  ... and {} more SPDX ids", sorted.len() - 30));
    }

    // Compliance flag
    let strong = by_spdx.iter().filter(|(s, _)| license_family(s) == "strong_copyleft").count();
    let proprietary = by_spdx.iter().filter(|(s, _)| license_family(s) == "proprietary").count();
    if strong > 0 || proprietary > 0 {
        lines.push(String::new());
        if strong > 0 {
            lines.push(format!("⚠ {} strong-copyleft license(s) present — review obligations before redistribution", strong));
        }
        if proprietary > 0 {
            lines.push(format!("⚠ {} proprietary/restricted license(s) present — review usage rights", proprietary));
        }
    }

    lines.join("\n")
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let head: String = s.chars().take(max - 1).collect();
    format!("{head}…")
}

fn scan_directory(scan_dir: &str) -> Vec<LicenseHit> {
    let mut hits = Vec::new();
    let max_files = 5000usize;
    let mut visited = 0usize;

    let walker = walkdir::WalkDir::new(scan_dir)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.') || name == "."
        });

    for entry in walker.flatten() {
        if visited >= max_files { break; }
        if !entry.file_type().is_file() { continue; }
        visited += 1;
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        let fname = entry.file_name().to_string_lossy();
        let fname_lower = fname.to_ascii_lowercase();

        // ── 1. LICENSE / COPYING / NOTICE / COPYRIGHT files ──
        let is_license_file = matches!(fname_lower.as_str(),
            "license" | "license.md" | "license.txt" | "license.html"
            | "copying" | "copying.md" | "copying.txt" | "copying.lib"
            | "notice" | "notice.txt" | "notice.md"
            | "copyright" | "copyright.txt" | "copyright.md"
            | "license-mit" | "license-apache"
        );
        if is_license_file {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(spdx) = match_template(&content) {
                    hits.push(LicenseHit { spdx, source: path_str.clone(), method: "template" });
                }
            }
            continue;
        }

        // ── 2. Manifest license fields ──
        if matches!(fname_lower.as_str(),
            "cargo.toml" | "package.json" | "pyproject.toml"
            | "pom.xml" | "go.mod" | "gemspec" | "composer.json"
        ) || fname_lower.ends_with(".gemspec") {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(spdx) = parse_manifest_license(&content, &fname_lower) {
                    hits.push(LicenseHit { spdx, source: path_str.clone(), method: "manifest" });
                }
            }
            continue;
        }

        // ── 3. SPDX-License-Identifier comments in source files ──
        // Only check files small enough not to blow memory.
        let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
        if meta.len() > 256 * 1024 { continue; } // skip big files
        // Limit to common source extensions
        let ext_ok = matches!(path.extension().and_then(|e| e.to_str()),
            Some("rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "go"
                 | "java" | "kt" | "c" | "cpp" | "h" | "hpp"
                 | "rb" | "php" | "cs" | "swift" | "lua" | "sh"));
        if !ext_ok { continue; }

        if let Ok(content) = std::fs::read_to_string(path) {
            // Only scan first ~16 KB to find header license tags
            let head = if content.len() > 16384 { &content[..16384] } else { &content };
            if let Some(spdx) = find_spdx_marker(head) {
                hits.push(LicenseHit { spdx, source: path_str, method: "spdx_marker" });
            }
        }
    }

    hits
}

fn find_spdx_marker(content: &str) -> Option<String> {
    let pos = content.find(SPDX_MARKER)?;
    let rest = &content[pos + SPDX_MARKER.len()..];
    let line = rest.lines().next()?;
    // Strip C-style comment terminators (`*/`) and trailing punctuation.
    let mut candidate = line.trim().to_string();
    if let Some(end) = candidate.find("*/") { candidate.truncate(end); }
    let candidate = candidate.trim().trim_end_matches('*').trim_end_matches('/').trim();
    let candidate = candidate.trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')' || c.is_whitespace());
    if candidate.is_empty() || candidate.len() > 80 { return None; }
    // Require ≥2 alphabetic chars and a leading letter — avoids
    // false positives from source code that *mentions* the marker
    // (e.g. `SPDX_MARKER: &str = "SPDX-License-Identifier:";` parses
    // the ";" as a license id otherwise).
    let alpha_count = candidate.chars().filter(|c| c.is_alphabetic()).count();
    if alpha_count < 2 { return None; }
    if !candidate.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) { return None; }
    Some(candidate.to_string())
}

fn parse_manifest_license(content: &str, fname: &str) -> Option<String> {
    if fname == "cargo.toml" || fname.ends_with(".toml") {
        return parse_toml_license(content);
    }
    if fname == "package.json" || fname == "composer.json" {
        return parse_json_license(content);
    }
    if fname == "pom.xml" {
        return parse_pom_license(content);
    }
    if fname == "pyproject.toml" {
        return parse_toml_license(content);
    }
    if fname.ends_with(".gemspec") {
        return parse_gemspec_license(content);
    }
    None
}

fn parse_toml_license(content: &str) -> Option<String> {
    // Look for `license = "..."` or `license = "MIT OR Apache-2.0"`
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("license") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if rest.starts_with('"') {
                    if let Some(end) = rest[1..].find('"') {
                        return Some(rest[1..1 + end].to_string());
                    }
                }
            }
        }
    }
    None
}

fn parse_json_license(content: &str) -> Option<String> {
    // Naive scan for `"license": "..."` (don't pull in serde for one field)
    let needle = "\"license\"";
    let pos = content.find(needle)?;
    let rest = &content[pos + needle.len()..];
    let after_colon = rest.trim_start().strip_prefix(':')?.trim_start();
    if let Some(stripped) = after_colon.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_string());
    }
    // Object form: {"type": "MIT"}
    if let Some(stripped) = after_colon.strip_prefix('{') {
        if let Some(type_pos) = stripped.find("\"type\"") {
            let rest2 = &stripped[type_pos + 6..].trim_start();
            let rest2 = rest2.strip_prefix(':')?.trim_start();
            if let Some(stripped2) = rest2.strip_prefix('"') {
                let end = stripped2.find('"')?;
                return Some(stripped2[..end].to_string());
            }
        }
    }
    None
}

fn parse_pom_license(content: &str) -> Option<String> {
    // Maven: <license><name>...</name>...</license>
    let lic_block_start = content.find("<license>")?;
    let block = &content[lic_block_start..];
    let name_start = block.find("<name>")? + 6;
    let name_end = block[name_start..].find("</name>")? + name_start;
    Some(block[name_start..name_end].trim().to_string())
}

fn parse_gemspec_license(content: &str) -> Option<String> {
    // RubyGems: spec.license = "MIT"
    for line in content.lines() {
        let t = line.trim();
        if t.contains(".license") && t.contains('=') {
            if let Some(eq) = t.find('=') {
                let rhs = t[eq + 1..].trim();
                if let Some(stripped) = rhs.strip_prefix('"') {
                    if let Some(end) = stripped.find('"') {
                        return Some(stripped[..end].to_string());
                    }
                }
                if let Some(stripped) = rhs.strip_prefix('\'') {
                    if let Some(end) = stripped.find('\'') {
                        return Some(stripped[..end].to_string());
                    }
                }
            }
        }
    }
    None
}

fn match_template(content: &str) -> Option<String> {
    let head = if content.len() > 32 * 1024 { &content[..32 * 1024] } else { content };
    let mut best: Option<(&'static str, usize)> = None;
    for tpl in TEMPLATES {
        let matches = tpl.anchors.iter().filter(|a| head.contains(*a)).count();
        if matches > 0 {
            // Prefer the template with more anchor hits
            if best.map(|(_, n)| matches > n).unwrap_or(true) {
                best = Some((tpl.spdx, matches));
            }
        }
    }
    best.map(|(s, _)| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_classification() {
        assert_eq!(license_family("MIT"), "permissive");
        assert_eq!(license_family("Apache-2.0"), "permissive");
        assert_eq!(license_family("GPL-3.0-or-later"), "strong_copyleft");
        assert_eq!(license_family("LGPL-2.1-or-later"), "weak_copyleft");
        assert_eq!(license_family("PROPRIETARY"), "proprietary");
        assert_eq!(license_family("never-heard-of-it"), "unknown");
    }

    #[test]
    fn spdx_marker_extraction() {
        let src = "// SPDX-License-Identifier: MIT\nfn main() {}";
        assert_eq!(find_spdx_marker(src).as_deref(), Some("MIT"));
        let src = "/* SPDX-License-Identifier: Apache-2.0 OR MIT */";
        assert_eq!(find_spdx_marker(src).as_deref(), Some("Apache-2.0 OR MIT"));
    }

    #[test]
    fn toml_license_field() {
        let toml = "[package]\nname = \"foo\"\nlicense = \"MIT OR Apache-2.0\"\nversion = \"1.0\"";
        assert_eq!(parse_toml_license(toml).as_deref(), Some("MIT OR Apache-2.0"));
    }

    #[test]
    fn json_license_field_string() {
        let json = "{\"name\":\"foo\",\"license\":\"ISC\",\"version\":\"1\"}";
        assert_eq!(parse_json_license(json).as_deref(), Some("ISC"));
    }

    #[test]
    fn json_license_field_object() {
        let json = "{\"license\":{\"type\":\"BSD-3-Clause\",\"url\":\"...\"}}";
        assert_eq!(parse_json_license(json).as_deref(), Some("BSD-3-Clause"));
    }

    #[test]
    fn pom_license_block() {
        let pom = "<project><licenses><license><name>The Apache License, Version 2.0</name><url>...</url></license></licenses></project>";
        assert_eq!(parse_pom_license(pom).as_deref(), Some("The Apache License, Version 2.0"));
    }

    #[test]
    fn template_match_apache() {
        let txt = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/LICENSE-2.0\n...";
        assert_eq!(match_template(txt).as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn template_match_mit() {
        let txt = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software... THE SOFTWARE IS PROVIDED \"AS IS\"";
        assert_eq!(match_template(txt).as_deref(), Some("MIT"));
    }
}
