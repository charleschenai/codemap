use std::collections::HashMap;
use crate::types::{Graph, EntityKind};

// ── CVE Import + Match ─────────────────────────────────────────────
//
// Two actions:
//
//   cve-import <nvd-json> — parses an NVD JSON feed (1.1 or 2.0)
//   and registers a Cve node per record with attrs (id, severity,
//   cvss, year, cwe, description, cpe_products). No network — the
//   user feeds a downloaded NVD JSON dump.
//
//   cve-match — walks every Dll/Symbol node already in the graph
//   and matches its `name` attr against each Cve's `cpe_products`
//   attr. On match, adds a dll→cve edge. Together with the existing
//   source→binary→dll edges, this enables the killer query:
//   meta-path "source->binary->dll->cve" finds vulnerable
//   transitive dependencies in your code.
//
// CPE matching is intentionally simple for v1: case-insensitive
// substring match on product name. CPE version-range comparison
// (cpe:2.3:a:vendor:product:version:update:edition...) is its own
// project — we'll accept a small false-positive rate to keep the
// implementation tractable. The Cve node stores the raw CPE strings
// so users can do their own filtering downstream.

#[derive(Debug)]
struct CveRecord {
    id: String,
    severity: String,
    cvss: f64,
    year: u32,
    cwe: Vec<String>,
    description: String,
    cpe_products: Vec<String>,  // distinct product names extracted from CPEs
    cpe_full: Vec<String>,      // raw CPE 2.3 strings
}

// ── cve-import ─────────────────────────────────────────────────────

pub fn cve_import(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap cve-import <nvd-json-file>".to_string();
    }
    let raw = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return format!("JSON parse error: {e}"),
    };

    let records = parse_nvd_records(&json);
    if records.is_empty() {
        return format!("No CVE records found in {target}. Expected NVD JSON 1.1 or 2.0 schema.");
    }

    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    for rec in &records {
        let cve_id = format!("cve:{}", rec.id);
        let cvss_str = format!("{:.1}", rec.cvss);
        let year_str = rec.year.to_string();
        let cpe_joined = rec.cpe_products.join(",");
        let cpe_full_joined = rec.cpe_full.join("|");
        let cwe_joined = rec.cwe.join(",");
        let desc_short = if rec.description.len() > 240 { &rec.description[..240] } else { rec.description.as_str() };
        graph.ensure_typed_node(&cve_id, EntityKind::Cve, &[
            ("id", &rec.id),
            ("severity", &rec.severity),
            ("cvss", &cvss_str),
            ("year", &year_str),
            ("cwe", &cwe_joined),
            ("description", desc_short),
            ("cpe_products", &cpe_joined),
            ("cpe_full", &cpe_full_joined),
        ]);
        match rec.severity.as_str() {
            "CRITICAL" => critical += 1,
            "HIGH" => high += 1,
            "MEDIUM" => medium += 1,
            "LOW" => low += 1,
            _ => {}
        }
    }

    let mut lines = vec![
        format!("=== CVE Import: {} ===", target),
        format!("Records ingested: {}", records.len()),
        String::new(),
        "Severity breakdown:".to_string(),
        format!("  CRITICAL  {critical}"),
        format!("  HIGH      {high}"),
        format!("  MEDIUM    {medium}"),
        format!("  LOW       {low}"),
        String::new(),
        "Run `codemap cve-match` to link these CVEs to DLL nodes already".to_string(),
        "in the graph. Then `codemap meta-path source->binary->dll->cve`".to_string(),
        "finds vulnerable transitive dependencies in your code.".to_string(),
    ];
    let critical_examples: Vec<&CveRecord> = records.iter().filter(|r| r.severity == "CRITICAL").take(5).collect();
    if !critical_examples.is_empty() {
        lines.push(String::new());
        lines.push(format!("Sample CRITICAL records ({}):", critical_examples.len()));
        for r in critical_examples {
            let products = if r.cpe_products.is_empty() { "(no CPE)".to_string() } else { r.cpe_products.join(", ") };
            lines.push(format!("  {}  CVSS={:.1}  products={}", r.id, r.cvss, trunc(&products, 60)));
        }
    }
    lines.join("\n")
}

fn parse_nvd_records(json: &serde_json::Value) -> Vec<CveRecord> {
    let mut records = Vec::new();

    // NVD 1.1: {"CVE_Items": [{...}]}
    if let Some(items) = json.get("CVE_Items").and_then(|v| v.as_array()) {
        for item in items {
            if let Some(rec) = parse_nvd_v1(item) { records.push(rec); }
        }
        return records;
    }
    // NVD 2.0: {"vulnerabilities": [{"cve": {...}}]}
    if let Some(items) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
        for item in items {
            if let Some(cve) = item.get("cve") {
                if let Some(rec) = parse_nvd_v2(cve) { records.push(rec); }
            }
        }
        return records;
    }
    // Plain array of CVEs (some user-supplied feeds)
    if let Some(items) = json.as_array() {
        for item in items {
            if let Some(rec) = parse_nvd_v2(item).or_else(|| parse_nvd_v1(item)) {
                records.push(rec);
            }
        }
    }
    records
}

fn parse_nvd_v1(item: &serde_json::Value) -> Option<CveRecord> {
    let cve = item.get("cve")?;
    let id = cve.get("CVE_data_meta")?.get("ID")?.as_str()?.to_string();
    let year = id.split('-').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let description = cve.get("description")?.get("description_data")?
        .as_array()?
        .first()?.get("value")?.as_str().unwrap_or("").to_string();

    let mut cwe: Vec<String> = Vec::new();
    if let Some(ptypes) = cve.get("problemtype").and_then(|p| p.get("problemtype_data")).and_then(|p| p.as_array()) {
        for pt in ptypes {
            if let Some(descs) = pt.get("description").and_then(|d| d.as_array()) {
                for d in descs {
                    if let Some(v) = d.get("value").and_then(|v| v.as_str()) {
                        if v.starts_with("CWE-") { cwe.push(v.to_string()); }
                    }
                }
            }
        }
    }

    let (cvss, severity) = item.get("impact")
        .and_then(|i| i.get("baseMetricV3"))
        .and_then(|m| m.get("cvssV3"))
        .map(|c| (
            c.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0),
            c.get("baseSeverity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN").to_string(),
        ))
        .unwrap_or((0.0, "UNKNOWN".to_string()));

    let mut cpe_full: Vec<String> = Vec::new();
    if let Some(cfg) = item.get("configurations").and_then(|c| c.get("nodes")).and_then(|n| n.as_array()) {
        collect_cpes_v1(cfg, &mut cpe_full);
    }
    let cpe_products = extract_products(&cpe_full);

    Some(CveRecord {
        id, severity, cvss, year,
        cwe,
        description,
        cpe_products,
        cpe_full,
    })
}

fn parse_nvd_v2(cve: &serde_json::Value) -> Option<CveRecord> {
    let id = cve.get("id")?.as_str()?.to_string();
    let year = id.split('-').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let description = cve.get("descriptions").and_then(|d| d.as_array())
        .and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en")))
        .and_then(|d| d.get("value").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let mut cwe: Vec<String> = Vec::new();
    if let Some(weaknesses) = cve.get("weaknesses").and_then(|w| w.as_array()) {
        for w in weaknesses {
            if let Some(descs) = w.get("description").and_then(|d| d.as_array()) {
                for d in descs {
                    if let Some(v) = d.get("value").and_then(|v| v.as_str()) {
                        if v.starts_with("CWE-") { cwe.push(v.to_string()); }
                    }
                }
            }
        }
    }

    let (cvss, severity) = cve.get("metrics")
        .and_then(|m| m.get("cvssMetricV31").or_else(|| m.get("cvssMetricV30")))
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("cvssData"))
        .map(|c| (
            c.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0),
            c.get("baseSeverity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN").to_string(),
        ))
        .unwrap_or((0.0, "UNKNOWN".to_string()));

    let mut cpe_full: Vec<String> = Vec::new();
    if let Some(configs) = cve.get("configurations").and_then(|c| c.as_array()) {
        for config in configs {
            if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                collect_cpes_v2(nodes, &mut cpe_full);
            }
        }
    }
    let cpe_products = extract_products(&cpe_full);

    Some(CveRecord {
        id, severity, cvss, year,
        cwe,
        description,
        cpe_products,
        cpe_full,
    })
}

fn collect_cpes_v1(nodes: &[serde_json::Value], out: &mut Vec<String>) {
    for node in nodes {
        if let Some(matches) = node.get("cpe_match").and_then(|c| c.as_array()) {
            for m in matches {
                if let Some(uri) = m.get("cpe23Uri").and_then(|u| u.as_str()) {
                    out.push(uri.to_string());
                }
            }
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            collect_cpes_v1(children, out);
        }
    }
}

fn collect_cpes_v2(nodes: &[serde_json::Value], out: &mut Vec<String>) {
    for node in nodes {
        if let Some(matches) = node.get("cpeMatch").and_then(|c| c.as_array()) {
            for m in matches {
                if let Some(uri) = m.get("criteria").and_then(|u| u.as_str()) {
                    out.push(uri.to_string());
                }
            }
        }
    }
}

/// CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:...
/// We extract the <product> field, which is what users will match
/// DLL/binary names against.
fn extract_products(cpes: &[String]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cpe in cpes {
        if let Some(prefix_stripped) = cpe.strip_prefix("cpe:2.3:") {
            let parts: Vec<&str> = prefix_stripped.split(':').collect();
            // [0]=part, [1]=vendor, [2]=product
            if parts.len() >= 3 && parts[2] != "*" && !parts[2].is_empty() {
                set.insert(parts[2].to_lowercase());
            }
        } else if let Some(prefix_stripped) = cpe.strip_prefix("cpe:/") {
            let parts: Vec<&str> = prefix_stripped.split(':').collect();
            if parts.len() >= 3 && parts[2] != "*" && !parts[2].is_empty() {
                set.insert(parts[2].to_lowercase());
            }
        }
    }
    set.into_iter().collect()
}

// ── cve-match ──────────────────────────────────────────────────────

pub fn cve_match(graph: &mut Graph, _target: &str) -> String {
    // Collect Cve nodes + their products
    let cves: Vec<(String, Vec<String>, String)> = graph.nodes.iter()
        .filter(|(_, n)| n.kind == EntityKind::Cve)
        .map(|(id, n)| {
            let products: Vec<String> = n.attrs.get("cpe_products")
                .map(|s| s.split(',').filter(|p| !p.is_empty()).map(|p| p.to_lowercase()).collect())
                .unwrap_or_default();
            let severity = n.attrs.get("severity").cloned().unwrap_or_default();
            (id.clone(), products, severity)
        })
        .collect();

    if cves.is_empty() {
        return "No Cve nodes in graph. Run `codemap cve-import <nvd.json>` first.".to_string();
    }

    // Collect Dll nodes + their normalized names. DLL names take many
    // shapes:
    //   libc.so.6         (Linux SONAME)
    //   libssl.so.3
    //   kernel32.dll      (Windows)
    //   libsystem_c.dylib (Mach-O)
    //   log4j-core-2.14.1.jar
    // Strip the version-suffix + the lib prefix + the format extension
    // so we end up with a clean product-shaped token for matching.
    let dlls: Vec<(String, String)> = graph.nodes.iter()
        .filter(|(_, n)| n.kind == EntityKind::Dll)
        .map(|(id, n)| {
            let raw = n.attrs.get("name").cloned().unwrap_or_default();
            (id.clone(), normalize_dll_name(&raw))
        })
        .collect();

    let mut matches = 0usize;
    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut new_edges: Vec<(String, String)> = Vec::new();
    for (cve_id, products, severity) in &cves {
        for (dll_id, dll_name) in &dlls {
            for product in products {
                if dll_name.contains(product) || product.contains(dll_name) {
                    new_edges.push((dll_id.clone(), cve_id.clone()));
                    matches += 1;
                    *by_severity.entry(severity.clone()).or_insert(0) += 1;
                    break;
                }
            }
        }
    }
    for (a, b) in new_edges {
        graph.add_edge(&a, &b);
    }

    let mut lines = vec![
        format!("=== CVE Match ==="),
        format!("CVEs in graph:    {}", cves.len()),
        format!("DLLs in graph:    {}", dlls.len()),
        format!("Matches added:    {matches}"),
        String::new(),
    ];
    if matches == 0 {
        lines.push("No matches. Either CPE products don't overlap with DLL names, or".to_string());
        lines.push("the binaries in the graph aren't in the imported CVE feed's coverage.".to_string());
    } else {
        lines.push("Match severity breakdown:".to_string());
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] {
            if let Some(&n) = by_severity.get(sev) {
                lines.push(format!("  {sev:<10} {n}"));
            }
        }
        lines.push(String::new());
        lines.push("Try: codemap meta-path \"source->pe->dll->cve\"".to_string());
        lines.push("     codemap meta-path \"source->elf->dll->cve\"".to_string());
    }
    lines.join("\n")
}

/// Strip Linux/Mac/Windows lib prefix + extension + version suffix
/// from a raw DLL name to get a CPE-comparable product token.
///   libc.so.6              -> libc
///   libssl.so.3            -> ssl
///   libcrypto.so.1.1       -> crypto
///   kernel32.dll           -> kernel32
///   libsystem_c.dylib      -> system_c
///   log4j-core-2.14.1.jar  -> log4j-core
fn normalize_dll_name(raw: &str) -> String {
    let mut s = raw.to_ascii_lowercase();
    // Strip everything from the first ".so" / ".dll" / ".dylib" / ".jar" onward
    for ext in [".so", ".dll", ".dylib", ".jar", ".bundle"] {
        if let Some(idx) = s.find(ext) { s.truncate(idx); }
    }
    // Strip version suffix that some toolchains glue on with `-`:
    //   log4j-core-2.14.1 -> log4j-core
    if let Some(dash) = s.rfind('-') {
        let tail = &s[dash + 1..];
        if !tail.is_empty() && tail.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            s.truncate(dash);
        }
    }
    // Strip leading "lib" if present
    if let Some(stripped) = s.strip_prefix("lib") {
        if !stripped.is_empty() { s = stripped.to_string(); }
    }
    s
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let head: String = s.chars().take(max - 1).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_products_from_cpe23() {
        let cpes = vec![
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*".to_string(),
            "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*".to_string(),
            "cpe:2.3:o:microsoft:windows_10:21H2:*:*:*:*:*:*:*".to_string(),
        ];
        let products = extract_products(&cpes);
        assert!(products.contains(&"log4j".to_string()));
        assert!(products.contains(&"openssl".to_string()));
        assert!(products.contains(&"windows_10".to_string()));
    }

    #[test]
    fn extract_products_handles_old_cpe22_format() {
        let cpes = vec!["cpe:/a:apache:log4j:2.14.1".to_string()];
        let products = extract_products(&cpes);
        assert!(products.contains(&"log4j".to_string()));
    }

    #[test]
    fn parse_nvd_v2_minimal() {
        let json: serde_json::Value = serde_json::from_str(r#"{
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4Shell"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}
                }]
            },
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]
                }]
            }]
        }"#).unwrap();
        let rec = parse_nvd_v2(&json).unwrap();
        assert_eq!(rec.id, "CVE-2021-44228");
        assert_eq!(rec.severity, "CRITICAL");
        assert!((rec.cvss - 10.0).abs() < 0.001);
        assert!(rec.cpe_products.contains(&"log4j".to_string()));
    }

    #[test]
    fn normalize_dll_examples() {
        assert_eq!(normalize_dll_name("libc.so.6"), "c");
        assert_eq!(normalize_dll_name("libssl.so.3"), "ssl");
        assert_eq!(normalize_dll_name("libcrypto.so.1.1"), "crypto");
        assert_eq!(normalize_dll_name("kernel32.dll"), "kernel32");
        assert_eq!(normalize_dll_name("libsystem_c.dylib"), "system_c");
        assert_eq!(normalize_dll_name("log4j-core-2.14.1.jar"), "log4j-core");
    }

    #[test]
    fn parse_nvd_v1_minimal() {
        let json: serde_json::Value = serde_json::from_str(r#"{
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2020-1234"},
                "description": {"description_data": [{"value": "Test CVE"}]}
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {"baseScore": 7.5, "baseSeverity": "HIGH"}
                }
            },
            "configurations": {
                "nodes": [{
                    "cpe_match": [{"cpe23Uri": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"}]
                }]
            }
        }"#).unwrap();
        let rec = parse_nvd_v1(&json).unwrap();
        assert_eq!(rec.id, "CVE-2020-1234");
        assert_eq!(rec.severity, "HIGH");
        assert!(rec.cpe_products.contains(&"openssl".to_string()));
    }
}
