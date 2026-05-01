use std::collections::HashMap;
use crate::types::{Graph, EntityKind};

// ── SBOM Export ────────────────────────────────────────────────────
//
// Two formats — both standard, both consumed by every modern
// supply-chain tool:
//
//   to-spdx      — SPDX 2.3 JSON. Linux Foundation standard,
//                  required for federal procurement (US EO 14028).
//   to-cyclonedx — CycloneDX 1.5 JSON. OWASP standard, broader
//                  vulnerability + service inventory.
//
// Both serialize the heterogeneous graph into a normalized doc:
//   - Source file packages (with detected licenses)
//   - Binary packages (PE/ELF/Mach-O/Java/WASM)
//   - DLL/library dependencies (with edges → vulnerable Cves)
//   - License nodes referenced by source/binary
//   - Vulnerability records as separate sections
//
// Pure read-side — no new graph mutations. Ships the existing
// supply-chain graph as a portable doc.

// ── to-spdx ────────────────────────────────────────────────────────

pub fn to_spdx(graph: &Graph) -> String {
    let now = chrono_iso8601_now();
    let scan_dir = &graph.scan_dir;
    let doc_name = format!("codemap-sbom-{}", scan_dir.rsplit('/').next().unwrap_or("repo"));

    // Collect packages: source files + binaries + DLLs
    let mut packages = serde_json::json!([]);
    let pkgs = packages.as_array_mut().unwrap();

    let mut spdx_id_counter = 1usize;
    let mut node_to_spdx: HashMap<String, String> = HashMap::new();

    for (id, node) in &graph.nodes {
        if !is_sbom_relevant(node.kind) { continue; }
        let spdx_ref = format!("SPDXRef-{spdx_id_counter}");
        spdx_id_counter += 1;
        node_to_spdx.insert(id.clone(), spdx_ref.clone());

        let kind_label = sbom_kind_label(node.kind);
        let name = node.attrs.get("name")
            .or_else(|| node.attrs.get("path"))
            .cloned()
            .unwrap_or_else(|| id.clone());

        let mut pkg = serde_json::json!({
            "SPDXID": spdx_ref,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "primaryPackagePurpose": kind_label,
        });
        // License (find linked License node)
        let license = find_license_for(graph, id);
        if let Some(spdx_id) = license {
            pkg["licenseConcluded"] = serde_json::json!(spdx_id);
            pkg["licenseDeclared"] = serde_json::json!(spdx_id);
        } else {
            pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
            pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
        }
        if let Some(version) = node.attrs.get("version") {
            pkg["versionInfo"] = serde_json::json!(version);
        }
        // CPE if available (from CVE matching pipeline)
        if let Some(cpes) = node.attrs.get("cpe_full") {
            let externals: Vec<serde_json::Value> = cpes.split('|').filter(|s| !s.is_empty())
                .map(|c| serde_json::json!({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": c,
                }))
                .collect();
            if !externals.is_empty() {
                pkg["externalRefs"] = serde_json::json!(externals);
            }
        }
        pkgs.push(pkg);
    }

    // Relationships: source CONTAINS binary, binary DEPENDS_ON dll, dll HAS_VULN cve
    let mut relationships = serde_json::json!([]);
    let rels = relationships.as_array_mut().unwrap();
    for (id, node) in &graph.nodes {
        let from_ref = match node_to_spdx.get(id) { Some(s) => s, None => continue };
        for imp in &node.imports {
            if let Some(to_ref) = node_to_spdx.get(imp) {
                let rel_type = match (node.kind, graph.nodes.get(imp).map(|n| n.kind)) {
                    (EntityKind::SourceFile, _) => "DEPENDS_ON",
                    (_, Some(EntityKind::Cve)) => "HAS_ASSOCIATED_VULNERABILITY",
                    (_, Some(EntityKind::License)) => "DESCRIBES",
                    _ => "DEPENDS_ON",
                };
                rels.push(serde_json::json!({
                    "spdxElementId": from_ref,
                    "relationshipType": rel_type,
                    "relatedSpdxElement": to_ref,
                }));
            }
        }
    }

    let doc = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": format!("https://codemap.local/sbom/{}", doc_name),
        "creationInfo": {
            "created": now,
            "creators": ["Tool: codemap-5.14.0"],
            "licenseListVersion": "3.20",
        },
        "packages": packages,
        "relationships": relationships,
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("SPDX serialization error: {e}"))
}

// ── to-cyclonedx ──────────────────────────────────────────────────

pub fn to_cyclonedx(graph: &Graph) -> String {
    let now = chrono_iso8601_now();
    let scan_dir = &graph.scan_dir;
    let _doc_name = format!("codemap-sbom-{}", scan_dir.rsplit('/').next().unwrap_or("repo"));
    let serial = format!("urn:uuid:{}", fnv_hex(scan_dir.as_bytes()));

    // Components
    let mut components = serde_json::json!([]);
    let comps = components.as_array_mut().unwrap();
    let mut bom_ref_counter = 1usize;
    let mut node_to_bomref: HashMap<String, String> = HashMap::new();

    for (id, node) in &graph.nodes {
        if !is_sbom_relevant(node.kind) { continue; }
        let bomref = format!("comp-{bom_ref_counter}");
        bom_ref_counter += 1;
        node_to_bomref.insert(id.clone(), bomref.clone());

        let kind_label = cdx_kind_label(node.kind);
        let name = node.attrs.get("name")
            .or_else(|| node.attrs.get("path"))
            .cloned()
            .unwrap_or_else(|| id.clone());

        let mut comp = serde_json::json!({
            "type": kind_label,
            "bom-ref": bomref,
            "name": name,
        });
        if let Some(version) = node.attrs.get("version") {
            comp["version"] = serde_json::json!(version);
        }
        // License
        if let Some(spdx_id) = find_license_for(graph, id) {
            comp["licenses"] = serde_json::json!([{"license": {"id": spdx_id}}]);
        }
        if let Some(cpes) = node.attrs.get("cpe_full") {
            let cpe = cpes.split('|').next().unwrap_or("");
            if !cpe.is_empty() {
                comp["cpe"] = serde_json::json!(cpe);
            }
        }
        comps.push(comp);
    }

    // Vulnerabilities (Cve nodes)
    let mut vulns = serde_json::json!([]);
    let vs = vulns.as_array_mut().unwrap();
    for (id, node) in &graph.nodes {
        if node.kind != EntityKind::Cve { continue; }
        let cve_id = node.attrs.get("id").cloned().unwrap_or_else(|| id.clone());
        let severity = node.attrs.get("severity").cloned().unwrap_or_default();
        let cvss: f64 = node.attrs.get("cvss").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let description = node.attrs.get("description").cloned().unwrap_or_default();
        // Find which components this vuln affects (incoming edges)
        let mut affects: Vec<serde_json::Value> = Vec::new();
        for (other_id, other_node) in &graph.nodes {
            if other_node.imports.iter().any(|imp| imp == id) {
                if let Some(bomref) = node_to_bomref.get(other_id) {
                    affects.push(serde_json::json!({"ref": bomref}));
                }
            }
        }
        vs.push(serde_json::json!({
            "id": cve_id,
            "ratings": [{"score": cvss, "severity": severity.to_lowercase(), "method": "CVSSv3.1"}],
            "description": description,
            "affects": affects,
        }));
    }

    // Dependencies (component → component edges)
    let mut deps = serde_json::json!([]);
    let dl = deps.as_array_mut().unwrap();
    for (id, node) in &graph.nodes {
        let bomref = match node_to_bomref.get(id) { Some(s) => s, None => continue };
        let mut depends_on: Vec<String> = Vec::new();
        for imp in &node.imports {
            if let Some(other_ref) = node_to_bomref.get(imp) {
                depends_on.push(other_ref.clone());
            }
        }
        if !depends_on.is_empty() {
            dl.push(serde_json::json!({
                "ref": bomref,
                "dependsOn": depends_on,
            }));
        }
    }

    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "codemap", "name": "codemap", "version": env!("CARGO_PKG_VERSION")}],
        },
        "components": components,
        "vulnerabilities": vulns,
        "dependencies": deps,
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("CycloneDX serialization error: {e}"))
}

// ── helpers ────────────────────────────────────────────────────────

fn is_sbom_relevant(kind: EntityKind) -> bool {
    matches!(kind,
        EntityKind::SourceFile | EntityKind::PeBinary | EntityKind::ElfBinary
        | EntityKind::MachoBinary | EntityKind::JavaClass | EntityKind::WasmModule
        | EntityKind::Dll)
}

fn sbom_kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::SourceFile => "SOURCE",
        EntityKind::PeBinary | EntityKind::ElfBinary | EntityKind::MachoBinary => "APPLICATION",
        EntityKind::JavaClass | EntityKind::WasmModule => "APPLICATION",
        EntityKind::Dll => "LIBRARY",
        _ => "OTHER",
    }
}

fn cdx_kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::SourceFile => "file",
        EntityKind::PeBinary | EntityKind::ElfBinary | EntityKind::MachoBinary => "application",
        EntityKind::JavaClass | EntityKind::WasmModule => "application",
        EntityKind::Dll => "library",
        _ => "library",
    }
}

/// Walk outgoing edges; return the SPDX id of the first License node
/// found. Source/binary nodes link to their license via add_edge.
fn find_license_for(graph: &Graph, id: &str) -> Option<String> {
    let node = graph.nodes.get(id)?;
    for imp in &node.imports {
        if let Some(other) = graph.nodes.get(imp) {
            if other.kind == EntityKind::License {
                return other.attrs.get("spdx").cloned();
            }
        }
    }
    None
}

fn chrono_iso8601_now() -> String {
    // RFC 3339 / ISO 8601 — UTC. Year 1970+, month/day computed via
    // Howard Hinnant civil_from_days. (We avoid the chrono dep.)
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86400);
    let secs_of_day = (secs - days * 86400) as u64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yyyy = if m <= 2 { y + 1 } else { y };
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yyyy, m, d, h, mi, s)
}

fn fnv_hex(data: &[u8]) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (h >> 32) as u32, (h >> 16) as u16, h as u16, ((h >> 48) ^ h) as u16, h ^ 0x123456789abc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_graph() -> Graph {
        let mut g = Graph { nodes: HashMap::new(), scan_dir: "/test/repo".to_string(), cpg: None };
        g.ensure_typed_node("src/main.rs", EntityKind::SourceFile, &[("path", "src/main.rs")]);
        g.ensure_typed_node("license:MIT", EntityKind::License, &[("spdx", "MIT"), ("family", "permissive")]);
        g.add_edge("src/main.rs", "license:MIT");
        g.ensure_typed_node("dll:libc.so.6", EntityKind::Dll, &[("name", "libc.so.6")]);
        g.ensure_typed_node("cve:CVE-2099-99999", EntityKind::Cve, &[
            ("id", "CVE-2099-99999"), ("severity", "CRITICAL"), ("cvss", "9.8"),
            ("description", "test"),
        ]);
        g.add_edge("dll:libc.so.6", "cve:CVE-2099-99999");
        g
    }

    #[test]
    fn spdx_doc_is_valid_json_with_required_fields() {
        let g = fixture_graph();
        let out = to_spdx(&g);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(v["packages"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn cyclonedx_doc_is_valid_json_with_vulnerability() {
        let g = fixture_graph();
        let out = to_cyclonedx(&g);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let vulns = v["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "CVE-2099-99999");
    }

    #[test]
    fn iso8601_format_is_correct() {
        let s = chrono_iso8601_now();
        // YYYY-MM-DDTHH:MM:SSZ — 20 chars
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
    }
}
