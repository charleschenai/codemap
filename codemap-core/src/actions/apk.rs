use std::collections::BTreeSet;
use crate::types::{Graph, EntityKind};

// ── APK Analysis (v1) ──────────────────────────────────────────────
//
// APK = ZIP archive containing:
//   AndroidManifest.xml   (binary AXML — Android's compressed XML)
//   classes.dex           (Dalvik bytecode, primary)
//   classes2.dex, ...     (additional DEX files for multidex APKs)
//   resources.arsc        (resource table)
//   META-INF/             (signing info)
//   res/ assets/ lib/     (assets, native .so libraries)
//
// v1 scope:
//   - Walk ZIP local-file headers (no full inflate; we just list
//     entry names + extract the AndroidManifest if present).
//   - Parse AndroidManifest binary AXML to extract package name +
//     declared permissions.
//   - Register AndroidPackage + Permission nodes.
//   - List embedded .dex files but don't disassemble them yet.
//
// Full DEX bytecode method extraction is its own multi-hour project
// (Dalvik opcode catalog, string_ids/method_ids/proto_ids tables,
// LEB128 method-body parsing). Deferred to a follow-up release.

pub fn apk_info(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap apk-info <apk-file>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 4 || &data[..4] != b"PK\x03\x04" {
        return format!("Not an APK/ZIP: {target}");
    }

    let entries = walk_zip_entries(&data);
    let mut dex_files: Vec<String> = Vec::new();
    let mut has_manifest = false;
    let mut has_resources = false;
    let mut native_libs: Vec<String> = Vec::new();
    let mut signing_files: Vec<String> = Vec::new();
    let mut manifest_bytes: Option<Vec<u8>> = None;

    for entry in &entries {
        let n = entry.name.as_str();
        if n.starts_with("classes") && n.ends_with(".dex") {
            dex_files.push(n.to_string());
        } else if n == "AndroidManifest.xml" {
            has_manifest = true;
            // Try to extract the manifest body if it isn't compressed
            if let Some(b) = entry.try_extract_uncompressed(&data) {
                manifest_bytes = Some(b);
            }
        } else if n == "resources.arsc" {
            has_resources = true;
        } else if n.starts_with("lib/") && n.ends_with(".so") {
            native_libs.push(n.to_string());
        } else if n.starts_with("META-INF/") &&
            (n.ends_with(".RSA") || n.ends_with(".DSA") || n.ends_with(".EC") || n.ends_with(".SF") || n == "META-INF/MANIFEST.MF") {
            signing_files.push(n.to_string());
        }
    }

    let apk_id = format!("apk:{target}");
    graph.ensure_typed_node(&apk_id, EntityKind::AndroidPackage, &[
        ("path", target),
        ("dex_count", &dex_files.len().to_string()),
        ("has_manifest", &has_manifest.to_string()),
        ("has_resources", &has_resources.to_string()),
        ("native_libs", &native_libs.len().to_string()),
        ("zip_entries", &entries.len().to_string()),
    ]);

    // Parse manifest if we got it uncompressed; otherwise note compression
    let mut package_name = String::new();
    let mut permissions: BTreeSet<String> = BTreeSet::new();
    if let Some(bytes) = &manifest_bytes {
        let parsed = parse_axml(bytes);
        package_name = parsed.0;
        permissions = parsed.1;
    }
    if !package_name.is_empty() {
        if let Some(node) = graph.nodes.get_mut(&apk_id) {
            node.attrs.insert("package".into(), package_name.clone());
        }
    }
    for perm in &permissions {
        let perm_id = format!("permission:{perm}");
        graph.ensure_typed_node(&perm_id, EntityKind::Permission, &[
            ("name", perm.as_str()),
        ]);
        graph.add_edge(&apk_id, &perm_id);
    }

    // 5.23.0: DEX bytecode walker. For each `classes*.dex` entry, decode
    // the DEX (uncompress via miniz_oxide if needed), enumerate methods,
    // and register each as a `BinaryFunction(binary_format=dex)` node
    // with edge from the AndroidPackage. Heuristic permission→method
    // linking adds method→Permission edges based on invoke-* opcode
    // targets matching ~30 well-known protected Android APIs.
    let mut total_methods = 0usize;
    let mut total_perm_edges = 0usize;
    for entry in &entries {
        let n = entry.name.as_str();
        if !(n.starts_with("classes") && n.ends_with(".dex")) { continue; }
        let dex_bytes = match entry.try_extract_uncompressed(&data) {
            Some(b) => b,
            None => continue,  // unsupported compression — skip silently
        };
        let info = match crate::actions::dex::parse_dex(&dex_bytes) {
            Ok(i) => i,
            Err(_) => continue,  // corrupt or non-DEX-shaped — skip
        };
        for (i, m) in info.methods.iter().enumerate() {
            if total_methods >= 5000 { break; }
            // Stable ID per method: dex_filename + index keeps multidex
            // (classes2.dex, classes3.dex) collisions impossible.
            let func_id = format!("bin_func:dex:{target}::{n}::{i}");
            let access_str = format!("{:#x}", m.access_flags);
            let code_off_str = format!("{:#x}", m.code_off);
            graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                ("name", &m.fqn()),
                ("class_name", &m.class_name),
                ("method_name", &m.method_name),
                ("binary_format", "dex"),
                ("kind_detail", "dex_method"),
                ("access_flags", &access_str),
                ("code_off", &code_off_str),
                ("dex_file", n),
            ]);
            graph.add_edge(&apk_id, &func_id);
            total_methods += 1;
        }
        for edge in &info.permission_edges {
            // Find the matching method node by FQN — we just registered
            // every method above so the lookup is fast.
            let caller_fqn = format!("{}.{}", edge.caller_class, edge.caller_method);
            let perm_id = format!("permission:{}", edge.permission);
            // Permission node may not have been registered yet (e.g. if
            // the manifest didn't declare it but the code uses it — this
            // is exactly the "did I ship a permission I'm not actually
            // using?" / "did I forget to declare a permission I AM using?"
            // workflow). Auto-register with a `discovered_via=dex`
            // attribute so the diff between manifest-declared and code-
            // referenced is queryable.
            graph.ensure_typed_node(&perm_id, EntityKind::Permission, &[
                ("name", edge.permission),
                ("discovered_via", "dex"),
            ]);
            // Walk the just-registered method nodes to find the caller.
            // Linear scan kept small by 5000-method cap.
            let caller_node_id = graph.nodes.iter()
                .find(|(_, node)| node.kind == EntityKind::BinaryFunction
                    && node.attrs.get("name").map(|s| s.as_str()) == Some(caller_fqn.as_str())
                    && node.attrs.get("dex_file").map(|s| s.as_str()) == Some(n))
                .map(|(id, _)| id.clone());
            if let Some(caller_id) = caller_node_id {
                graph.add_edge(&caller_id, &perm_id);
                total_perm_edges += 1;
            }
        }
    }
    if let Some(node) = graph.nodes.get_mut(&apk_id) {
        node.attrs.insert("dex_methods".into(), total_methods.to_string());
        node.attrs.insert("dex_permission_edges".into(), total_perm_edges.to_string());
    }

    // Build report
    let mut lines = vec![
        format!("=== APK Analysis: {target} ==="),
        format!("ZIP entries:       {}", entries.len()),
        {
            let dex_summary = if dex_files.is_empty() { "(none)".to_string() } else { dex_files.join(", ") };
            format!("DEX files:         {} ({})", dex_files.len(), dex_summary)
        },
        format!("Manifest:          {}", if has_manifest { "yes" } else { "MISSING" }),
        format!("resources.arsc:    {}", if has_resources { "yes" } else { "no" }),
        format!("Native libraries:  {}", native_libs.len()),
        format!("Signing files:     {}", signing_files.len()),
    ];
    if !package_name.is_empty() {
        lines.push(format!("Package:           {package_name}"));
    } else if has_manifest {
        lines.push("Package:           (manifest is compressed — unzip first)".to_string());
    }
    lines.push(format!("Permissions:       {}", permissions.len()));

    if !permissions.is_empty() {
        lines.push(String::new());
        lines.push("── Declared permissions ──".to_string());
        for p in &permissions {
            // Highlight high-risk
            let marker = if is_dangerous_permission(p) { "  ⚠ " } else { "    " };
            lines.push(format!("{marker}{p}"));
        }
    }
    if !native_libs.is_empty() {
        lines.push(String::new());
        lines.push(format!("── Native libs ({}) ──", native_libs.len()));
        for lib in native_libs.iter().take(20) {
            lines.push(format!("  {lib}"));
        }
        if native_libs.len() > 20 {
            lines.push(format!("  ... and {} more", native_libs.len() - 20));
        }
    }
    if !signing_files.is_empty() {
        lines.push(String::new());
        lines.push("── Signing files ──".to_string());
        for f in &signing_files { lines.push(format!("  {f}")); }
    }

    lines.push(String::new());
    lines.push(format!("DEX methods (graph): {}", total_methods));
    lines.push(format!("Heuristic permission→method edges: {}", total_perm_edges));
    if total_methods >= 5000 {
        lines.push("(capped at 5000 methods — see attribute filters for the full picture)".to_string());
    }

    lines.join("\n")
}

#[derive(Debug)]
struct ZipEntry {
    name: String,
    /// File offset of the local file header (PK\x03\x04 + 26 bytes + name + extra + body)
    header_offset: usize,
    compressed_size: u32,
    uncompressed_size: u32,
    compression_method: u16,  // 0 = stored, 8 = deflate
    name_len: u16,
    extra_len: u16,
}

impl ZipEntry {
    /// Returns the body bytes for stored (method=0) or deflated (method=8)
    /// entries. v1 (5.15.3) was stored-only; 5.23.0 adds deflate via
    /// pure-Rust miniz_oxide so classes.dex (always compressed in real
    /// APKs) can be extracted for DEX bytecode walking.
    fn try_extract_uncompressed(&self, data: &[u8]) -> Option<Vec<u8>> {
        let body_start = self.header_offset + 30 + self.name_len as usize + self.extra_len as usize;
        let body_end = body_start + self.compressed_size as usize;
        if body_end > data.len() { return None; }
        match self.compression_method {
            0 => Some(data[body_start..body_end].to_vec()),
            8 => miniz_oxide::inflate::decompress_to_vec(&data[body_start..body_end]).ok(),
            _ => None,
        }
    }
}

fn walk_zip_entries(data: &[u8]) -> Vec<ZipEntry> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 30 <= data.len() {
        // Local file header magic
        if &data[p..p + 4] != b"PK\x03\x04" { break; }
        let compression = u16::from_le_bytes([data[p + 8], data[p + 9]]);
        let compressed_size = u32::from_le_bytes([data[p + 18], data[p + 19], data[p + 20], data[p + 21]]);
        let uncompressed_size = u32::from_le_bytes([data[p + 22], data[p + 23], data[p + 24], data[p + 25]]);
        let name_len = u16::from_le_bytes([data[p + 26], data[p + 27]]);
        let extra_len = u16::from_le_bytes([data[p + 28], data[p + 29]]);
        let name_start = p + 30;
        let name_end = name_start + name_len as usize;
        if name_end > data.len() { break; }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();

        out.push(ZipEntry {
            name,
            header_offset: p,
            compressed_size,
            uncompressed_size,
            compression_method: compression,
            name_len,
            extra_len,
        });

        // Advance to next local header
        let body_start = name_end + extra_len as usize;
        let body_end = body_start + compressed_size as usize;
        p = body_end;
        // ZIP central directory follows after all local file headers; once we
        // see the directory signature 'PK\x01\x02', stop.
        if out.len() > 50_000 { break; }
        if p + 4 > data.len() { break; }
        if &data[p..p + 4] == b"PK\x01\x02" { break; }
    }
    out
}

/// Best-effort AXML permission extraction. Android binary XML is
/// length-prefixed UTF-16 in a string pool; permissions appear as
/// the value attribute of <uses-permission android:name="..." /> tags.
/// We don't parse the full AXML format — instead, we scan for known
/// permission name patterns in the UTF-8 / UTF-16 string pool.
fn parse_axml(data: &[u8]) -> (String, BTreeSet<String>) {
    let mut permissions = BTreeSet::new();
    let package_name = String::new();

    // The string pool in compiled AXML stores strings as length-prefixed
    // UTF-16. Permission strings always follow the form
    // "android.permission.X" or "com.example.permission.X" — easy to
    // pattern-match in either UTF-8 or UTF-16.

    // UTF-8 scan
    let prefixes: [&[u8]; 3] = [
        b"android.permission.",
        b"com.android.permission.",
        b"com.google.android.permission.",
    ];
    let mut i = 0;
    while i < data.len() {
        for prefix in &prefixes {
            if i + prefix.len() <= data.len() && &data[i..i + prefix.len()] == *prefix {
                let mut end = i + prefix.len();
                while end < data.len() {
                    let b = data[end];
                    if !(b == b'.' || b == b'_' || b.is_ascii_alphanumeric()) { break; }
                    end += 1;
                }
                let name = String::from_utf8_lossy(&data[i..end]).to_string();
                if name.len() > prefix.len() {
                    permissions.insert(name);
                }
                i = end;
                break;
            }
        }
        i += 1;
    }

    // UTF-16 scan — same prefixes interleaved with 0x00 bytes
    for prefix in &prefixes {
        let utf16_prefix: Vec<u8> = prefix.iter().flat_map(|&b| [b, 0u8]).collect();
        let mut k = 0;
        while k + utf16_prefix.len() <= data.len() {
            if &data[k..k + utf16_prefix.len()] == utf16_prefix.as_slice() {
                let mut end = k + utf16_prefix.len();
                while end + 1 < data.len() {
                    let b = data[end];
                    let hi = data[end + 1];
                    if hi != 0 { break; }
                    if !(b == b'.' || b == b'_' || b.is_ascii_alphanumeric()) { break; }
                    end += 2;
                }
                if end > k + utf16_prefix.len() {
                    // Decode the UTF-16 → UTF-8
                    let mut decoded = Vec::with_capacity((end - k) / 2);
                    let mut p = k;
                    while p + 1 < end {
                        decoded.push(data[p]);
                        p += 2;
                    }
                    permissions.insert(String::from_utf8_lossy(&decoded).to_string());
                }
                k = end;
            } else {
                k += 1;
            }
        }
    }

    // Package name heuristic: scan for "package=" in raw bytes (sometimes
    // appears verbatim) or look for typical reverse-DNS package strings.
    // We use a simple heuristic: find a UTF-16 string that's "package"
    // immediately followed by a longer reverse-DNS string. For v1 we
    // skip this since the manifest is usually compressed.

    (package_name, permissions)
}

fn is_dangerous_permission(perm: &str) -> bool {
    matches!(perm,
        "android.permission.READ_CONTACTS" | "android.permission.WRITE_CONTACTS"
        | "android.permission.CAMERA" | "android.permission.RECORD_AUDIO"
        | "android.permission.ACCESS_FINE_LOCATION" | "android.permission.ACCESS_COARSE_LOCATION"
        | "android.permission.ACCESS_BACKGROUND_LOCATION"
        | "android.permission.READ_SMS" | "android.permission.SEND_SMS"
        | "android.permission.RECEIVE_SMS" | "android.permission.READ_CALL_LOG"
        | "android.permission.WRITE_CALL_LOG" | "android.permission.PROCESS_OUTGOING_CALLS"
        | "android.permission.READ_EXTERNAL_STORAGE" | "android.permission.WRITE_EXTERNAL_STORAGE"
        | "android.permission.READ_PHONE_STATE" | "android.permission.READ_PHONE_NUMBERS"
        | "android.permission.SYSTEM_ALERT_WINDOW" | "android.permission.REQUEST_INSTALL_PACKAGES"
        | "android.permission.BIND_DEVICE_ADMIN" | "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_zip_magic() {
        let data = b"PK\x03\x04rest of zip file body...";
        let entries = walk_zip_entries(data);
        // Won't fully parse without a real ZIP, but should not crash
        assert!(entries.len() <= 1);
    }

    #[test]
    fn dangerous_permission_lookup() {
        assert!(is_dangerous_permission("android.permission.CAMERA"));
        assert!(is_dangerous_permission("android.permission.READ_SMS"));
        assert!(!is_dangerous_permission("android.permission.INTERNET"));
        assert!(!is_dangerous_permission("android.permission.WAKE_LOCK"));
    }

    #[test]
    fn axml_extracts_utf8_permission_names() {
        let blob = b"\x00\x00garbage_android.permission.CAMERA\x00\x00garbage";
        let (_, perms) = parse_axml(blob);
        assert!(perms.iter().any(|p| p == "android.permission.CAMERA"));
    }
}
