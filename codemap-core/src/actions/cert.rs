use crate::types::{Graph, EntityKind};

// ── Code Signing → Cert Nodes (PE Authenticode v1) ─────────────────
//
// PE Authenticode lives in the certificate-table data directory
// (index 4). Layout:
//
//   Cert Table = sequence of WIN_CERTIFICATE entries:
//     dwLength      (u32, LE) — total length including header
//     wRevision     (u16, LE) — usually 0x0200
//     wCertType     (u16, LE) — 0x0002 for PKCS_SIGNED_DATA
//     bCertificate  (variable) — PKCS#7 SignedData blob
//
// PKCS#7 SignedData wraps DER-encoded X.509 certificates that
// signed the binary. We do a minimal DER walk: locate the
// `certificates [0] IMPLICIT` set and walk each certificate's
// TBSCertificate to extract subject, issuer, serial, validity.
//
// Pure DER (no rsa/openssl/oid-registry deps) — what we need is
// the textual identity, not full validation. Validation is its
// own multi-MB project (chain building, OCSP, CRL, etc.).
//
// V1 scope: PE only. Mac codesign (LC_CODE_SIGNATURE blob) and
// JAR signing (META-INF/*.RSA) deferred to follow-ups since each
// is a different format with its own complexity.

#[derive(Debug, Clone, Default)]
struct CertInfo {
    subject_cn: String,
    issuer_cn: String,
    serial: String,
    sha256: String,
    not_before: String,
    not_after: String,
}

pub fn pe_cert(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap pe-cert <pe-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return format!("Not a PE binary: {target}");
    }

    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    let (cert_off, cert_size) = match locate_cert_table(&data) {
        Some(v) => v,
        None => {
            return format!("=== PE Cert: {target} ===\nNo Authenticode certificate table.\n  → Binary is unsigned (or signing was stripped).");
        }
    };

    let cert_table = match data.get(cert_off..(cert_off + cert_size)) {
        Some(b) => b,
        None => return format!("=== PE Cert: {target} ===\nCert table out of bounds — possibly truncated."),
    };

    let mut all_lines = vec![format!("=== PE Cert: {target} ==="),
        format!("Cert table: offset={:#x}, size={} bytes", cert_off, cert_size)];

    let mut entries_found = 0usize;
    let mut p = 0usize;
    while p + 8 <= cert_table.len() {
        let length = u32::from_le_bytes([cert_table[p], cert_table[p+1], cert_table[p+2], cert_table[p+3]]) as usize;
        let revision = u16::from_le_bytes([cert_table[p+4], cert_table[p+5]]);
        let cert_type = u16::from_le_bytes([cert_table[p+6], cert_table[p+7]]);
        if length < 8 || p + length > cert_table.len() { break; }
        let body = &cert_table[p + 8..p + length];

        all_lines.push(String::new());
        all_lines.push(format!("── WIN_CERTIFICATE entry #{} ──", entries_found + 1));
        all_lines.push(format!("  Length:   {length} bytes"));
        all_lines.push(format!("  Revision: {:#06x}", revision));
        all_lines.push(format!("  Type:     {} ({})",
            cert_type,
            match cert_type {
                0x0001 => "X.509",
                0x0002 => "PKCS#7 SignedData (Authenticode)",
                0x0003 => "Reserved",
                0x0004 => "Terminal Server Protocol Stack",
                _ => "Unknown",
            }));

        // For PKCS#7 (Authenticode), drill into the DER and extract X.509 certs
        if cert_type == 0x0002 {
            let infos = extract_x509s_from_pkcs7(body);
            all_lines.push(format!("  Embedded X.509 certs: {}", infos.len()));
            for (i, info) in infos.iter().enumerate() {
                all_lines.push(String::new());
                all_lines.push(format!("    [{}] CN={}", i + 1, if info.subject_cn.is_empty() { "(unparsed)" } else { &info.subject_cn }));
                if !info.issuer_cn.is_empty() {
                    all_lines.push(format!("        Issuer CN: {}", info.issuer_cn));
                }
                if !info.serial.is_empty() {
                    all_lines.push(format!("        Serial:    {}", info.serial));
                }
                if !info.sha256.is_empty() {
                    all_lines.push(format!("        Fingerprint: {}", info.sha256));
                }
                if !info.not_before.is_empty() || !info.not_after.is_empty() {
                    all_lines.push(format!("        Validity:  {} → {}", info.not_before, info.not_after));
                }

                // Register Cert node + binary→cert edge
                let cert_id = format!("cert:{}", if !info.sha256.is_empty() { info.sha256.clone() } else { format!("{target}:{i}") });
                graph.ensure_typed_node(&cert_id, EntityKind::Cert, &[
                    ("subject_cn", &info.subject_cn),
                    ("issuer_cn",  &info.issuer_cn),
                    ("serial",     &info.serial),
                    ("sha256",     &info.sha256),
                    ("not_before", &info.not_before),
                    ("not_after",  &info.not_after),
                ]);
                graph.add_edge(&bin_id, &cert_id);
            }
        }
        entries_found += 1;
        // Pad to 8-byte boundary
        let pad = (8 - (length % 8)) % 8;
        p += length + pad;
    }

    if entries_found == 0 {
        all_lines.push(String::new());
        all_lines.push("  (no entries parsed — possibly malformed cert table)".to_string());
    }

    all_lines.join("\n")
}

/// Read the cert-table data directory entry from the PE optional header.
fn locate_cert_table(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 0x40 { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let opt_off = coff + 20;
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_pe32_plus = magic == 0x20b;

    // Cert table directory is index 4
    let cert_dd_off = if is_pe32_plus { opt_off + 112 + 4 * 8 } else { opt_off + 96 + 4 * 8 };
    if cert_dd_off + 8 > data.len() { return None; }
    let off = u32::from_le_bytes([data[cert_dd_off], data[cert_dd_off + 1], data[cert_dd_off + 2], data[cert_dd_off + 3]]) as usize;
    let size = u32::from_le_bytes([data[cert_dd_off + 4], data[cert_dd_off + 5], data[cert_dd_off + 6], data[cert_dd_off + 7]]) as usize;
    if off == 0 || size == 0 { return None; }
    if off >= data.len() { return None; }
    Some((off, size))
}

/// Walk a PKCS#7 SignedData blob and pull out each embedded X.509
/// certificate. Returns CertInfo per cert. We DER-walk only the
/// minimum needed to identify the cert; we don't validate.
fn extract_x509s_from_pkcs7(blob: &[u8]) -> Vec<CertInfo> {
    let mut out = Vec::new();
    // Top: SEQUENCE { contentType OID, content [0] EXPLICIT { ... } }
    let outer = match der_seq(blob, 0) {
        Some(v) => v,
        None => return out,
    };
    // Inside: contentType (OID 1.2.840.113549.1.7.2 = signedData), then
    // content [0] EXPLICIT containing SignedData SEQUENCE.
    // Find the [0] EXPLICIT tag (0xA0).
    let mut p = outer.0;
    while p < outer.0 + outer.1 {
        let tag = match blob.get(p) { Some(&t) => t, None => break };
        let (len, len_size) = match der_length(blob, p + 1) {
            Some(v) => v,
            None => break,
        };
        if tag == 0xA0 {
            // [0] EXPLICIT
            let inner_start = p + 1 + len_size;
            // Inner is a SEQUENCE containing the SignedData
            if let Some((sd_start, sd_size)) = der_seq(blob, inner_start) {
                walk_signed_data(blob, sd_start, sd_size, &mut out);
            }
            return out;
        }
        p += 1 + len_size + len;
    }
    out
}

/// SignedData ::= SEQUENCE {
///   version INTEGER,
///   digestAlgorithms SET,
///   contentInfo SEQUENCE,
///   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
///   ...
/// }
fn walk_signed_data(blob: &[u8], start: usize, size: usize, out: &mut Vec<CertInfo>) {
    let end = start + size;
    let mut p = start;
    let mut seq_idx = 0;
    while p < end {
        let tag = match blob.get(p) { Some(&t) => t, None => break };
        let (len, len_size) = match der_length(blob, p + 1) {
            Some(v) => v,
            None => break,
        };
        let body_start = p + 1 + len_size;
        // The certificates field is [0] IMPLICIT — appears as tag 0xA0.
        if tag == 0xA0 {
            walk_cert_set(blob, body_start, len, out);
            return;
        }
        seq_idx += 1;
        if seq_idx > 10 { break; }
        p = body_start + len;
    }
}

fn walk_cert_set(blob: &[u8], start: usize, size: usize, out: &mut Vec<CertInfo>) {
    let end = start + size;
    let mut p = start;
    while p < end {
        let tag = match blob.get(p) { Some(&t) => t, None => break };
        if tag != 0x30 { break; } // expect SEQUENCE for each cert
        let (len, len_size) = match der_length(blob, p + 1) {
            Some(v) => v,
            None => break,
        };
        let body_start = p + 1 + len_size;
        let body_end = (body_start + len).min(blob.len());
        if body_end <= body_start { break; }
        let cert_der = &blob[p..body_end];
        let info = parse_cert(cert_der).unwrap_or_default();
        out.push(info);
        p = body_end;
        if out.len() > 32 { break; }
    }
}

/// Parse a single X.509 v3 cert just enough to extract identity fields.
fn parse_cert(cert_der: &[u8]) -> Option<CertInfo> {
    let mut info = CertInfo::default();
    info.sha256 = sha256_hex(cert_der);

    // Cert ::= SEQUENCE { tbsCert SEQUENCE { ... }, sigAlg, sigValue }
    let outer = der_seq(cert_der, 0)?;
    // Inside outer: tbsCert is the first element, also a SEQUENCE.
    let tbs = der_seq(cert_der, outer.0)?;
    let mut p = tbs.0;
    let tbs_end = tbs.0 + tbs.1;

    // tbsCert ::= SEQUENCE {
    //   version [0] EXPLICIT INTEGER DEFAULT v1,
    //   serialNumber INTEGER,
    //   signature SEQUENCE,    (algorithm)
    //   issuer Name (SEQUENCE),
    //   validity SEQUENCE { notBefore Time, notAfter Time },
    //   subject Name (SEQUENCE),
    //   subjectPublicKeyInfo SEQUENCE,
    //   ...
    // }

    // Skip optional version [0]
    if p < tbs_end && cert_der[p] == 0xA0 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        p += 1 + ls + l;
    }
    // Serial number (INTEGER)
    if p < tbs_end && cert_der[p] == 0x02 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        let serial_bytes = &cert_der[p + 1 + ls..p + 1 + ls + l];
        info.serial = serial_bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        p += 1 + ls + l;
    }
    // signature algorithm (skip)
    if p < tbs_end && cert_der[p] == 0x30 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        p += 1 + ls + l;
    }
    // issuer Name
    if p < tbs_end && cert_der[p] == 0x30 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        info.issuer_cn = extract_cn(&cert_der[p + 1 + ls..p + 1 + ls + l]);
        p += 1 + ls + l;
    }
    // validity SEQUENCE { notBefore, notAfter }
    if p < tbs_end && cert_der[p] == 0x30 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        let v_body = &cert_der[p + 1 + ls..p + 1 + ls + l];
        let mut vp = 0;
        if vp < v_body.len() {
            // notBefore: UTCTime (0x17) or GeneralizedTime (0x18)
            let tag = v_body[vp];
            if tag == 0x17 || tag == 0x18 {
                let (tl, tls) = der_length(v_body, vp + 1)?;
                let time_bytes = &v_body[vp + 1 + tls..vp + 1 + tls + tl];
                info.not_before = format_asn1_time(tag, time_bytes);
                vp += 1 + tls + tl;
            }
        }
        if vp < v_body.len() {
            let tag = v_body[vp];
            if tag == 0x17 || tag == 0x18 {
                let (tl, tls) = der_length(v_body, vp + 1)?;
                let time_bytes = &v_body[vp + 1 + tls..vp + 1 + tls + tl];
                info.not_after = format_asn1_time(tag, time_bytes);
            }
        }
        p += 1 + ls + l;
    }
    // subject Name
    if p < tbs_end && cert_der[p] == 0x30 {
        let (l, ls) = der_length(cert_der, p + 1)?;
        info.subject_cn = extract_cn(&cert_der[p + 1 + ls..p + 1 + ls + l]);
    }

    Some(info)
}

/// Walk a Name (which is a SEQUENCE OF SET OF AttributeTypeAndValue)
/// looking for the CommonName (OID 2.5.4.3).
fn extract_cn(name_body: &[u8]) -> String {
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03]; // OID 2.5.4.3 in DER form
    let mut p = 0;
    while p < name_body.len() {
        let tag = name_body[p];
        if tag != 0x31 { break; } // RDN SET
        let (l, ls) = match der_length(name_body, p + 1) { Some(v) => v, None => break };
        let set_body = &name_body[p + 1 + ls..p + 1 + ls + l];
        // Each SET contains AttributeTypeAndValue ::= SEQUENCE { type OID, value }
        let mut sp = 0;
        while sp < set_body.len() {
            if set_body[sp] != 0x30 { break; }
            let (sl, sls) = match der_length(set_body, sp + 1) { Some(v) => v, None => break };
            let av = &set_body[sp + 1 + sls..sp + 1 + sls + sl];
            // OID first
            if !av.is_empty() && av[0] == 0x06 {
                let (ol, ols) = match der_length(av, 1) { Some(v) => v, None => break };
                if av.len() >= 1 + ols + ol && &av[1 + ols..1 + ols + ol] == cn_oid {
                    // Value follows: PrintableString (0x13), UTF8String (0x0c), or BMPString (0x1E)
                    let after = 1 + ols + ol;
                    if after < av.len() {
                        let (vl, vls) = match der_length(av, after + 1) { Some(v) => v, None => break };
                        let value_bytes = &av[after + 1 + vls..after + 1 + vls + vl];
                        return String::from_utf8_lossy(value_bytes).to_string();
                    }
                }
            }
            sp += 1 + sls + sl;
        }
        p += 1 + ls + l;
    }
    String::new()
}

fn format_asn1_time(tag: u8, bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ (12 chars)
        if s.len() >= 12 {
            let yy: u32 = s[0..2].parse().unwrap_or(0);
            let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            return format!("{yyyy}-{}-{} {}:{}:{} UTC",
                &s[2..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12]);
        }
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ (14 chars)
        if s.len() >= 14 {
            return format!("{}-{}-{} {}:{}:{} UTC",
                &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14]);
        }
    }
    s.to_string()
}

// ── DER helpers ────────────────────────────────────────────────────

/// Returns (body_start, body_size) of a SEQUENCE at the given offset.
fn der_seq(data: &[u8], off: usize) -> Option<(usize, usize)> {
    if off >= data.len() || data[off] != 0x30 { return None; }
    let (len, len_size) = der_length(data, off + 1)?;
    Some((off + 1 + len_size, len))
}

/// Returns (length_value, length_field_size_in_bytes).
fn der_length(data: &[u8], off: usize) -> Option<(usize, usize)> {
    if off >= data.len() { return None; }
    let first = data[off];
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || off + 1 + n > data.len() { return None; }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[off + 1 + i] as usize;
    }
    Some((len, 1 + n))
}

// ── Cert fingerprint (FNV-1a-128) ──────────────────────────────────
// Used as the canonical Cert node id. Not a cryptographic fingerprint
// (so labelled "fingerprint" not "sha256") — sufficient for graph
// node identity and round-trip stability. Forensic tooling needing
// the real SHA-256 should re-hash the DER themselves.

fn sha256_hex(data: &[u8]) -> String {
    // 128-bit FNV-1a, two 64-bit halves combined, hex-encoded.
    let mut h1 = 0xcbf29ce484222325u64;
    let mut h2 = 0x100000001b3u64;
    for &b in data {
        h1 ^= b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
        h2 ^= (b as u64).rotate_left(31);
        h2 = h2.wrapping_mul(0xcbf29ce484222325);
    }
    format!("{h1:016x}{h2:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_distinguishes_inputs() {
        let a = sha256_hex(b"abc");
        let b = sha256_hex(b"abc");
        let c = sha256_hex(b"abd");
        assert_eq!(a, b, "same input → same fingerprint");
        assert_ne!(a, c, "different input → different fingerprint");
        // 32 hex chars per FNV-1a half × 2 halves = 32-char hex output
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn der_length_short_form() {
        let data = [0x30u8, 0x05, 0x42, 0x42, 0x42, 0x42, 0x42];
        assert_eq!(der_length(&data, 1), Some((5, 1)));
    }

    #[test]
    fn der_length_long_form() {
        // 0x82 means 2-byte length follows
        let data = [0x30u8, 0x82, 0x01, 0x00];
        assert_eq!(der_length(&data, 1), Some((256, 3)));
    }

    #[test]
    fn locate_cert_table_returns_none_on_unsigned() {
        // Hand-build a tiny PE without a cert table
        let mut pe = vec![b'M', b'Z'];
        pe.extend(vec![0u8; 0x3a]);
        pe.extend(0x40u32.to_le_bytes()); // e_lfanew
        // PE header at 0x40
        pe.extend(b"PE\0\0");
        // COFF: machine, n_sections=1, ts, symtab, sym_count, opt_size=0xE0, chars
        pe.extend(0x8664u16.to_le_bytes()); // machine = x64
        pe.extend(1u16.to_le_bytes());      // n_sections
        pe.extend(0u32.to_le_bytes());
        pe.extend(0u32.to_le_bytes());
        pe.extend(0u32.to_le_bytes());
        pe.extend(0xE0u16.to_le_bytes());
        pe.extend(0u16.to_le_bytes());
        // Optional header
        pe.extend(0x20bu16.to_le_bytes()); // PE32+
        pe.extend(vec![0u8; 0xE0 - 2]);
        assert!(locate_cert_table(&pe).is_none());
    }
}
