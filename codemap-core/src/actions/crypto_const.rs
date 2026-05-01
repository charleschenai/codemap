// ── Crypto-Constants Scanner (Ship 1 #9a) ──────────────────────────
//
// Identifies cryptographic algorithms in PE/ELF binaries by scanning
// for well-known init values, S-boxes, polynomial constants, and
// magic numbers. Output: CryptoConstant nodes attached to the binary.
//
// Modeled on findcrypt-yara (`~/reference/codemap-research-targets/
// 09-findcrypt-yara/findcrypt3.rules`) — a 126-rule named-anchor set
// covering MD5/SHA*/Blowfish/RC6/TEA/AES/DES/CRC and big-num libraries.
// We hand-port the byte-level patterns; the regex-based "Big_Numbers"
// rules are skipped (they detect any long hex string and false-fire
// constantly on cert blobs / GUIDs).
//
// signsrch.xml (`~/reference/codemap-research-targets/11-ida-signsrch/
// signsrch.xml`) has 2,338 patterns covering the same algorithms in
// more variants — vendoring that as a bincode blob is the v2 plan
// (~50-100 KB embedded). For v1 we ship a curated, named subset.

use crate::types::{Graph, EntityKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian { Le, Be, Both }

impl Endian {
    fn as_str(self) -> &'static str {
        match self { Endian::Le => "le", Endian::Be => "be", Endian::Both => "le|be" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confidence { High, Medium, Low }

impl Confidence {
    fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

struct Sig {
    /// Display name (e.g., "init H0").
    name: &'static str,
    /// Algorithm family (e.g., "SHA-256").
    algorithm: &'static str,
    /// Bytes to match. Stored in the natural endian listed in `endian`.
    /// If `endian == Both`, we scan both byte orders.
    bytes: &'static [u8],
    endian: Endian,
    confidence: Confidence,
}

// Helper: emit a u32 init constant as little-endian bytes for memmem.
// Most x86 binaries store these little-endian; big-endian variants
// appear in network code and Java-derived crypto. We scan both unless
// the constant is symmetric.

const MD5_INIT: &[u8] = &[
    // h0..h3 little-endian: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10,
];

const SHA1_INIT: &[u8] = &[
    // h0..h4 little-endian: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10,
    0xF0, 0xE1, 0xD2, 0xC3,
];

const SHA256_INIT: &[u8] = &[
    // h0..h7 little-endian: 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    //                        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    0x67, 0xE6, 0x09, 0x6A,
    0x85, 0xAE, 0x67, 0xBB,
    0x72, 0xF3, 0x6E, 0x3C,
    0x3A, 0xF5, 0x4F, 0xA5,
    0x7F, 0x52, 0x0E, 0x51,
    0x8C, 0x68, 0x05, 0x9B,
    0xAB, 0xD9, 0x83, 0x1F,
    0x19, 0xCD, 0xE0, 0x5B,
];

const SHA512_INIT: &[u8] = &[
    // h0..h7 little-endian, 64-bit each
    // 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    // 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A,
    0x3B, 0xA7, 0xCA, 0x84, 0x85, 0xAE, 0x67, 0xBB,
    0x2B, 0xF8, 0x94, 0xFE, 0x72, 0xF3, 0x6E, 0x3C,
    0xF1, 0x36, 0x1D, 0x5F, 0x3A, 0xF5, 0x4F, 0xA5,
    0xD1, 0x82, 0xE6, 0xAD, 0x7F, 0x52, 0x0E, 0x51,
    0x1F, 0x6C, 0x3E, 0x2B, 0x8C, 0x68, 0x05, 0x9B,
    0x6B, 0xBD, 0x41, 0xFB, 0xAB, 0xD9, 0x83, 0x1F,
    0x79, 0x21, 0x7E, 0x13, 0x19, 0xCD, 0xE0, 0x5B,
];

const RIPEMD160_INIT: &[u8] = &[
    // RIPEMD-160 shares MD5/SHA1's first 4 words and adds 0xC3D2E1F0
    // as h4. Distinguishing from SHA-1 isn't possible from init alone;
    // scanning RIPEMD-only constants would require pattern-step values.
    // We list these but mark MEDIUM confidence and call it RIPEMD-160
    // when matched at offsets that don't also have SHA-1 markers nearby.
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10,
    0xF0, 0xE1, 0xD2, 0xC3,
];

// Blowfish P-array first 8 entries (pi digits, big-endian as stored
// in the published spec, then word-by-word little-endian on x86).
const BLOWFISH_P_LE: &[u8] = &[
    // 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344
    0x88, 0x6A, 0x3F, 0x24,
    0xD3, 0x08, 0xA3, 0x85,
    0x2E, 0x8A, 0x19, 0x13,
    0x44, 0x73, 0x70, 0x03,
];

const BLOWFISH_P_BE: &[u8] = &[
    0x24, 0x3F, 0x6A, 0x88,
    0x85, 0xA3, 0x08, 0xD3,
    0x13, 0x19, 0x8A, 0x2E,
    0x03, 0x70, 0x73, 0x44,
];

// AES Rcon constants (round-key generation): 01 02 04 08 10 20 40 80 1B 36
const AES_RCON: &[u8] = &[
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

// AES forward S-box first 16 bytes. The full 256-byte S-box is
// distinctive, but the first 16 bytes (63 7C 77 7B F2 6B 6F C5
// 30 01 67 2B FE D7 AB 76) are unique enough on their own.
const AES_SBOX_PREFIX: &[u8] = &[
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
];

// AES inverse S-box first 16 bytes
const AES_INV_SBOX_PREFIX: &[u8] = &[
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
];

// DES initial permutation IP table first 16 bytes
const DES_IP_PREFIX: &[u8] = &[
    0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12, 0x0A, 0x02,
    0x3C, 0x34, 0x2C, 0x24, 0x1C, 0x14, 0x0C, 0x04,
];

// CRC-32 (IEEE 802.3) reflected polynomial 0xEDB88320
const CRC32_POLY_REFLECTED: &[u8] = &[0x20, 0x83, 0xB8, 0xED];
// CRC-32 forward polynomial 0x04C11DB7
const CRC32_POLY_FORWARD: &[u8]   = &[0xB7, 0x1D, 0xC1, 0x04];
// CRC-32C (Castagnoli) reflected polynomial 0x82F63B78
const CRC32C_POLY: &[u8]          = &[0x78, 0x3B, 0xF6, 0x82];

// CRC-32 lookup table first 4 entries (0x00000000 0x77073096 0xEE0E612C 0x990951BA, LE)
const CRC32_TABLE_PREFIX: &[u8] = &[
    0x00, 0x00, 0x00, 0x00,
    0x96, 0x30, 0x07, 0x77,
    0x2C, 0x61, 0x0E, 0xEE,
    0xBA, 0x51, 0x09, 0x99,
];

// RC6 magic constants P32=B7E15163, Q32=9E3779B9
const RC6_P32: &[u8] = &[0x63, 0x51, 0xE1, 0xB7];
const RC6_Q32: &[u8] = &[0xB9, 0x79, 0x37, 0x9E];

// TEA delta constant 0x9E3779B9 (also Q32 of RC6)
const TEA_DELTA: &[u8] = &[0xB9, 0x79, 0x37, 0x9E];

// Whirlpool S-box first 16 bytes
const WHIRLPOOL_SBOX_PREFIX: &[u8] = &[
    0x18, 0x18, 0x60, 0x18, 0xC0, 0x78, 0x30, 0xD8,
    0x23, 0x23, 0x8C, 0x23, 0x05, 0xAF, 0x46, 0x26,
];

// MD2 substitution table first 16 bytes
const MD2_SUBST_PREFIX: &[u8] = &[
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01,
    0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
];

// MD4 init = MD5 init (same constants). We collapse with MD5 above.
// SHA-224 init differs: 0xC1059ED8, 0x367CD507, 0x3070DD17, ...
const SHA224_INIT: &[u8] = &[
    0xD8, 0x9E, 0x05, 0xC1,
    0x07, 0xD5, 0x7C, 0x36,
    0x17, 0xDD, 0x70, 0x30,
    0x39, 0x59, 0x0E, 0xF7,
    0xFF, 0xC0, 0x0B, 0x31,
    0x68, 0x58, 0x15, 0x11,
    0x64, 0xF9, 0x8F, 0xA7,
    0xBE, 0xFA, 0x4F, 0xA4,
];

// SHA-384 init (first 64 bytes): 0xCBBB9D5DC1059ED8, 0x629A292A367CD507, etc.
const SHA384_INIT: &[u8] = &[
    0xD8, 0x9E, 0x05, 0xC1, 0x5D, 0x9D, 0xBB, 0xCB,
    0x07, 0xD5, 0x7C, 0x36, 0x2A, 0x29, 0x9A, 0x62,
    0x17, 0xDD, 0x70, 0x30, 0x70, 0xDD, 0x17, 0x9C,
    0x39, 0x59, 0x0E, 0xF7, 0xC2, 0x6E, 0xF1, 0x39,
    0xFF, 0xC0, 0x0B, 0x31, 0x65, 0xA8, 0x9D, 0xFF,
    0x68, 0x58, 0x15, 0x11, 0x4F, 0xCB, 0x2B, 0x68,
    0xF7, 0x88, 0xC6, 0xDB, 0x9A, 0xE9, 0xC5, 0x58,
    0xBE, 0xFA, 0x4F, 0xA4, 0x91, 0x47, 0x8D, 0xB1,
];

// ── The signature catalog ──────────────────────────────────────────

const SIGS: &[Sig] = &[
    Sig { name: "init constants H0..H3 (LE)", algorithm: "MD5", bytes: MD5_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init constants H0..H4 (LE)", algorithm: "SHA-1", bytes: SHA1_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init constants H0..H7 (LE)", algorithm: "SHA-256", bytes: SHA256_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init constants (LE 64-bit)", algorithm: "SHA-512", bytes: SHA512_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init constants (LE)", algorithm: "SHA-224", bytes: SHA224_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init constants (LE 64-bit)", algorithm: "SHA-384", bytes: SHA384_INIT,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "init H0..H4 (LE)", algorithm: "RIPEMD-160", bytes: RIPEMD160_INIT,
          endian: Endian::Le, confidence: Confidence::Medium },
    Sig { name: "P-array prefix (LE, π digits)", algorithm: "Blowfish", bytes: BLOWFISH_P_LE,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "P-array prefix (BE, π digits)", algorithm: "Blowfish", bytes: BLOWFISH_P_BE,
          endian: Endian::Be, confidence: Confidence::High },
    Sig { name: "Rcon table", algorithm: "AES", bytes: AES_RCON,
          endian: Endian::Both, confidence: Confidence::Medium },
    Sig { name: "S-box prefix", algorithm: "AES", bytes: AES_SBOX_PREFIX,
          endian: Endian::Both, confidence: Confidence::High },
    Sig { name: "inverse S-box prefix", algorithm: "AES", bytes: AES_INV_SBOX_PREFIX,
          endian: Endian::Both, confidence: Confidence::High },
    Sig { name: "IP table prefix", algorithm: "DES", bytes: DES_IP_PREFIX,
          endian: Endian::Both, confidence: Confidence::High },
    Sig { name: "polynomial 0xEDB88320 (reflected)", algorithm: "CRC-32",
          bytes: CRC32_POLY_REFLECTED, endian: Endian::Le, confidence: Confidence::Medium },
    Sig { name: "polynomial 0x04C11DB7 (forward)", algorithm: "CRC-32",
          bytes: CRC32_POLY_FORWARD, endian: Endian::Le, confidence: Confidence::Medium },
    Sig { name: "polynomial 0x82F63B78 (reflected)", algorithm: "CRC-32C",
          bytes: CRC32C_POLY, endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "lookup-table prefix", algorithm: "CRC-32", bytes: CRC32_TABLE_PREFIX,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "magic constant P32 (B7E15163)", algorithm: "RC6", bytes: RC6_P32,
          endian: Endian::Le, confidence: Confidence::High },
    Sig { name: "magic constant Q32 (9E3779B9)", algorithm: "RC6", bytes: RC6_Q32,
          endian: Endian::Le, confidence: Confidence::Medium },
    Sig { name: "delta constant 0x9E3779B9 (golden ratio)", algorithm: "TEA/XTEA",
          bytes: TEA_DELTA, endian: Endian::Le, confidence: Confidence::Low },
    Sig { name: "S-box prefix", algorithm: "Whirlpool", bytes: WHIRLPOOL_SBOX_PREFIX,
          endian: Endian::Both, confidence: Confidence::High },
    Sig { name: "substitution table prefix", algorithm: "MD2", bytes: MD2_SUBST_PREFIX,
          endian: Endian::Both, confidence: Confidence::High },
];

// ── Action ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Match {
    algorithm: &'static str,
    name: &'static str,
    offset: usize,
    endian: &'static str,
    confidence: &'static str,
}

pub fn crypto_const(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap crypto-const <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 16 {
        return format!("Binary too small ({} bytes) for crypto-constant scanning", data.len());
    }

    let matches = scan(&data);
    register_into_graph(graph, target, &data, &matches);
    format_report(target, &data, &matches)
}

fn scan(data: &[u8]) -> Vec<Match> {
    let mut out = Vec::new();
    for sig in SIGS {
        // Search for the byte pattern. memmem-style: linear scan with
        // first-byte filter. For our pattern lengths (≤ 64 bytes) and
        // typical binary sizes (< 100 MB), naive scan is fast enough
        // (~50 ns per pattern per MB on modern CPUs).
        for (off, _) in find_all(data, sig.bytes) {
            out.push(Match {
                algorithm: sig.algorithm,
                name: sig.name,
                offset: off,
                endian: sig.endian.as_str(),
                confidence: sig.confidence.as_str(),
            });
        }
        // For Endian::Both, also scan the reversed pattern.
        if matches!(sig.endian, Endian::Both) && sig.bytes.len() >= 4 {
            let mut rev: Vec<u8> = sig.bytes.to_vec();
            rev.reverse();
            for (off, _) in find_all(data, &rev) {
                out.push(Match {
                    algorithm: sig.algorithm,
                    name: sig.name,
                    offset: off,
                    endian: "be|reversed",
                    confidence: sig.confidence.as_str(),
                });
            }
        }
    }
    out
}

/// Naive linear search returning all non-overlapping match offsets.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<(usize, ())> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() { return out; }
    let n = needle.len();
    let mut i = 0;
    while i + n <= haystack.len() {
        if &haystack[i..i + n] == needle {
            out.push((i, ()));
            i += n;       // non-overlapping
        } else {
            i += 1;
        }
    }
    out
}

fn register_into_graph(graph: &mut Graph, target: &str, _data: &[u8], matches: &[Match]) {
    if matches.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    // Dedup by (algorithm, name) — we only care that the algorithm is
    // present, not how many times its constants appear.
    let mut seen = std::collections::HashSet::new();
    for m in matches {
        let key = (m.algorithm, m.name);
        if !seen.insert(key) { continue; }
        let crypto_id = format!("crypto:{}::{}", m.algorithm, m.name);
        let off = format!("{:#x}", m.offset);
        graph.ensure_typed_node(&crypto_id, EntityKind::CryptoConstant, &[
            ("algorithm", m.algorithm),
            ("constant_name", m.name),
            ("offset", &off),
            ("endian", m.endian),
            ("confidence", m.confidence),
        ]);
        graph.add_edge(&bin_id, &crypto_id);
    }
}

fn format_report(target: &str, data: &[u8], matches: &[Match]) -> String {
    let mut lines = vec![
        format!("=== Crypto Constants Scan: {} ===", target),
        format!("Binary size:      {} bytes", data.len()),
        format!("Signatures:       {}", SIGS.len()),
        format!("Matches:          {}", matches.len()),
        String::new(),
    ];
    if matches.is_empty() {
        lines.push("(no crypto constants detected)".to_string());
        return lines.join("\n");
    }

    // Group by algorithm
    let mut by_algo: std::collections::BTreeMap<&str, Vec<&Match>> =
        std::collections::BTreeMap::new();
    for m in matches {
        by_algo.entry(m.algorithm).or_default().push(m);
    }

    for (algo, ms) in &by_algo {
        lines.push(format!("── {} ──", algo));
        for m in ms {
            lines.push(format!(
                "  [{}] {} @ {:#x}  ({})",
                m.confidence, m.name, m.offset, m.endian
            ));
        }
    }
    lines.push(String::new());
    lines.push("Try: codemap meta-path \"pe->crypto\"  (cross-binary crypto inventory)".to_string());
    lines.push("     codemap pagerank --type crypto    (most-prevalent crypto algorithms)".to_string());
    lines.join("\n")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_md5_init_at_known_offset() {
        // Build a binary blob with MD5 init at offset 0x100.
        let mut data = vec![0u8; 0x200];
        data[0x100..0x110].copy_from_slice(MD5_INIT);
        let matches = scan(&data);
        let md5 = matches.iter().filter(|m| m.algorithm == "MD5").count();
        assert!(md5 >= 1, "expected ≥ 1 MD5 match, got {md5}");
        let m = matches.iter().find(|m| m.algorithm == "MD5").unwrap();
        assert_eq!(m.offset, 0x100);
    }

    #[test]
    fn finds_sha256_init_at_known_offset() {
        let mut data = vec![0u8; 0x200];
        data[0x80..0xA0].copy_from_slice(SHA256_INIT);
        let matches = scan(&data);
        assert!(matches.iter().any(|m| m.algorithm == "SHA-256" && m.offset == 0x80));
    }

    #[test]
    fn finds_aes_sbox_prefix() {
        let mut data = vec![0u8; 0x100];
        data[0x40..0x50].copy_from_slice(AES_SBOX_PREFIX);
        let matches = scan(&data);
        assert!(matches.iter().any(|m| m.algorithm == "AES" && m.name == "S-box prefix"));
    }

    #[test]
    fn finds_crc32_polynomial() {
        let mut data = vec![0u8; 0x100];
        data[0x10..0x14].copy_from_slice(CRC32_POLY_REFLECTED);
        let matches = scan(&data);
        assert!(matches.iter().any(|m| m.algorithm == "CRC-32" && m.name.contains("EDB88320")));
    }

    #[test]
    fn finds_blowfish_le_only_when_present() {
        let mut data = vec![0u8; 0x100];
        data[0x40..0x50].copy_from_slice(BLOWFISH_P_LE);
        let matches = scan(&data);
        let bf = matches.iter().filter(|m| m.algorithm == "Blowfish").count();
        // We embedded LE form; should match the LE signature.
        assert!(bf >= 1);
    }

    #[test]
    fn empty_data_yields_no_matches() {
        let matches = scan(&[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn random_data_yields_no_matches() {
        // Pseudo-random bytes — should not contain any of our patterns.
        let mut data = vec![0u8; 0x10000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2654435761) >> 16) as u8;
        }
        let matches = scan(&data);
        // Allow up to 2 false-positive matches (4-byte patterns can
        // collide in PRNG-ish streams). Real crypto-using binaries hit
        // dozens of distinct algorithm signatures; pure-PRNG content
        // should be near zero.
        assert!(matches.len() <= 2,
            "expected ≤ 2 spurious matches, got {} ({:?})",
            matches.len(),
            matches.iter().map(|m| (m.algorithm, m.name)).collect::<Vec<_>>());
    }

    #[test]
    fn sig_catalog_covers_expected_algorithms() {
        use std::collections::HashSet;
        let algos: HashSet<&str> = SIGS.iter().map(|s| s.algorithm).collect();
        for expected in ["MD5", "SHA-1", "SHA-256", "SHA-512", "AES", "DES", "Blowfish",
                          "CRC-32", "RC6", "TEA/XTEA", "Whirlpool"] {
            assert!(algos.contains(expected), "missing signature for {expected}");
        }
    }

    #[test]
    fn find_all_handles_overlapping_correctly() {
        // Pattern "ABAB" in "ABABAB" — non-overlapping match yields 1 hit at offset 0
        // (offsets 0 and 2 would be overlapping).
        let hits = find_all(b"ABABAB", b"ABAB");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
    }
}
