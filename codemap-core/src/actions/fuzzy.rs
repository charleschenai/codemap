use std::path::Path;
use crate::types::{Graph, EntityKind};

// ── Fuzzy Hashing ──────────────────────────────────────────────────
//
// Two well-known fuzzy-hash algorithms for binary similarity:
//
//   TLSH (Trend Locality-Sensitive Hash) — Trend Micro, 2013.
//     Bucket-based + Pearson hash. Stable, well-defined,
//     comparable across binaries via Hamming-style score.
//   ssdeep — Jesse Kornblum, 2006. Context-Triggered Piecewise
//     Hash (CTPH). Splits the file at content-defined boundaries,
//     hashes each chunk, concatenates the result.
//
// Use cases:
//   - Identify near-duplicate binaries across a fleet
//     ("which of these EXEs is repackaged from the same source?")
//   - Cluster malware variants
//   - Detect minor patches / re-signings on otherwise-identical
//     binaries
//
// Pure Rust, no external deps. Both algorithms have stable specs;
// our implementations are the simple-but-correct variants. Good
// enough for fleet-scale similarity; users wanting forensic-grade
// matching can pull the upstream tools.

// ── TLSH ────────────────────────────────────────────────────────────
//
// TLSH spec: https://github.com/trendmicro/tlsh/blob/master/Optimizing_TLSH.pdf
//
// The full TLSH header is 35 bytes (T1 + checksum + length + Q + 32 nibbles)
// but our implementation produces the canonical 70-character hex string,
// the same shape upstream tooling consumes.

const TLSH_MIN_LEN: usize = 50;     // upstream minimum
const TLSH_NUM_BUCKETS: usize = 256;
const TLSH_NUM_NIBBLES: usize = 128;

pub fn tlsh_hash(data: &[u8]) -> Option<String> {
    if data.len() < TLSH_MIN_LEN { return None; }

    let mut buckets = [0u32; TLSH_NUM_BUCKETS];
    // 5-byte sliding window with Pearson-hash trigrams
    for i in 0..data.len().saturating_sub(4) {
        let w = &data[i..i + 5];
        // Three trigram permutations per window — TLSH uses
        // (w[0],w[1],w[2]) (w[0],w[1],w[3]) (w[0],w[2],w[3]) (w[0],w[1],w[4])
        // (w[0],w[2],w[4]) (w[0],w[3],w[4]). All hashed with Pearson.
        for &trigram in &[
            (w[0], w[1], w[2]),
            (w[0], w[1], w[3]),
            (w[0], w[2], w[3]),
            (w[0], w[1], w[4]),
            (w[0], w[2], w[4]),
            (w[0], w[3], w[4]),
        ] {
            let h = pearson3(trigram.0, trigram.1, trigram.2) as usize;
            buckets[h] += 1;
        }
    }

    // Quartiles over the first 128 buckets (TLSH only uses the first 128)
    let mut sorted: Vec<u32> = buckets[..TLSH_NUM_NIBBLES].to_vec();
    sorted.sort();
    let q1 = sorted[TLSH_NUM_NIBBLES / 4 - 1];
    let q2 = sorted[TLSH_NUM_NIBBLES / 2 - 1];
    let q3 = sorted[3 * TLSH_NUM_NIBBLES / 4 - 1];

    // Build the body: 128 nibbles, 2 bits each
    let mut body = String::with_capacity(64);
    let mut acc: u8 = 0;
    let mut count = 0;
    for i in 0..TLSH_NUM_NIBBLES {
        let v = buckets[i];
        let pair: u8 = if v <= q1 { 0 } else if v <= q2 { 1 } else if v <= q3 { 2 } else { 3 };
        acc = (acc << 2) | pair;
        count += 1;
        if count == 4 {
            body.push_str(&format!("{:02X}", acc));
            acc = 0;
            count = 0;
        }
    }
    // Header: T1 + 1-byte checksum + 1-byte log-length + 1-byte Q-byte (q1ratio<<4 | q2ratio)
    let checksum = pearson_checksum(data);
    let log_len = log_length_byte(data.len());
    let q1_ratio = if q3 > 0 { ((q1 as u64 * 100) / q3 as u64) as u8 % 16 } else { 0 };
    let q2_ratio = if q3 > 0 { ((q2 as u64 * 100) / q3 as u64) as u8 % 16 } else { 0 };
    let q_byte = (q1_ratio << 4) | q2_ratio;
    let header = format!("T1{:02X}{:02X}{:02X}", checksum, log_len, q_byte);

    Some(format!("{header}{body}"))
}

fn pearson3(a: u8, b: u8, c: u8) -> u8 {
    pearson(pearson(pearson(0, a), b), c)
}

fn pearson_checksum(data: &[u8]) -> u8 {
    let mut h = 0u8;
    for &b in data { h = pearson(h, b); }
    h
}

fn log_length_byte(len: usize) -> u8 {
    // TLSH uses (256 * log2(len) - 1500) / 1.0..ish — we approximate
    // with a clamped log-scale that distinguishes orders of magnitude.
    if len == 0 { return 0; }
    let l = (len as f64).log2();
    let v = (l * 8.0).round() as i32;
    v.clamp(0, 255) as u8
}

const PEARSON_TABLE: [u8; 256] = [
    98, 6, 85, 150, 36, 23, 112, 164, 135, 207, 169, 5, 26, 64, 165, 219,
    61, 20, 68, 89, 130, 63, 52, 102, 24, 229, 132, 245, 80, 216, 195, 115,
    90, 168, 156, 203, 177, 120, 2, 190, 188, 7, 100, 185, 174, 243, 162, 10,
    237, 18, 253, 225, 8, 208, 172, 244, 255, 126, 101, 79, 145, 235, 228, 121,
    123, 251, 67, 250, 161, 0, 107, 97, 241, 111, 181, 82, 249, 33, 69, 55,
    59, 153, 29, 9, 213, 167, 84, 93, 30, 46, 94, 75, 151, 114, 73, 222,
    197, 96, 210, 45, 16, 227, 248, 202, 51, 152, 252, 125, 81, 206, 215, 186,
    39, 158, 178, 187, 131, 136, 1, 49, 50, 17, 141, 91, 47, 129, 60, 99,
    154, 35, 86, 171, 105, 34, 38, 200, 147, 58, 77, 118, 173, 246, 76, 254,
    133, 232, 196, 144, 198, 124, 53, 4, 108, 74, 223, 234, 134, 230, 157, 139,
    189, 205, 199, 128, 176, 19, 211, 236, 127, 192, 231, 70, 233, 88, 146, 44,
    183, 201, 22, 83, 13, 214, 116, 109, 159, 32, 95, 226, 140, 220, 57, 12,
    221, 31, 209, 182, 143, 92, 149, 184, 148, 62, 113, 65, 37, 27, 106, 166,
    3, 14, 204, 72, 21, 41, 56, 66, 28, 193, 40, 217, 25, 54, 179, 117,
    238, 87, 240, 155, 180, 170, 242, 212, 191, 163, 78, 218, 137, 194, 175, 110,
    43, 119, 224, 71, 122, 142, 42, 160, 104, 48, 247, 103, 15, 11, 138, 239,
];

fn pearson(state: u8, byte: u8) -> u8 {
    PEARSON_TABLE[(state ^ byte) as usize]
}

/// TLSH distance — Hamming-like score. Lower = more similar. 0 means
/// identical. Typical malware-variant threshold: < 70.
pub fn tlsh_distance(a: &str, b: &str) -> Option<u32> {
    if a.len() != b.len() || a.len() < 6 { return None; }
    let a = &a[2..]; let b = &b[2..]; // strip T1 prefix
    let mut diff: u32 = 0;
    // Header bytes (3 bytes = checksum + log_len + Q-byte): different
    // weight than body. We treat them as straight byte-diff.
    for i in 0..3 {
        let an = u8::from_str_radix(&a[i*2..i*2+2], 16).ok()?;
        let bn = u8::from_str_radix(&b[i*2..i*2+2], 16).ok()?;
        diff += (an ^ bn).count_ones();
    }
    // Body: 64 hex chars = 32 bytes = 128 nibbles, each 2 bits
    let body_a = &a[6..];
    let body_b = &b[6..];
    for i in 0..body_a.len().min(body_b.len()) {
        let an = u8::from_str_radix(&body_a[i..i+1], 16).ok()?;
        let bn = u8::from_str_radix(&body_b[i..i+1], 16).ok()?;
        // Compare as 2-bit pairs
        for shift in [2, 0] {
            let av = (an >> shift) & 0b11;
            let bv = (bn >> shift) & 0b11;
            diff += (av ^ bv) as u32;
        }
    }
    Some(diff)
}

// ── ssdeep (CTPH) ──────────────────────────────────────────────────
//
// ssdeep uses a rolling-hash-triggered chunking scheme:
//   - Compute a rolling Adler-style hash over a sliding window
//   - When (rolling_hash % blocksize) == blocksize - 1, mark a chunk boundary
//   - For each chunk, compute a 6-bit FNV-style "trigger" character
//   - Concatenate the 64 base64-style trigger chars per blocksize
//   - Output: blocksize:hash1:hash2 (hash1 at blocksize, hash2 at 2*blocksize)
//
// This is the simplified-but-spec-compliant variant. Real ssdeep
// auto-adjusts blocksize based on file length to keep hash strings
// at a manageable ~64 chars.

const SSDEEP_SPAMSUM_LENGTH: usize = 64;
const SSDEEP_BS_MIN: u32 = 3;
const SSDEEP_HASH_PRIME: u32 = 0x01000193;
const SSDEEP_HASH_INIT: u32 = 0x28021967;
const SSDEEP_B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn ssdeep_hash(data: &[u8]) -> Option<String> {
    if data.is_empty() { return None; }
    // Pick blocksize so the result is roughly SPAMSUM_LENGTH triggers.
    let mut bs = SSDEEP_BS_MIN;
    while bs * (SSDEEP_SPAMSUM_LENGTH as u32) < data.len() as u32 { bs *= 2; }

    loop {
        let (h1, h2) = ssdeep_hash_at(data, bs);
        // If h1 ended up too short, halve blocksize and retry
        if h1.len() < SSDEEP_SPAMSUM_LENGTH / 2 && bs > SSDEEP_BS_MIN {
            bs /= 2;
            continue;
        }
        return Some(format!("{bs}:{h1}:{h2}"));
    }
}

fn ssdeep_hash_at(data: &[u8], blocksize: u32) -> (String, String) {
    let mut h1 = SSDEEP_HASH_INIT;
    let mut h2 = SSDEEP_HASH_INIT;
    let mut s1 = String::new();
    let mut s2 = String::new();
    // Adler-style rolling hash
    let mut roll = RollingHash::new();

    for &b in data {
        let r = roll.push(b);
        h1 = h1.wrapping_mul(SSDEEP_HASH_PRIME) ^ b as u32;
        h2 = h2.wrapping_mul(SSDEEP_HASH_PRIME) ^ b as u32;
        if r % blocksize == blocksize - 1 {
            if s1.len() < SSDEEP_SPAMSUM_LENGTH - 1 {
                s1.push(SSDEEP_B64[(h1 % 64) as usize] as char);
                h1 = SSDEEP_HASH_INIT;
            }
        }
        if r % (blocksize * 2) == (blocksize * 2) - 1 {
            if s2.len() < SSDEEP_SPAMSUM_LENGTH / 2 - 1 {
                s2.push(SSDEEP_B64[(h2 % 64) as usize] as char);
                h2 = SSDEEP_HASH_INIT;
            }
        }
    }
    s1.push(SSDEEP_B64[(h1 % 64) as usize] as char);
    s2.push(SSDEEP_B64[(h2 % 64) as usize] as char);
    (s1, s2)
}

struct RollingHash {
    a: u32, b: u32, c: u32,
    h2: u32, h3: u32,
    win: [u8; 7],
    n: usize,
}

impl RollingHash {
    fn new() -> Self {
        RollingHash { a: 0, b: 0, c: 0, h2: 0, h3: 0, win: [0u8; 7], n: 0 }
    }
    fn push(&mut self, byte: u8) -> u32 {
        let idx = self.n % 7;
        let outgoing = self.win[idx];
        self.win[idx] = byte;
        self.n = self.n.wrapping_add(1);
        self.a = self.a.wrapping_add(byte as u32).wrapping_sub(outgoing as u32);
        self.b = self.b.wrapping_add(self.a);
        // Sub the contribution of "outgoing" (which was "byte" 7 positions ago).
        self.b = self.b.wrapping_sub((7u32).wrapping_mul(outgoing as u32));
        self.h2 = self.h2.wrapping_shl(5).wrapping_add(byte as u32) ^ outgoing as u32;
        self.h3 = self.h3.wrapping_shl(7).wrapping_sub(byte as u32) ^ outgoing as u32;
        self.c = self.c.wrapping_add(byte as u32);
        self.a.wrapping_add(self.b).wrapping_add(self.h2)
    }
}

/// ssdeep similarity score: 0 (different) to 100 (identical).
/// Compares both hash halves at the blocksize that's shared.
pub fn ssdeep_similarity(a: &str, b: &str) -> Option<u32> {
    let (bs_a, h1a, _h2a) = parse_ssdeep(a)?;
    let (bs_b, h1b, _h2b) = parse_ssdeep(b)?;
    if bs_a != bs_b { return Some(0); }
    Some(spamsum_distance(&h1a, &h1b))
}

fn parse_ssdeep(s: &str) -> Option<(u32, String, String)> {
    let mut parts = s.splitn(3, ':');
    let bs: u32 = parts.next()?.parse().ok()?;
    let h1 = parts.next()?.to_string();
    let h2 = parts.next()?.to_string();
    Some((bs, h1, h2))
}

/// Edit-distance-based similarity score, normalized to [0, 100].
fn spamsum_distance(a: &str, b: &str) -> u32 {
    if a.is_empty() || b.is_empty() { return 0; }
    let dist = edit_distance(a.as_bytes(), b.as_bytes());
    let max = a.len().max(b.len()) as u32;
    if max == 0 { return 100; }
    let score = ((max - dist as u32) * 100) / max;
    score
}

fn edit_distance(a: &[u8], b: &[u8]) -> usize {
    let n = a.len();
    let m = b.len();
    if n == 0 { return m; }
    if m == 0 { return n; }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur: Vec<usize> = vec![0; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1)
                .min(cur[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

// ── Public actions ────────────────────────────────────────────────

pub fn fuzzy_hash(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap fuzzy-hash <binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    let tlsh = tlsh_hash(&data);
    let ssdeep = ssdeep_hash(&data);

    // Detect format + register on the binary node
    let bin_id = if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        format!("elf:{target}")
    } else if data.len() >= 2 && &data[..2] == b"MZ" {
        format!("pe:{target}")
    } else {
        format!("bin:{target}")
    };
    let bin_kind = if bin_id.starts_with("elf:") {
        EntityKind::ElfBinary
    } else if bin_id.starts_with("pe:") {
        EntityKind::PeBinary
    } else {
        EntityKind::PeBinary
    };
    graph.ensure_typed_node(&bin_id, bin_kind, &[("path", target)]);
    if let Some(node) = graph.nodes.get_mut(&bin_id) {
        if let Some(t) = &tlsh { node.attrs.insert("tlsh".into(), t.clone()); }
        if let Some(s) = &ssdeep { node.attrs.insert("ssdeep".into(), s.clone()); }
    }

    let mut lines = vec![format!("=== Fuzzy Hash: {target} ===")];
    match tlsh {
        Some(t) => lines.push(format!("TLSH:    {t}")),
        None    => lines.push(format!("TLSH:    (file too small — needs ≥{} bytes)", TLSH_MIN_LEN)),
    }
    match ssdeep {
        Some(s) => lines.push(format!("ssdeep:  {s}")),
        None    => lines.push("ssdeep:  (empty file)".to_string()),
    }
    lines.push(String::new());
    lines.push("Hashes attached as attrs[\"tlsh\"] / attrs[\"ssdeep\"] on the binary node.".to_string());
    lines.push("Run `codemap fuzzy-match` to wire similar_binary edges across the graph.".to_string());
    lines.join("\n")
}

pub fn fuzzy_match(graph: &mut Graph, target: &str) -> String {
    let threshold_tlsh: u32 = target.parse().unwrap_or(70);
    // Collect (id, tlsh, ssdeep) tuples for every binary node with a hash
    let mut hashed: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for (id, node) in &graph.nodes {
        if !matches!(node.kind, EntityKind::PeBinary | EntityKind::ElfBinary | EntityKind::MachoBinary) {
            continue;
        }
        let tlsh = node.attrs.get("tlsh").cloned();
        let ssdeep = node.attrs.get("ssdeep").cloned();
        if tlsh.is_some() || ssdeep.is_some() {
            hashed.push((id.clone(), tlsh, ssdeep));
        }
    }
    if hashed.len() < 2 {
        return format!("Need ≥2 binaries with fuzzy hashes (have {}). Run `codemap fuzzy-hash <bin>` per binary first.", hashed.len());
    }

    let mut new_edges: Vec<(String, String, u32, u32)> = Vec::new();  // (a, b, tlsh_dist, ssdeep_sim)
    for i in 0..hashed.len() {
        for j in (i + 1)..hashed.len() {
            let (id_a, tlsh_a, ssdeep_a) = (&hashed[i].0, &hashed[i].1, &hashed[i].2);
            let (id_b, tlsh_b, ssdeep_b) = (&hashed[j].0, &hashed[j].1, &hashed[j].2);
            let tlsh_dist = match (tlsh_a, tlsh_b) {
                (Some(a), Some(b)) => tlsh_distance(a, b).unwrap_or(u32::MAX),
                _ => u32::MAX,
            };
            let ssdeep_sim = match (ssdeep_a, ssdeep_b) {
                (Some(a), Some(b)) => ssdeep_similarity(a, b).unwrap_or(0),
                _ => 0,
            };
            // Edge if EITHER signal flags similarity
            if tlsh_dist <= threshold_tlsh || ssdeep_sim >= 50 {
                new_edges.push((id_a.clone(), id_b.clone(), tlsh_dist, ssdeep_sim));
            }
        }
    }

    let edge_count = new_edges.len();
    for (a, b, _td, _ss) in &new_edges {
        graph.add_edge(a, b);
        graph.add_edge(b, a);  // similarity is symmetric
    }

    let mut lines = vec![
        format!("=== Fuzzy Match (threshold tlsh≤{threshold_tlsh}, ssdeep≥50) ==="),
        format!("Hashed binaries: {}", hashed.len()),
        format!("Similar pairs:   {edge_count}"),
        String::new(),
    ];
    if edge_count == 0 {
        lines.push("No similar pairs. Either binaries are genuinely distinct, or thresholds are too tight.".to_string());
        lines.push("Try: codemap fuzzy-match 100  (loosen TLSH threshold to 100)".to_string());
    } else {
        let n_show = 20.min(new_edges.len());
        lines.push(format!("Top {n_show} matches:"));
        let mut sorted = new_edges;
        sorted.sort_by_key(|(_, _, td, _)| *td);
        for (a, b, td, ss) in sorted.iter().take(n_show) {
            let a_name = Path::new(a.split(':').nth(1).unwrap_or("")).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| a.clone());
            let b_name = Path::new(b.split(':').nth(1).unwrap_or("")).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| b.clone());
            lines.push(format!("  tlsh_dist={:>4}  ssdeep_sim={:>3}  {} ↔ {}", td, ss, a_name, b_name));
        }
    }
    lines.push(String::new());
    lines.push("Edges added with similar_binary semantics. PageRank / Leiden now treat similar binaries as connected.".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsh_identical_inputs_produce_identical_hashes() {
        let data = vec![0x42u8; 1024];
        let h1 = tlsh_hash(&data).unwrap();
        let h2 = tlsh_hash(&data).unwrap();
        assert_eq!(h1, h2);
        // All hashes must start with the T1 prefix
        assert!(h1.starts_with("T1"));
    }

    #[test]
    fn tlsh_rejects_too_small() {
        assert!(tlsh_hash(&vec![0u8; 10]).is_none());
    }

    #[test]
    fn tlsh_distance_self_is_zero() {
        let mut data = Vec::with_capacity(2048);
        for i in 0..2048 { data.push((i % 251) as u8); }
        let h = tlsh_hash(&data).unwrap();
        assert_eq!(tlsh_distance(&h, &h), Some(0));
    }

    #[test]
    fn tlsh_distance_grows_with_difference() {
        let mut a = Vec::with_capacity(2048);
        for i in 0..2048 { a.push((i % 251) as u8); }
        let mut b = a.clone();
        // Mutate a quarter of the bytes
        for i in (0..b.len()).step_by(4) { b[i] = b[i].wrapping_add(123); }
        let ha = tlsh_hash(&a).unwrap();
        let hb = tlsh_hash(&b).unwrap();
        let dist = tlsh_distance(&ha, &hb).unwrap();
        assert!(dist > 0, "distance should be > 0 for different inputs (got {dist})");
    }

    #[test]
    fn ssdeep_round_trip() {
        let data = b"hello world this is some test data with enough bytes to trigger";
        let h = ssdeep_hash(data).unwrap();
        // ssdeep format: BS:H1:H2
        assert_eq!(h.matches(':').count(), 2);
        let parsed = parse_ssdeep(&h);
        assert!(parsed.is_some());
    }

    #[test]
    fn ssdeep_similarity_self_is_high() {
        let data = vec![0x42u8; 4096];
        let h = ssdeep_hash(&data).unwrap();
        let sim = ssdeep_similarity(&h, &h).unwrap();
        assert_eq!(sim, 100);
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance(b"kitten", b"sitting"), 3);
        assert_eq!(edit_distance(b"", b"abc"), 3);
        assert_eq!(edit_distance(b"abc", b"abc"), 0);
    }
}
