// Build-time XML → bincode conversion of the signsrch corpus.
//
// Reads `data/signsrch.xml` (3.4 MB, 2,338 byte-pattern entries from
// Luigi Auriemma's signsrch tool, GPL-2-or-later — see
// `data/signsrch.LICENSE.md`) and emits a serialized `Vec<SignsrchSig>`
// to `$OUT_DIR/signsrch.bin`. The runtime crate `include_bytes!`-s
// that blob and deserializes once into a `OnceLock<Vec<SignsrchSig>>`.
//
// The schema below MUST stay binary-compatible with the runtime
// `SignsrchSig` defined in `src/actions/signsrch_corpus.rs`. bincode
// v1 encodes positionally — same field order & types is what matters.

use std::env;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SignsrchSig {
    /// Full original `<p t>` name (e.g. "AES Rijndael Alogtable").
    name: String,
    /// Best-effort algorithm family (paren-stripped, leading word).
    algorithm: String,
    /// Coarse classification: 0=Other, 1=AntiDebug, 2=EllipticCurve,
    /// 3=Compression, 4=Hash, 5=Cipher, 6=Crc, 7=FileFormat.
    category: u8,
    /// 0 = raw byte table, 16/32/64 = integer chunks of that width.
    /// `float`→32, `double`→64 only when `multi_chunk` is set (the
    /// only context where the original signsrch.py rebinds them).
    bits: u8,
    /// 0 = unspecified/raw, 1 = little-endian, 2 = big-endian.
    endian: u8,
    /// Byte length declared in the XML suffix (`size` field).
    size: u32,
    /// True when the entry has the `&` flag — pattern is split into
    /// `bits/8`-byte chunks, each must appear in order with arbitrary
    /// gaps. ~136 of 2,338 entries.
    multi_chunk: bool,
    /// Decoded pattern bytes.
    bytes: Vec<u8>,
}

fn main() {
    println!("cargo:rerun-if-changed=data/signsrch.xml");
    println!("cargo:rerun-if-changed=build.rs");

    let xml_path = Path::new("data/signsrch.xml");
    let xml = match fs::read_to_string(xml_path) {
        Ok(s) => s,
        Err(e) => {
            // Allow the tree to build even if the corpus was deliberately
            // stripped (e.g. for a GPL-clean redistribution). We emit an
            // empty blob; the runtime falls back to the curated 22-sig
            // catalog.
            eprintln!("signsrch build: cannot read {}: {} — emitting empty corpus",
                xml_path.display(), e);
            write_blob(&Vec::<SignsrchSig>::new());
            return;
        }
    };

    // Each entry is one <p t="...">HEX</p> per line. Greedy match on
    // hex content; attribute is between the first pair of double quotes.
    let entry_re = regex::Regex::new(r#"<p t="([^"]+)">([0-9A-Fa-f]+)</p>"#)
        .expect("compile entry regex");

    let mut sigs: Vec<SignsrchSig> = Vec::new();
    let mut skipped = 0usize;

    for cap in entry_re.captures_iter(&xml) {
        let attr = cap.get(1).unwrap().as_str();
        let hex = cap.get(2).unwrap().as_str();

        // Split off the trailing " [bits.endian.size]" suffix. Some
        // names contain `[…]` themselves (e.g.
        // "AAC escAssignment[MAX_ELEMENTS][NR_OF_ASSIGNMENT_SCHEMES]"),
        // so we anchor on " [" with a leading space and take the LAST
        // occurrence.
        let (name, bracket) = match attr.rsplit_once(" [") {
            Some((n, b)) => (n.trim().to_string(), b.trim_end_matches(']').to_string()),
            None => { skipped += 1; continue; }
        };
        let bracket = bracket.replace("&amp;", "&");

        // Suffix grammar (always 3 dot-separated tokens):
        //   bits . endian-with-optional-rev . size[&]
        // Examples:
        //   ""    "le"   "1024"      → raw stream LE, 1024 bytes
        //   "32"  "le"   "1024"      → 32-bit LE chunks, 1024 bytes
        //   "32"  "le rev" "1024"    → 32-bit LE chunks, byte-reversed
        //   ""    ""     "256"       → raw bytes, no endian
        //   "32"  "le"   "32&"       → multi-chunk
        //   "float" "le" "56&"       → float multi-chunk → bits=32
        let parts: Vec<&str> = bracket.split('.').collect();
        if parts.len() < 3 { skipped += 1; continue; }
        let bits_str = parts[0].trim();
        let endian_str = parts[1].trim();
        let size_str = parts[parts.len() - 1].trim();

        let multi_chunk = size_str.ends_with('&');
        let size_str = size_str.trim_end_matches('&');
        let size: u32 = size_str.parse().unwrap_or(0);

        let bits: u8 = match bits_str {
            "" => 0,
            "float"  => if multi_chunk { 32 } else { 0 },
            "double" => if multi_chunk { 64 } else { 0 },
            other    => other.parse().unwrap_or(0),
        };

        // endian token may carry "rev" after a space — take the first
        // word for canonical le/be detection. The "rev" flag is implicit
        // in the byte ordering of the data and is NOT applied as an
        // additional reversal at runtime (signsrch.xml stores rev
        // variants verbatim in their already-reversed form).
        let endian: u8 = match endian_str.split_whitespace().next().unwrap_or("") {
            "le" => 1,
            "be" => 2,
            _    => 0,
        };

        let bytes = match decode_hex(hex) {
            Some(b) => b,
            None => { skipped += 1; continue; }
        };

        // Multi-chunk patterns whose advertised bits is 0 (raw) or where
        // bits/8 doesn't divide the byte length cleanly are degenerate;
        // we still keep them as single-chunk entries (multi_chunk=false)
        // because the chunk-walk would otherwise fail or behave like a
        // byte-by-byte scan.
        let usable_multi = multi_chunk && bits >= 8 && (bits as usize) % 8 == 0
            && !bytes.is_empty() && bytes.len() % ((bits as usize) / 8) == 0;

        let category = classify(&name);
        let algorithm = extract_algorithm(&name);

        sigs.push(SignsrchSig {
            name,
            algorithm,
            category,
            bits,
            endian,
            size,
            multi_chunk: usable_multi,
            bytes,
        });
    }

    // Verify the canonical entry count. We don't *fail* the build on
    // mismatch (the corpus might have been swapped out intentionally),
    // but we surface it so it shows up in `cargo build` output.
    if sigs.len() < 2200 {
        println!("cargo:warning=signsrch corpus: only {} entries parsed (expected ~2,338, skipped {})",
            sigs.len(), skipped);
    } else {
        eprintln!("signsrch build: {} entries parsed (skipped {})", sigs.len(), skipped);
    }

    write_blob(&sigs);
}

fn write_blob(sigs: &[SignsrchSig]) {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join("signsrch.bin");
    let encoded = bincode::serialize(sigs).expect("bincode serialize");
    fs::write(&out_path, &encoded).expect("write signsrch.bin");
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn extract_algorithm(name: &str) -> String {
    // Strip trailing parenthetical variant info: "Adler CRC32 (0x191b3141)"
    // → "Adler CRC32". Leave dual-name entries intact ("AES Rijndael S /
    //  ARIA S1") — downstream consumers can split on " / " if they care.
    name.split('(').next().unwrap_or(name).trim().to_string()
}

fn classify(name: &str) -> u8 {
    let lower = name.to_ascii_lowercase();

    if lower.starts_with("anti-debug:") || lower.starts_with("antidebug") {
        return 1;
    }
    if lower.starts_with("ec curve") || lower.starts_with("ec_") || lower.contains("nist_prime") {
        return 2;
    }

    const COMPRESSION: &[&str] = &[
        "zlib", "deflate", "lzma", "lz4", "lzo ", " lzo", "lzo_", "huffman", "brotli",
        "zstd", "paq", "lzfse", "lzss", "lzw", "lz77", "lz78", "bzip", "rangecoder",
        "snappy", "xpress", "libzling", "lzham", "lzx", "lzfind", "matchidx",
        "rolz", "lzp", "lzbench",
    ];
    if COMPRESSION.iter().any(|w| lower.contains(w)) {
        return 3;
    }

    const HASH: &[&str] = &[
        "sha-", "sha1", "sha2", "sha3", "sha256", "sha384", "sha512", "sha512", "sha224",
        "md5", "md4", "md2", "ripemd", "whirlpool", "tiger", "haval", "snefru", "blake",
        "keccak", "siphash", "panama", "fnv",
    ];
    if HASH.iter().any(|w| lower.contains(w)) {
        return 4;
    }

    const CIPHER: &[&str] = &[
        "aes", "rijndael", " des", "3des", "blowfish", "twofish", "serpent",
        "rc2", "rc4", "rc5", "rc6", "tea ", "xtea", "xxtea", "idea", "gost",
        " seed", "cast", "aria", "anubis", "camellia", "kasumi", "skipjack",
        "salsa", "chacha", "khazad", "shacal", "noekeon", "mars", "loki",
        "feal", "frog", "magenta", "safer",
    ];
    if CIPHER.iter().any(|w| lower.contains(w)) {
        return 5;
    }

    if lower.contains("crc") || lower.contains("adler") {
        return 6;
    }

    7  // FileFormat / generic
}
