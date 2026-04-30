use crate::types::{Graph, EntityKind};

// ── Overlay Detection ──────────────────────────────────────────────
//
// "Overlay" = data appended past the official end of a PE/ELF/Mach-O
// binary. Common indicator of:
//
//   - NSIS / Inno Setup installers (Nullsoft / Jordan Russell formats
//     ship their payload as an appended blob)
//   - PyInstaller / py2exe bootloaders (the embedded Python archive)
//   - Self-extracting archives
//   - Authenticode signing certificates (PKCS#7 in cert directory —
//     this is *normal* trailing data on signed binaries)
//   - Malware payloads (XORed shellcode, second-stage downloaders)
//
// We detect it format-aware (so we don't false-positive on certs)
// and classify the trailing-data shape via signature bytes + entropy.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayKind {
    NsisInstaller,
    InnoSetup,
    PyInstaller,
    Py2exe,
    SelfExtract,
    AuthenticodeSig,
    HighEntropyBlob,
    Generic,
}

impl OverlayKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverlayKind::NsisInstaller    => "nsis_installer",
            OverlayKind::InnoSetup        => "inno_setup",
            OverlayKind::PyInstaller      => "pyinstaller",
            OverlayKind::Py2exe           => "py2exe",
            OverlayKind::SelfExtract      => "self_extract",
            OverlayKind::AuthenticodeSig  => "authenticode_sig",
            OverlayKind::HighEntropyBlob  => "high_entropy_blob",
            OverlayKind::Generic          => "generic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OverlayInfo {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub kind: OverlayKind,
}

/// Detect overlay in a PE binary. PE end is determined by
/// (raw_offset + raw_size) of the last section + cert directory size.
pub fn detect_pe_overlay(data: &[u8]) -> Option<OverlayInfo> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = coff + 20;

    // Read magic to know PE32 vs PE32+ (cert table offset differs)
    if opt_off + 2 > data.len() { return None; }
    let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_pe32_plus = opt_magic == 0x20b;

    // Cert table is data directory entry index 4
    // PE32:    opt_off + 96 + 4*8
    // PE32+:   opt_off + 112 + 4*8
    let cert_dd_off = if is_pe32_plus { opt_off + 112 + 4 * 8 } else { opt_off + 96 + 4 * 8 };
    let mut cert_end: u64 = 0;
    let mut cert_offset: u64 = 0;
    let mut cert_size: u64 = 0;
    if cert_dd_off + 8 <= data.len() {
        cert_offset = u32::from_le_bytes([data[cert_dd_off], data[cert_dd_off + 1], data[cert_dd_off + 2], data[cert_dd_off + 3]]) as u64;
        cert_size = u32::from_le_bytes([data[cert_dd_off + 4], data[cert_dd_off + 5], data[cert_dd_off + 6], data[cert_dd_off + 7]]) as u64;
        if cert_offset > 0 { cert_end = cert_offset + cert_size; }
    }

    // Walk section table to find max raw end
    let sec_table = coff + 20 + opt_size;
    let mut max_raw_end: u64 = 0;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { break; }
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as u64;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64;
        let end = raw_off + raw_size;
        if end > max_raw_end { max_raw_end = end; }
    }

    let pe_end = max_raw_end.max(cert_end);
    let file_len = data.len() as u64;

    // Authenticode signature is a "legitimate" overlay — flag it as such.
    if cert_offset > 0 && cert_size > 0 && file_len <= cert_end + 16 {
        // Trailing data is just the signature
        return Some(OverlayInfo {
            offset: cert_offset,
            size: cert_size,
            entropy: shannon_entropy(&data[cert_offset as usize..(cert_offset + cert_size) as usize]),
            kind: OverlayKind::AuthenticodeSig,
        });
    }

    if file_len <= pe_end || file_len - pe_end < 16 { return None; }

    let overlay_off = pe_end as usize;
    let overlay_data = &data[overlay_off..];
    let entropy = shannon_entropy(overlay_data);
    let kind = classify_overlay(overlay_data, entropy);

    Some(OverlayInfo {
        offset: pe_end,
        size: file_len - pe_end,
        entropy,
        kind,
    })
}

/// ELF overlay: bytes past max(section.offset + section.size).
pub fn detect_elf_overlay(data: &[u8]) -> Option<OverlayInfo> {
    if data.len() < 64 || &data[..4] != b"\x7FELF" { return None; }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let read_u32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if little_endian { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let read_u64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if little_endian { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if little_endian { u16::from_le_bytes([data[off], data[off+1]]) }
        else { u16::from_be_bytes([data[off], data[off+1]]) }
    };

    let (e_shoff, e_shentsize, e_shnum) = if is_64 {
        (read_u64(0x28), read_u16(0x3a) as u64, read_u16(0x3c) as u64)
    } else {
        (read_u32(0x20) as u64, read_u16(0x2e) as u64, read_u16(0x30) as u64)
    };
    let (e_phoff, e_phentsize, e_phnum) = if is_64 {
        (read_u64(0x20), read_u16(0x36) as u64, read_u16(0x38) as u64)
    } else {
        (read_u32(0x1c) as u64, read_u16(0x2a) as u64, read_u16(0x2c) as u64)
    };

    let mut max_end: u64 = 0;
    // Walk section headers
    if e_shoff > 0 && e_shentsize > 0 {
        for i in 0..e_shnum.min(256) {
            let hdr = (e_shoff + i * e_shentsize) as usize;
            if hdr + 64 > data.len() { break; }
            let (sh_offset, sh_size) = if is_64 {
                (read_u64(hdr + 0x18), read_u64(hdr + 0x20))
            } else {
                (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64)
            };
            let end = sh_offset + sh_size;
            if end > max_end { max_end = end; }
        }
    }
    // Also program headers (segment data can exceed sections in stripped binaries)
    if e_phoff > 0 && e_phentsize > 0 {
        for i in 0..e_phnum.min(64) {
            let hdr = (e_phoff + i * e_phentsize) as usize;
            if hdr + 56 > data.len() { break; }
            let (p_offset, p_filesz) = if is_64 {
                (read_u64(hdr + 0x08), read_u64(hdr + 0x20))
            } else {
                (read_u32(hdr + 0x04) as u64, read_u32(hdr + 0x10) as u64)
            };
            let end = p_offset + p_filesz;
            if end > max_end { max_end = end; }
        }
    }
    // Also section header table itself
    if e_shoff > 0 && e_shentsize > 0 && e_shnum > 0 {
        let sht_end = e_shoff + e_shnum * e_shentsize;
        if sht_end > max_end { max_end = sht_end; }
    }

    let file_len = data.len() as u64;
    if file_len <= max_end || file_len - max_end < 16 { return None; }
    let overlay_off = max_end as usize;
    let overlay_data = &data[overlay_off..];
    let entropy = shannon_entropy(overlay_data);
    let kind = classify_overlay(overlay_data, entropy);
    Some(OverlayInfo { offset: max_end, size: file_len - max_end, entropy, kind })
}

/// Classify overlay bytes by signature + entropy.
fn classify_overlay(data: &[u8], entropy: f64) -> OverlayKind {
    if data.len() >= 8 {
        // NSIS: starts with a signature 0xEFBEADDE or "NullsoftInst"
        if &data[..4] == b"\xef\xbe\xad\xde" || data.windows(12).any(|w| w == b"NullsoftInst") {
            return OverlayKind::NsisInstaller;
        }
        // Inno Setup: "Inno Setup" or "ldr64.exe" or "rdr.exe"
        if data.windows(10).any(|w| w == b"Inno Setup") {
            return OverlayKind::InnoSetup;
        }
        // PyInstaller: "MEI" magic or "_MEIPASS" or "PyZ" embedded
        if data.windows(4).any(|w| w == b"MEI\x0c") || data.windows(8).any(|w| w == b"_MEIPASS") {
            return OverlayKind::PyInstaller;
        }
        // py2exe: "py2exe" or "PYZ\x00"
        if data.windows(6).any(|w| w == b"py2exe") || data.windows(4).any(|w| w == b"PYZ\x00") {
            return OverlayKind::Py2exe;
        }
        // ZIP/JAR: 'PK\x03\x04'
        if &data[..4] == b"PK\x03\x04" {
            return OverlayKind::SelfExtract;
        }
        // 7z: '7z\xbc\xaf\x27\x1c'
        if data.len() >= 6 && &data[..6] == b"7z\xbc\xaf\x27\x1c" {
            return OverlayKind::SelfExtract;
        }
    }
    if entropy > 7.5 { OverlayKind::HighEntropyBlob } else { OverlayKind::Generic }
}

/// Shannon entropy in bits/byte. 0 = constant, 8 = perfectly random.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Public action: codemap overlay-info <binary>
pub fn overlay_info(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap overlay-info <binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let (overlay, format) = if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        (detect_elf_overlay(&data), "elf")
    } else if data.len() >= 2 && &data[..2] == b"MZ" {
        (detect_pe_overlay(&data), "pe")
    } else {
        return format!("Unsupported binary format for overlay detection (file: {target})");
    };

    match overlay {
        None => format!("=== Overlay Analysis: {target} ===\nFormat:  {format}\nResult:  no overlay detected (clean binary)"),
        Some(info) => {
            // Register Overlay node + binary→overlay edge
            let bin_id = if format == "elf" { format!("elf:{target}") } else { format!("pe:{target}") };
            let bin_kind = if format == "elf" { EntityKind::ElfBinary } else { EntityKind::PeBinary };
            graph.ensure_typed_node(&bin_id, bin_kind, &[("path", target)]);
            let overlay_id = format!("overlay:{target}:{:x}", info.offset);
            let size_str = info.size.to_string();
            let entropy_str = format!("{:.3}", info.entropy);
            let off_str = format!("{:#x}", info.offset);
            graph.ensure_typed_node(&overlay_id, EntityKind::Overlay, &[
                ("source_binary", target),
                ("offset", &off_str),
                ("size", &size_str),
                ("entropy", &entropy_str),
                ("kind", info.kind.as_str()),
            ]);
            graph.add_edge(&bin_id, &overlay_id);

            let mut lines = vec![
                format!("=== Overlay Analysis: {target} ==="),
                format!("Format:  {format}"),
                format!("Offset:  {:#x} ({} bytes from EOF)", info.offset, info.size),
                format!("Size:    {} bytes", info.size),
                format!("Entropy: {:.3} bits/byte (max 8.0)", info.entropy),
                format!("Kind:    {}", info.kind.as_str()),
            ];
            // Annotate what the kind means
            let note = match info.kind {
                OverlayKind::NsisInstaller   => "  → NSIS (Nullsoft) installer payload appended to bootloader",
                OverlayKind::InnoSetup       => "  → Inno Setup installer — payload below",
                OverlayKind::PyInstaller     => "  → PyInstaller frozen Python — embedded module archive",
                OverlayKind::Py2exe          => "  → py2exe frozen Python",
                OverlayKind::SelfExtract     => "  → ZIP/7z self-extracting archive (run with archive viewer)",
                OverlayKind::AuthenticodeSig => "  → benign — Authenticode (PKCS#7) digital signature",
                OverlayKind::HighEntropyBlob => "  → high-entropy data (likely encrypted/packed/encoded)",
                OverlayKind::Generic         => "  → unrecognized trailing data",
            };
            lines.push(note.to_string());
            lines.join("\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_known_values() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0x42; 100]), 0.0); // constant = 0
        // perfectly uniform 256-byte alphabet → 8.0 bits/byte
        let uniform: Vec<u8> = (0u16..256).map(|x| x as u8).collect();
        let h = shannon_entropy(&uniform);
        assert!((h - 8.0).abs() < 1e-9);
    }

    #[test]
    fn classify_pkzip_signature() {
        let data = b"PK\x03\x04rest of zip body";
        assert_eq!(classify_overlay(data, 5.0), OverlayKind::SelfExtract);
    }

    #[test]
    fn classify_high_entropy() {
        let data = vec![0u8; 100];
        assert_eq!(classify_overlay(&data, 7.8), OverlayKind::HighEntropyBlob);
    }

    #[test]
    fn classify_low_entropy_unknown() {
        let data = b"plain text trailing";
        assert_eq!(classify_overlay(data, 4.5), OverlayKind::Generic);
    }
}
