// ── Section Entropy — Ship 5 #2 (clean-room port) ─────────────────
//
// Per-section Shannon byte entropy (`Σ −p·log₂(p)`). Sections at ≈8.0
// bits/byte are random-looking → packed / encrypted / compressed
// payloads (UPX, MPRESS, Themida, VMProtect; embedded encrypted
// resources; obfuscated data blobs).
//
// Independent of BB-CFG / propagator. Reads raw bytes only; pure
// static.
//
// Algorithm: textbook Shannon entropy of a 256-bin byte histogram
// (no GPL contamination — Shannon 1948). Cross-format wrapper that
// enumerates PE / ELF / Mach-O sections and attaches/updates an
// `entropy: f32` attribute on the existing `BinarySection` node
// (or registers one if missing). High-entropy sections additionally
// flag the parent binary node with `packed: true`.

use crate::types::{Graph, EntityKind};

const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

pub fn section_entropy(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap section-entropy <pe-or-elf-or-macho-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let (sections, format) = match enumerate_sections(&data) {
        Some(v) => v,
        None => return "Unsupported binary format (need PE / ELF / Mach-O)".to_string(),
    };

    if sections.is_empty() {
        return format!("=== Section Entropy: {target} ({format}) ===\n\nNo sections found.\n");
    }

    let bin_id = format!("{format}:{target}");
    let bin_kind = match format {
        "pe" => EntityKind::PeBinary,
        "elf" => EntityKind::ElfBinary,
        "macho" => EntityKind::MachoBinary,
        _ => EntityKind::PeBinary,
    };
    graph.ensure_typed_node(&bin_id, bin_kind, &[("path", target)]);

    let mut max_entropy = 0.0_f64;
    let mut high_entropy_count = 0usize;
    for sec in &sections {
        if sec.entropy > max_entropy { max_entropy = sec.entropy; }
        if sec.entropy > HIGH_ENTROPY_THRESHOLD { high_entropy_count += 1; }

        // Attach/refresh the BinarySection node (may already exist
        // from pe_sections / elf_info — ensure_typed_node merges attrs).
        let sec_id = format!("section:{}:{}::{}", format, target, sec.name);
        let entropy_str = format!("{:.3}", sec.entropy);
        let raw_size = sec.size.to_string();
        graph.ensure_typed_node(&sec_id, EntityKind::BinarySection, &[
            ("name", sec.name.as_str()),
            ("binary_format", format),
            ("raw_size", raw_size.as_str()),
            ("entropy", entropy_str.as_str()),
        ]);
        graph.add_edge(&bin_id, &sec_id);
    }

    if let Some(node) = graph.nodes.get_mut(&bin_id) {
        node.attrs.insert("max_section_entropy".into(), format!("{max_entropy:.3}"));
        if max_entropy > HIGH_ENTROPY_THRESHOLD {
            node.attrs.insert("packed".into(), "true".into());
        }
    }

    format_report(target, format, &sections, max_entropy, high_entropy_count)
}

#[derive(Debug, Clone)]
struct SectionEntropy {
    name: String,
    /// Raw size (bytes) measured for entropy.
    size: usize,
    entropy: f64,
}

/// Shannon byte entropy in bits/byte. 0.0 = constant; 8.0 = uniform random.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

fn enumerate_sections(data: &[u8]) -> Option<(Vec<SectionEntropy>, &'static str)> {
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        return Some((enumerate_elf(data), "elf"));
    }
    if data.len() >= 4 {
        let m = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(m, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA) {
            return Some((enumerate_macho(data), "macho"));
        }
    }
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        return Some((enumerate_pe(data), "pe"));
    }
    None
}

fn enumerate_pe(data: &[u8]) -> Vec<SectionEntropy> {
    let mut out = Vec::new();
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return out; }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;

    for i in 0..n_sections.min(96) {
        let off = sec_table + i * 40;
        if off + 40 > data.len() { break; }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name: String = name_bytes[..name_end].iter()
            .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
            .collect();
        if name.is_empty() { continue; }
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as usize;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
        let entropy = if raw_size == 0 || raw_off >= data.len() {
            0.0
        } else {
            let end = (raw_off + raw_size).min(data.len());
            shannon_entropy(&data[raw_off..end])
        };
        out.push(SectionEntropy { name, size: raw_size, entropy });
    }
    out
}

fn enumerate_elf(data: &[u8]) -> Vec<SectionEntropy> {
    let mut out = Vec::new();
    if data.len() < 64 { return out; }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let r32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if little_endian { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let r64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if little_endian { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let r16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if little_endian { u16::from_le_bytes([data[off], data[off+1]]) }
        else { u16::from_be_bytes([data[off], data[off+1]]) }
    };

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        (r64(0x28) as usize, r16(0x3a) as usize, r16(0x3c) as usize, r16(0x3e) as usize)
    } else {
        (r32(0x20) as usize, r16(0x2e) as usize, r16(0x30) as usize, r16(0x32) as usize)
    };
    if e_shoff == 0 || e_shentsize == 0 { return out; }

    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = if is_64 { r64(shstr_hdr + 0x18) as usize } else { r32(shstr_hdr + 0x10) as usize };

    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
        let name_idx = r32(hdr) as usize;
        let sh_type = r32(hdr + 4);
        let (offset, size) = if is_64 {
            (r64(hdr + 0x18), r64(hdr + 0x20))
        } else {
            (r32(hdr + 0x10) as u64, r32(hdr + 0x14) as u64)
        };
        if sh_type == 8 { continue; } // SHT_NOBITS — no bytes on disk
        if size == 0 { continue; }

        let mut name = String::new();
        if shstrtab_off + name_idx < data.len() {
            let mut end = shstrtab_off + name_idx;
            while end < data.len() && data[end] != 0 { end += 1; }
            name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
        }
        if name.is_empty() { continue; }

        let off = offset as usize;
        let sz = size as usize;
        let entropy = if off >= data.len() {
            0.0
        } else {
            let end = (off + sz).min(data.len());
            shannon_entropy(&data[off..end])
        };
        out.push(SectionEntropy { name, size: sz, entropy });
    }
    out
}

fn enumerate_macho(data: &[u8]) -> Vec<SectionEntropy> {
    if data.len() < 4 { return Vec::new(); }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Fat binary: pick the first arch slice.
    if matches!(magic, 0xCAFEBABE | 0xBEBAFECA) {
        if data.len() < 8 + 20 { return Vec::new(); }
        let off = u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let size = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as usize;
        if off + size > data.len() { return Vec::new(); }
        return enumerate_macho(&data[off..off + size]);
    }
    let (is_64, is_le) = match magic {
        0xFEEDFACE => (false, true),
        0xFEEDFACF => (true, true),
        0xCEFAEDFE => (false, false),
        0xCFFAEDFE => (true, false),
        _ => return Vec::new(),
    };
    let r32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if is_le { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let r64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if is_le { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size { return Vec::new(); }
    let ncmds = r32(16) as usize;

    let mut out = Vec::new();
    let mut offset = header_size;
    for _ in 0..ncmds {
        if offset + 8 > data.len() { break; }
        let cmd = r32(offset);
        let cmdsize = r32(offset + 4) as usize;
        if cmdsize == 0 || offset + cmdsize > data.len() { break; }
        // LC_SEGMENT (0x01) / LC_SEGMENT_64 (0x19)
        if cmd == 0x01 || cmd == 0x19 {
            let is_seg64 = cmd == 0x19;
            let sect_header_size: usize = if is_seg64 { 80 } else { 68 };
            let nsects_off: usize = if is_seg64 { 64 } else { 48 };
            let sect_start: usize = if is_seg64 { 72 } else { 56 };

            if offset + nsects_off + 4 <= data.len() {
                let nsects = r32(offset + nsects_off) as usize;
                let sec_base = offset + sect_start;
                for s in 0..nsects {
                    let soff = sec_base + s * sect_header_size;
                    if soff + sect_header_size > data.len() { break; }
                    let sectname_bytes = &data[soff..soff + 16];
                    let segname_bytes = &data[soff + 16..soff + 32];
                    let trim = |b: &[u8]| -> String {
                        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                        String::from_utf8_lossy(&b[..end]).to_string()
                    };
                    let sectname = trim(sectname_bytes);
                    let segname = trim(segname_bytes);
                    let (size, file_offset) = if is_seg64 {
                        let sz = r64(soff + 40);
                        let fo = r32(soff + 48) as u64;
                        (sz, fo)
                    } else {
                        let sz = r32(soff + 28) as u64;
                        let fo = r32(soff + 36) as u64;
                        (sz, fo)
                    };
                    if size == 0 { continue; }
                    let off_u = file_offset as usize;
                    let sz_u = size as usize;
                    let entropy = if off_u == 0 || off_u >= data.len() {
                        0.0
                    } else {
                        let end = (off_u + sz_u).min(data.len());
                        shannon_entropy(&data[off_u..end])
                    };
                    let qualified = if segname.is_empty() {
                        sectname
                    } else {
                        format!("{segname},{sectname}")
                    };
                    out.push(SectionEntropy { name: qualified, size: sz_u, entropy });
                }
            }
        }
        offset += cmdsize;
    }
    out
}

fn format_report(
    target: &str,
    format: &str,
    sections: &[SectionEntropy],
    max_entropy: f64,
    high_count: usize,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Section Entropy: {target} ({format}) ===\n\n"));
    out.push_str(&format!("Sections analyzed: {}\n", sections.len()));
    out.push_str(&format!("Max entropy:       {max_entropy:.3} bits/byte\n"));
    out.push_str(&format!("High-entropy (>{HIGH_ENTROPY_THRESHOLD:.1}): {high_count}\n"));
    out.push('\n');

    out.push_str("── Per-section entropy ──\n");
    for sec in sections {
        let marker = if sec.entropy > 7.5 { " 🚨 packed/encrypted" }
            else if sec.entropy > HIGH_ENTROPY_THRESHOLD { " ⚠ compressed/random" }
            else { "" };
        out.push_str(&format!(
            "  {:<24}  size={:>10}  H={:.3}{}\n",
            truncate(&sec.name, 24), sec.size, sec.entropy, marker,
        ));
    }
    out.push('\n');
    if high_count > 0 {
        out.push_str("Binary tagged 'packed: true' (entropy > 7.0 bits/byte).\n");
        out.push_str("Try: codemap meta-path \"pe->section\"  (cross-binary section-entropy survey)\n");
    } else {
        out.push_str("No high-entropy sections detected.\n");
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let cut: String = s.chars().take(max - 1).collect();
    format!("{cut}…")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_constant_is_zero() {
        let data = vec![0x90u8; 4096]; // all NOPs
        let h = shannon_entropy(&data);
        assert!(h < 0.001, "expected ~0 for constant bytes, got {h}");
    }

    #[test]
    fn entropy_of_uniform_random_is_near_eight() {
        // Deterministic high-entropy stream: each byte appears 16 times,
        // 256 * 16 = 4096 bytes, perfectly uniform → exactly 8.0.
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.001, "expected exactly 8.0, got {h}");
    }

    #[test]
    fn entropy_of_two_value_balanced_is_one_bit() {
        // Half 0x00, half 0xFF → exactly 1.0 bit/byte.
        let mut data = vec![0u8; 1024];
        for i in 0..512 { data[i] = 0xFF; }
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 0.001, "expected exactly 1.0, got {h}");
    }

    #[test]
    fn empty_input_returns_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn enumerate_unsupported_magic_returns_none() {
        let data = b"this is not a binary";
        assert!(enumerate_sections(data).is_none());
    }

    #[test]
    fn pe_synthetic_entropy_buckets() {
        // Tiny synthetic PE-like header with two sections: a low-entropy
        // .text and a high-entropy .data. Entropy figures matter; section
        // walking just has to find them.
        let mut pe = vec![0u8; 0x400];
        pe[0] = b'M'; pe[1] = b'Z';
        let e_lfanew = 0x80usize;
        pe[0x3c] = e_lfanew as u8;
        pe[0x3d] = (e_lfanew >> 8) as u8;
        pe[e_lfanew] = b'P';
        pe[e_lfanew + 1] = b'E';
        pe[e_lfanew + 2] = 0;
        pe[e_lfanew + 3] = 0;
        // COFF: NumberOfSections at coff+2, SizeOfOptionalHeader at coff+16
        let coff = e_lfanew + 4;
        pe[coff + 2] = 2; // 2 sections
        pe[coff + 3] = 0;
        let opt_size = 0u16;
        pe[coff + 16] = opt_size as u8;
        pe[coff + 17] = (opt_size >> 8) as u8;
        let sec_table = coff + 20 + opt_size as usize;
        // Two sections, each 0x80 bytes raw.
        // Section 0 = ".text", raw_off = 0x180, raw_size = 0x80, all NOPs (low H).
        // Section 1 = ".rsrc", raw_off = 0x200, raw_size = 0x100, uniform random (high H).
        let s0 = sec_table;
        let name0 = b".text\0\0\0";
        pe[s0..s0 + 8].copy_from_slice(name0);
        // raw_size at +16, raw_off at +20
        pe[s0 + 16..s0 + 20].copy_from_slice(&0x80u32.to_le_bytes());
        pe[s0 + 20..s0 + 24].copy_from_slice(&0x180u32.to_le_bytes());
        let s1 = sec_table + 40;
        let name1 = b".rsrc\0\0\0";
        pe[s1..s1 + 8].copy_from_slice(name1);
        pe[s1 + 16..s1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        pe[s1 + 20..s1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // Fill .text region with 0x90 (NOP) — low H.
        for i in 0..0x80 { pe[0x180 + i] = 0x90; }
        // Fill .rsrc with uniform-256 → exactly 8.0.
        for i in 0..0x100 { pe[0x200 + i] = i as u8; }

        let secs = enumerate_pe(&pe);
        assert_eq!(secs.len(), 2);
        let text = secs.iter().find(|s| s.name == ".text").expect("text");
        let rsrc = secs.iter().find(|s| s.name == ".rsrc").expect("rsrc");
        assert!(text.entropy < 0.5, "text entropy {} should be ~0", text.entropy);
        assert!((rsrc.entropy - 8.0).abs() < 0.001, "rsrc entropy {} should be ~8", rsrc.entropy);
    }
}
