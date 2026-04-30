use std::path::Path;
use crate::types::{Graph, EntityKind};
use crate::fingerprint::{Fingerprint, fingerprint};

// ── lang-fingerprint action ─────────────────────────────────────────
//
// Standalone CLI action: `codemap lang-fingerprint <file>` reads a
// binary, runs the fingerprint heuristics, registers the result as
// attrs on the binary node + creates a Compiler node with a
// binary→compiler edge. Idempotent (ensure_typed_node + add_edge are
// idempotent).

pub fn lang_fingerprint(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap lang-fingerprint <binary-path>".to_string();
    }
    let path = Path::new(target);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 64 {
        return format!("File too small to fingerprint: {} bytes", data.len());
    }

    // Scan the whole file (capped at 64 MB to keep memory bounded on
    // pathological inputs). Rust/Go signatures often live in .rodata
    // which can sit several MB into a stripped binary, so a small
    // window misses them. memchr-style substring search is fast — the
    // 16 needles we test add up to a few ms even on a 30 MB binary.
    let scan_window = &data[..data.len().min(64 * 1024 * 1024)];

    // Section names — read by sniffing the format. We keep this
    // intentionally lightweight; the existing pe/elf/macho actions
    // do the proper section parse if a richer view is needed.
    let sections = sniff_section_names(&data);
    let section_refs: Vec<&str> = sections.iter().map(|s| s.as_str()).collect();

    let fp = fingerprint(&section_refs, scan_window);
    let kind = sniff_binary_kind(&data);

    // Register binary node (if not already)
    let bin_id = match kind {
        Some(EntityKind::PeBinary) => format!("pe:{target}"),
        Some(EntityKind::ElfBinary) => format!("elf:{target}"),
        Some(EntityKind::MachoBinary) => format!("macho:{target}"),
        Some(EntityKind::WasmModule) => format!("wasm:{target}"),
        Some(EntityKind::JavaClass) => format!("jclass:{target}"),
        _ => format!("bin:{target}"),
    };
    if let Some(k) = kind {
        graph.ensure_typed_node(&bin_id, k, &[("path", target)]);
    }

    // Apply fingerprint attrs to the binary node + register Compiler
    // node with binary→compiler edge.
    if let Some(node) = graph.nodes.get_mut(&bin_id) {
        if let Some(l) = &fp.language { node.attrs.insert("language".into(), l.clone()); }
        if let Some(c) = &fp.compiler { node.attrs.insert("compiler".into(), c.clone()); }
        if let Some(r) = &fp.runtime  { node.attrs.insert("runtime".into(), r.clone()); }
        if fp.confidence > 0 { node.attrs.insert("fingerprint_confidence".into(), fp.confidence.to_string()); }
    }
    if let Some(c) = &fp.compiler {
        let comp_id = format!("compiler:{c}");
        let lang = fp.language.clone().unwrap_or_else(|| "unknown".to_string());
        let mut attrs: Vec<(&str, &str)> = vec![
            ("name", c.as_str()),
            ("language", lang.as_str()),
        ];
        if let Some(r) = &fp.runtime { attrs.push(("runtime", r.as_str())); }
        graph.ensure_typed_node(&comp_id, EntityKind::Compiler, &attrs);
        graph.add_edge(&bin_id, &comp_id);
    }

    format_report(target, &fp, kind)
}

fn format_report(target: &str, fp: &Fingerprint, kind: Option<EntityKind>) -> String {
    let mut lines = vec![
        format!("=== Language Fingerprint: {} ===", target),
        format!("Format:     {}", kind.map(|k| k.as_str()).unwrap_or("unknown")),
    ];
    if !fp.is_known() {
        lines.push("Result:     no signatures matched (likely C/C++ stripped or exotic)".to_string());
        return lines.join("\n");
    }
    if let Some(l) = &fp.language { lines.push(format!("Language:   {l}")); }
    if let Some(c) = &fp.compiler { lines.push(format!("Compiler:   {c}")); }
    if let Some(r) = &fp.runtime  { lines.push(format!("Runtime:    {r}")); }
    lines.push(format!("Confidence: {}/100", fp.confidence));
    lines.join("\n")
}

/// Best-effort format detection from magic bytes.
fn sniff_binary_kind(data: &[u8]) -> Option<EntityKind> {
    if data.len() < 4 { return None; }
    // ELF: 0x7F 'E' 'L' 'F'
    if &data[..4] == b"\x7FELF" { return Some(EntityKind::ElfBinary); }
    // PE: starts with MZ, e_lfanew points to "PE\0\0"
    if &data[..2] == b"MZ" {
        if data.len() >= 0x40 {
            let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                return Some(EntityKind::PeBinary);
            }
        }
    }
    // Mach-O: 0xFEEDFACE / 0xFEEDFACF / 0xCAFEBABE (fat)
    let mag = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let magl = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if mag == 0xFEEDFACE || mag == 0xFEEDFACF || mag == 0xCAFEBABE
        || magl == 0xFEEDFACE || magl == 0xFEEDFACF { return Some(EntityKind::MachoBinary); }
    // WASM
    if &data[..4] == b"\0asm" { return Some(EntityKind::WasmModule); }
    // Java .class
    if mag == 0xCAFEBABE && data.len() >= 8 {
        // Java class major version >= 45; CAFEBABE+real version distinguishes from Mach-O fat
        let minor = u16::from_be_bytes([data[4], data[5]]);
        let major = u16::from_be_bytes([data[6], data[7]]);
        if major >= 45 && minor < 100 { return Some(EntityKind::JavaClass); }
    }
    None
}

/// Cheap section-name extraction. PE: walks section table. ELF: walks
/// section header table + shstrtab. Mach-O: walks LC_SEGMENT load
/// commands. Returns up to ~50 names; bails out cleanly on malformed.
fn sniff_section_names(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if data.len() < 4 { return out; }

    // ── PE ─────────────────────────────────────────────────────────
    if data.len() > 0x40 && &data[..2] == b"MZ" {
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if e_lfanew + 24 < data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            let coff = e_lfanew + 4;
            let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
            let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
            let sec_table = coff + 20 + opt_size;
            for i in 0..n_sections.min(50) {
                let off = sec_table + i * 40;
                if off + 8 > data.len() { break; }
                let name = String::from_utf8_lossy(&data[off..off + 8])
                    .trim_matches('\0').to_string();
                if !name.is_empty() { out.push(name); }
            }
            return out;
        }
    }

    // ── ELF ────────────────────────────────────────────────────────
    if &data[..4] == b"\x7FELF" && data.len() > 64 {
        let is_64 = data[4] == 2;
        let little_endian = data[5] == 1;
        let read_u32 = |off: usize| -> u32 {
            if off + 4 > data.len() { return 0; }
            if little_endian {
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            } else {
                u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            }
        };
        let read_u64 = |off: usize| -> u64 {
            if off + 8 > data.len() { return 0; }
            if little_endian {
                u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
            } else {
                u64::from_be_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
            }
        };
        let read_u16 = |off: usize| -> u16 {
            if off + 2 > data.len() { return 0; }
            if little_endian {
                u16::from_le_bytes([data[off], data[off + 1]])
            } else {
                u16::from_be_bytes([data[off], data[off + 1]])
            }
        };
        let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
            (read_u64(0x28) as usize, read_u16(0x3a) as usize, read_u16(0x3c) as usize, read_u16(0x3e) as usize)
        } else {
            (read_u32(0x20) as usize, read_u16(0x2e) as usize, read_u16(0x30) as usize, read_u16(0x32) as usize)
        };
        if e_shentsize == 0 || e_shnum == 0 || e_shoff == 0 { return out; }
        // Find shstrtab section
        let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
        let shstrtab_off = if is_64 {
            read_u64(shstr_hdr_off + 0x18) as usize
        } else {
            read_u32(shstr_hdr_off + 0x10) as usize
        };
        for i in 0..e_shnum.min(60) {
            let hdr = e_shoff + i * e_shentsize;
            if hdr + 4 > data.len() { break; }
            let name_off = read_u32(hdr) as usize;
            let abs = shstrtab_off + name_off;
            let mut end = abs;
            while end < data.len() && data[end] != 0 { end += 1; }
            if abs < data.len() && end > abs {
                let name = String::from_utf8_lossy(&data[abs..end]).to_string();
                if !name.is_empty() { out.push(name); }
            }
        }
        return out;
    }

    // ── Mach-O ─────────────────────────────────────────────────────
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic == 0xFEEDFACE || magic == 0xFEEDFACF {
        let is_64 = magic == 0xFEEDFACF;
        let header_size = if is_64 { 32 } else { 28 };
        if data.len() < header_size + 8 { return out; }
        let ncmds = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let mut off = header_size;
        for _ in 0..ncmds.min(50) {
            if off + 8 > data.len() { break; }
            let cmd = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let cmdsize = u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]) as usize;
            if cmdsize < 8 || off + cmdsize > data.len() { break; }
            // LC_SEGMENT (0x01) / LC_SEGMENT_64 (0x19) — read segname (16 bytes)
            if cmd == 0x01 || cmd == 0x19 {
                if off + 24 <= data.len() {
                    let name = String::from_utf8_lossy(&data[off + 8..off + 24])
                        .trim_matches('\0').to_string();
                    if !name.is_empty() { out.push(name); }
                }
            }
            off += cmdsize;
        }
    }
    out
}
