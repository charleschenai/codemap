use crate::types::{Graph, EntityKind};

// ── PE Rich Header + TLS Callbacks + Entry Point ───────────────────
//
// Three small PE additions that round out 5.12.x without needing
// disassembly:
//
//   - Rich header: undocumented Microsoft toolchain fingerprint
//     embedded between the DOS stub and PE signature. Records which
//     specific MSVC versions (cl.exe / link.exe / masm) produced
//     each object file. Solves "which exact toolchain built this?"
//
//   - TLS callbacks: TLS_DIRECTORY callback addresses are functions
//     run BEFORE main() — common malware persistence vector. Even
//     without disassembling, knowing a binary HAS callbacks is a
//     red flag worth surfacing.
//
//   - Entry-point analysis: AddressOfEntryPoint from the optional
//     header → identifies the OEP (original entry point) location.
//     Sets attrs["entry_rva"] on the binary node.

#[derive(Debug, Clone)]
pub struct RichEntry {
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

impl RichEntry {
    pub fn product_name(&self) -> &'static str {
        // Rich header product IDs - well-known mapping (subset of common ones)
        // Full list maintained by the community; we cover the prevalent ones.
        match self.product_id {
            0x0000 => "Imported (linker import)",
            0x0001 => "Imported (linker)",
            0x0002 => "Linker (LNK500)",
            0x0006 => "VS97 SP3 cvtres",
            0x000A => "VS98 cvtres",
            0x000B => "VS98 link",
            0x000C => "VS98 cl",
            0x000F => "VC2.0 utc",
            0x0015 => "VS6 cl",
            0x0016 => "VS6 link",
            0x0019 => "VC6 export",
            0x001C => "VS2002 (.NET) cl",
            0x005C => "VS2002 link",
            0x005D => "VS2003 link",
            0x005E => "VS2003 cl",
            0x005F => "VS2005 link",
            0x0060 => "VS2005 cl",
            0x0078 => "VS2008 link",
            0x0083 => "VS2008 cl",
            0x009A => "VS2010 link",
            0x009B => "VS2010 cl",
            0x00AA => "VS2012 link",
            0x00AB => "VS2012 cl",
            0x00CC => "VS2013 link",
            0x00CD => "VS2013 cl",
            0x00DE => "VS2015 link",
            0x00FF => "VS2015 cl",
            0x0100 => "VS2017 link",
            0x0101 => "VS2017 cl",
            0x0102 => "VS2017 cvtres",
            0x0103 => "VS2017 export",
            0x0104 => "VS2019 link",
            0x0105 => "VS2019 cl",
            0x0106 => "VS2022 link",
            0x0107 => "VS2022 cl",
            _ => "(unknown)",
        }
    }
}

/// Parse the PE Rich header. Returns None if not present (only signed
/// MSVC-toolchain PE binaries have one — MinGW/Delphi/Go don't).
pub fn parse_rich_header(data: &[u8]) -> Option<Vec<RichEntry>> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew == 0 || e_lfanew >= data.len() { return None; }

    // Search the DOS stub region for "Rich" marker followed by XOR key
    // The header layout is: DanS (XOR'd) ... entries (XOR'd) Rich <key>
    let region = &data[..e_lfanew.min(0x400)];
    let rich_off = match find_pattern(region, b"Rich") {
        Some(off) => off,
        None => return None,
    };
    if rich_off + 8 > region.len() { return None; }
    let key = u32::from_le_bytes([
        region[rich_off + 4], region[rich_off + 5],
        region[rich_off + 6], region[rich_off + 7],
    ]);

    // Walk backwards from "Rich" looking for "DanS" (key XOR "DanS")
    let dans_xored: [u8; 4] = [
        b'D' ^ (key as u8),
        b'a' ^ ((key >> 8) as u8),
        b'n' ^ ((key >> 16) as u8),
        b'S' ^ ((key >> 24) as u8),
    ];
    let dans_off = match find_pattern(&region[..rich_off], &dans_xored) {
        Some(off) => off,
        None => return None,
    };

    // Entries live between DanS+16 (skip 3 padding dwords after DanS)
    // and Rich. Each entry is 8 bytes XOR'd with key.
    let start = dans_off + 16;
    let end = rich_off;
    if end <= start || (end - start) % 8 != 0 { return None; }

    let mut entries = Vec::new();
    let mut off = start;
    while off + 8 <= end {
        let w0 = u32::from_le_bytes([region[off], region[off + 1], region[off + 2], region[off + 3]]) ^ key;
        let w1 = u32::from_le_bytes([region[off + 4], region[off + 5], region[off + 6], region[off + 7]]) ^ key;
        let product_id = (w0 >> 16) as u16;
        let build_number = (w0 & 0xFFFF) as u16;
        let count = w1;
        if product_id != 0 || build_number != 0 || count != 0 {
            entries.push(RichEntry { product_id, build_number, count });
        }
        off += 8;
    }
    if entries.is_empty() { None } else { Some(entries) }
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub callback_count: usize,
    pub callback_rvas: Vec<u64>,
    pub raw_data_start: u64,
    pub raw_data_end: u64,
}

/// Parse the TLS directory. Returns the callback list if any.
pub fn parse_tls_callbacks(data: &[u8]) -> Option<TlsInfo> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let opt_off = coff + 20;
    if opt_off + 2 > data.len() { return None; }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_pe32_plus = magic == 0x20b;

    // TLS data directory is index 9
    // PE32:    opt_off + 96 + 9*8
    // PE32+:   opt_off + 112 + 9*8
    let tls_dd_off = if is_pe32_plus { opt_off + 112 + 9 * 8 } else { opt_off + 96 + 9 * 8 };
    if tls_dd_off + 8 > data.len() { return None; }
    let tls_rva = u32::from_le_bytes([data[tls_dd_off], data[tls_dd_off + 1], data[tls_dd_off + 2], data[tls_dd_off + 3]]) as u64;
    let tls_size = u32::from_le_bytes([data[tls_dd_off + 4], data[tls_dd_off + 5], data[tls_dd_off + 6], data[tls_dd_off + 7]]) as u64;
    if tls_rva == 0 || tls_size == 0 { return None; }

    // Map RVA → file offset using section table
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;
    let tls_off = match rva_to_offset(data, sec_table, n_sections, tls_rva) {
        Some(o) => o,
        None => return None,
    };

    // TLS_DIRECTORY layout: StartAddressOfRawData, EndOfRawData,
    // AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics
    // PE32: 4-byte VAs; PE32+: 8-byte VAs
    let va_size = if is_pe32_plus { 8 } else { 4 };
    let read_va = |off: usize| -> Option<u64> {
        if off + va_size > data.len() { return None; }
        if is_pe32_plus {
            Some(u64::from_le_bytes(data[off..off + 8].try_into().ok()?))
        } else {
            Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as u64)
        }
    };

    let raw_data_start = read_va(tls_off)?;
    let raw_data_end = read_va(tls_off + va_size)?;
    let _addr_of_index = read_va(tls_off + 2 * va_size)?;
    let addr_of_callbacks = read_va(tls_off + 3 * va_size)?;

    // Callbacks live as a null-terminated array of VAs at addr_of_callbacks.
    // Convert callback VA → RVA → file offset.
    let image_base = read_image_base(data, opt_off, is_pe32_plus)?;
    if addr_of_callbacks == 0 || addr_of_callbacks <= image_base { return None; }
    let cb_rva = addr_of_callbacks - image_base;
    let cb_off = match rva_to_offset(data, sec_table, n_sections, cb_rva) {
        Some(o) => o,
        None => return None,
    };

    let mut callbacks = Vec::new();
    let mut p = cb_off;
    while p + va_size <= data.len() && callbacks.len() < 64 {
        let cb = if is_pe32_plus {
            u64::from_le_bytes(data[p..p + 8].try_into().ok()?)
        } else {
            u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as u64
        };
        if cb == 0 { break; }
        let cb_as_rva = if cb >= image_base { cb - image_base } else { cb };
        callbacks.push(cb_as_rva);
        p += va_size;
    }

    Some(TlsInfo {
        callback_count: callbacks.len(),
        callback_rvas: callbacks,
        raw_data_start,
        raw_data_end,
    })
}

/// Read the image base from the optional header.
fn read_image_base(data: &[u8], opt_off: usize, is_pe32_plus: bool) -> Option<u64> {
    if is_pe32_plus {
        let off = opt_off + 24;
        if off + 8 > data.len() { return None; }
        Some(u64::from_le_bytes(data[off..off + 8].try_into().ok()?))
    } else {
        let off = opt_off + 28;
        if off + 4 > data.len() { return None; }
        Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as u64)
    }
}

/// Read entry point RVA from the optional header.
pub fn read_entry_rva(data: &[u8]) -> Option<u32> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let opt_off = coff + 20;
    if opt_off + 20 > data.len() { return None; }
    Some(u32::from_le_bytes([data[opt_off + 16], data[opt_off + 17], data[opt_off + 18], data[opt_off + 19]]))
}

/// Map RVA → file offset by walking the section table.
fn rva_to_offset(data: &[u8], sec_table: usize, n_sections: usize, rva: u64) -> Option<usize> {
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { return None; }
        let virt_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as u64;
        let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64;
        if rva >= virt_addr && rva < virt_addr + virt_size {
            return Some((raw_off + (rva - virt_addr)) as usize);
        }
    }
    None
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── Public action: pe-meta ─────────────────────────────────────────

pub fn pe_meta(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap pe-meta <pe-binary>".to_string();
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

    let mut lines = vec![format!("=== PE Meta: {target} ===")];

    // ── Rich header ─────────────────────────────────────────────
    if let Some(entries) = parse_rich_header(&data) {
        lines.push(format!("\n── Rich header ({} entries) ──", entries.len()));
        let highest_msvc = entries.iter()
            .filter(|e| (0x009A..=0x0107).contains(&e.product_id) && e.product_id % 2 == 1)
            .max_by_key(|e| e.product_id);
        for e in entries.iter().take(20) {
            lines.push(format!("  pid={:#06x} build={:>5} count={:>4}  {}",
                e.product_id, e.build_number, e.count, e.product_name()));
        }
        if entries.len() > 20 {
            lines.push(format!("  ... and {} more", entries.len() - 20));
        }
        if let Some(latest) = highest_msvc {
            let summary = format!("MSVC {}", latest.product_name());
            if let Some(node) = graph.nodes.get_mut(&bin_id) {
                node.attrs.insert("rich_msvc".into(), summary.clone());
                node.attrs.insert("rich_entries".into(), entries.len().to_string());
            }
            lines.push(format!("\n  Toolchain summary: {summary}"));
        }

        // Promote each unique Rich-header product to a first-class Compiler
        // node so cross-binary queries like
        //   meta-path "compiler->pe"   (every binary built with VS2019 link)
        // work uniformly with lang_fp.rs's family-level Compiler nodes.
        // De-duplicated by product_name; build_number + count aggregated when
        // the same tool appears multiple times in the linkage manifest.
        use std::collections::BTreeMap;
        let mut by_name: BTreeMap<&'static str, (u16, u16, u32)> = BTreeMap::new();
        for e in &entries {
            let name = e.product_name();
            if name == "(unknown)" { continue; }
            let slot = by_name.entry(name).or_insert((e.product_id, e.build_number, 0));
            slot.2 += e.count;
            // keep highest build_number seen for this product
            if e.build_number > slot.1 { slot.1 = e.build_number; }
        }
        for (name, (pid, build, count)) in by_name {
            let comp_id = format!("compiler:{name}");
            let pid_str = format!("{pid:#06x}");
            let build_str = build.to_string();
            let count_str = count.to_string();
            graph.ensure_typed_node(&comp_id, EntityKind::Compiler, &[
                ("name", name),
                ("language", "c++"),
                ("toolchain", "msvc"),
                ("source", "rich_header"),
                ("product_id", &pid_str),
                ("build_number", &build_str),
                ("object_count", &count_str),
            ]);
            graph.add_edge(&bin_id, &comp_id);
        }
    } else {
        lines.push("\n── Rich header ──\n  (not present — non-MSVC toolchain or stripped)".to_string());
    }

    // ── TLS callbacks ───────────────────────────────────────────
    if let Some(tls) = parse_tls_callbacks(&data) {
        lines.push(format!("\n── TLS callbacks ({}) ──", tls.callback_count));
        for (i, rva) in tls.callback_rvas.iter().enumerate() {
            lines.push(format!("  [{:>2}] RVA = {:#010x}", i + 1, rva));
        }
        if let Some(node) = graph.nodes.get_mut(&bin_id) {
            node.attrs.insert("has_tls_callback".into(), "true".into());
            node.attrs.insert("tls_callback_count".into(), tls.callback_count.to_string());
        }
        // Promote each TLS callback to a first-class BinaryFunction node so
        // they participate in centrality / meta-path queries. The
        // `tls_callback=true` + `kind_detail=tls_persistence` attrs let
        // analysts filter for "every binary in this graph with TLS-callback
        // persistence" via attribute-filter without relying on a
        // text-output scan.
        for (i, rva) in tls.callback_rvas.iter().enumerate() {
            let func_id = format!("bin_func:pe:{target}::tls{i}");
            let rva_str = format!("{rva:#010x}");
            let name = format!("tls_callback_{i}");
            graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                ("name", &name),
                ("binary_format", "pe"),
                ("kind_detail", "tls_persistence"),
                ("rva", &rva_str),
                ("tls_callback", "true"),
            ]);
            graph.add_edge(&bin_id, &func_id);
        }
        if tls.callback_count > 0 {
            lines.push("\n  ⚠ TLS callbacks run BEFORE main() — common malware persistence vector".to_string());
        }
    } else {
        lines.push("\n── TLS callbacks ──\n  (none — clean binary on this axis)".to_string());
    }

    // ── Entry point ─────────────────────────────────────────────
    if let Some(rva) = read_entry_rva(&data) {
        lines.push(format!("\n── Entry point ──\n  AddressOfEntryPoint RVA = {:#010x}", rva));
        if let Some(node) = graph.nodes.get_mut(&bin_id) {
            node.attrs.insert("entry_rva".into(), format!("{rva:#010x}"));
        }
        // 5.19.0: also register the entry point as a first-class
        // BinaryFunction node, parity with ELF/Mach-O entry promotion
        // and the existing TLS-callback promotion above.
        let func_id = format!("bin_func:pe:{target}::entry");
        let rva_str = format!("{rva:#010x}");
        graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
            ("name", "entry_point"),
            ("binary_format", "pe"),
            ("kind_detail", "entry_point"),
            ("rva", &rva_str),
        ]);
        graph.add_edge(&bin_id, &func_id);
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_product_name_lookup() {
        let e = RichEntry { product_id: 0x0107, build_number: 1234, count: 5 };
        assert_eq!(e.product_name(), "VS2022 cl");
        let e = RichEntry { product_id: 0xFFFF, build_number: 0, count: 0 };
        assert_eq!(e.product_name(), "(unknown)");
    }

    #[test]
    fn rich_header_absent_on_non_pe() {
        assert!(parse_rich_header(b"not a pe at all").is_none());
        assert!(parse_rich_header(b"").is_none());
    }

    #[test]
    fn tls_callbacks_absent_on_non_pe() {
        assert!(parse_tls_callbacks(b"junk").is_none());
    }

    #[test]
    fn entry_rva_absent_on_non_pe() {
        assert!(read_entry_rva(b"junk").is_none());
    }
}
