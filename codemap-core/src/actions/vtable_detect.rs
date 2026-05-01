// ── VTable / RTTI Detector — Ship 4 #19 (heuristic v1) ─────────────
//
// Recovers C++ virtual function tables from compiled binaries by
// scanning data sections for runs of N consecutive pointer-sized
// values whose targets all land at function entries inside `.text`.
// Pure structural pattern — doesn't parse Itanium ABI typeinfo or
// MSVC COL (Complete Object Locator) metadata for v1; that's the
// next ship's worth of work.
//
// What v1 does:
//   1. Re-uses Ship 1 #7's SectionMap to enumerate every readable
//      data section (.rodata / .data.rel.ro / .data / .rdata).
//   2. Slides an 8-byte (or 4-byte for 32-bit) window across each
//      section. A "candidate vtable run" = ≥ 2 consecutive values
//      that all map to known function entry points.
//   3. Each candidate becomes a `VTable` graph node attached to the
//      binary, with edges to each virtual method.
//
// Honest limitations (v1 → v2):
//   - **No RTTI parsing.** The 16-byte header before each Itanium
//     vtable (`offset_to_top` + `typeinfo_ptr`) is ignored. v2 will
//     follow `typeinfo_ptr` to extract the class name string.
//   - **No MSVC vtable layout** — MSVC binaries use a different
//     layout (COL pointer instead of typeinfo). They'll partially
//     work because the function-pointer run pattern still matches,
//     but class names won't be recovered.
//   - **False positives possible** on:
//     - .init_array / .fini_array (constructor/destructor arrays
//       look like vtables — emit but with 'init_array' tag).
//     - PLT/GOT — function-pointer-to-stub patterns.
//     - Fat-binary export tables.
//   - **No multi-inheritance virtual base detection** — multi-VBR
//     vtables have 3-pointer headers and the run heuristic might
//     split them.

use crate::types::{Graph, EntityKind};
use crate::disasm::disasm_binary;
use std::collections::HashSet;

const MIN_VIRTUAL_METHODS: usize = 2;
const MAX_VTABLES_PER_BINARY: usize = 5_000;

pub fn vtable_detect(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap vtable-detect <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let result = match disasm_binary(&data) {
        Ok(r) => r,
        Err(e) => return format!("Disasm failed: {e}"),
    };

    // Build a fast set of known function entry VAs
    let func_entries: HashSet<u64> = result.functions.iter()
        .map(|f| f.address)
        .collect();
    let func_count = func_entries.len();

    let pointer_size = if result.bitness == 64 { 8 } else { 4 };

    // We need section ranges to scan. disasm_binary doesn't return
    // them; recompute from PE / ELF headers (cheap, ~10 ms).
    let regions = enumerate_data_regions(&data, &result);

    let mut tables: Vec<VTableCandidate> = Vec::new();
    for region in &regions {
        scan_region(&data, region, pointer_size, &func_entries, &mut tables);
    }
    // Filter to genuine candidates and sort by size (most-virtual first)
    tables.retain(|t| t.virtual_count >= MIN_VIRTUAL_METHODS);
    tables.sort_by(|a, b| b.virtual_count.cmp(&a.virtual_count));
    tables.truncate(MAX_VTABLES_PER_BINARY);

    register_into_graph(graph, target, &tables, &result.format);
    format_report(target, func_count, &regions, &tables)
}

#[derive(Debug, Clone)]
struct DataRegion {
    name: String,
    va_start: u64,
    file_start: usize,
    size: usize,
}

#[derive(Debug, Clone)]
struct VTableCandidate {
    /// VA of the first function pointer in the run.
    va_start: u64,
    /// Section name where the vtable was found.
    section: String,
    /// Number of consecutive function-pointer slots.
    virtual_count: usize,
    /// First method's VA (the destructor, in Itanium ABI).
    first_method_va: u64,
    /// Last method's VA — informative only.
    last_method_va: u64,
    /// All method VAs in order (capped at 64 for graph attrs).
    methods: Vec<u64>,
}

/// Collect data section ranges to scan. PE: walk the section table for
/// non-executable, readable sections that aren't `.text` / `.idata` /
/// `.reloc` / `.pdata` / `.xdata` (those produce too many false
/// positives without specialised handling). ELF: read section
/// headers and pick `.rodata`, `.data.rel.ro`, `.data`, plus any
/// `.init_array` / `.fini_array` (tagged separately).
fn enumerate_data_regions(data: &[u8], r: &crate::disasm::DisasmResult) -> Vec<DataRegion> {
    let mut out = Vec::new();
    if r.format == "pe" {
        if data.len() < 0x40 || &data[..2] != b"MZ" { return out; }
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        let coff = e_lfanew + 4;
        if coff + 20 > data.len() { return out; }
        let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
        let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        let sec_table = coff + 20 + opt_size;
        for i in 0..n_sections {
            let off = sec_table + i * 40;
            if off + 40 > data.len() { break; }
            let raw_name = &data[off..off + 8];
            let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..end]).to_string();
            let virt_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as u64;
            let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
            let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as u64;
            let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64 as usize;
            let chars = u32::from_le_bytes([data[off + 36], data[off + 37], data[off + 38], data[off + 39]]);
            let executable = (chars & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE
            if executable { continue; }
            if matches!(name.as_str(), ".idata" | ".reloc" | ".pdata" | ".xdata") { continue; }
            let mapped = virt_size.min(raw_size) as usize;
            if mapped < 16 { continue; }
            out.push(DataRegion {
                name,
                va_start: r.image_base + virt_addr,
                file_start: raw_off,
                size: mapped,
            });
        }
    } else if r.format == "elf" {
        if data.len() < 64 || &data[..4] != b"\x7FELF" { return out; }
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

        let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
            (read_u64(0x28) as usize, read_u16(0x3a) as usize, read_u16(0x3c) as usize, read_u16(0x3e) as usize)
        } else {
            (read_u32(0x20) as usize, read_u16(0x2e) as usize, read_u16(0x30) as usize, read_u16(0x32) as usize)
        };
        if e_shoff == 0 || e_shentsize == 0 { return out; }

        let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
        let shstrtab_off = if is_64 { read_u64(shstr_hdr + 0x18) as usize } else { read_u32(shstr_hdr + 0x10) as usize };

        for i in 0..e_shnum {
            let hdr = e_shoff + i * e_shentsize;
            if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
            let name_idx = read_u32(hdr) as usize;
            let sh_type = read_u32(hdr + 4);
            let sh_flags = if is_64 { read_u64(hdr + 8) } else { read_u32(hdr + 8) as u64 };
            let (offset, size, addr) = if is_64 {
                (read_u64(hdr + 0x18), read_u64(hdr + 0x20), read_u64(hdr + 0x10))
            } else {
                (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64, read_u32(hdr + 0x0c) as u64)
            };
            if sh_type == 8 { continue; } // SHT_NOBITS
            // Skip executable sections (sh_flags & SHF_EXECINSTR=4)
            if (sh_flags & 4) != 0 { continue; }
            // Skip non-allocated sections (sh_flags & SHF_ALLOC=2)
            if (sh_flags & 2) == 0 { continue; }

            // Read section name
            let mut name = String::new();
            if shstrtab_off + name_idx < data.len() {
                let mut end = shstrtab_off + name_idx;
                while end < data.len() && data[end] != 0 { end += 1; }
                name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
            }
            // Skip noisy sections
            if matches!(name.as_str(), ".plt" | ".plt.got" | ".got" | ".got.plt"
                | ".eh_frame" | ".eh_frame_hdr" | ".dynsym" | ".dynstr"
                | ".symtab" | ".strtab" | ".shstrtab" | ".gnu.hash"
                | ".gnu.version" | ".gnu.version_r" | ".dynamic")
            {
                continue;
            }
            if size < 16 { continue; }
            out.push(DataRegion {
                name,
                va_start: addr,
                file_start: offset as usize,
                size: size as usize,
            });
        }
    }
    out
}

fn scan_region(
    data: &[u8],
    region: &DataRegion,
    pointer_size: usize,
    func_entries: &HashSet<u64>,
    out: &mut Vec<VTableCandidate>,
) {
    if region.size < pointer_size * MIN_VIRTUAL_METHODS { return; }
    let end = (region.file_start + region.size).min(data.len());
    let bytes = &data[region.file_start..end];

    // Sliding window: for each pointer-aligned offset, count how many
    // consecutive pointers from there land at function entries.
    let mut i = 0usize;
    while i + pointer_size <= bytes.len() {
        // Read pointer at i
        let val = read_pointer(bytes, i, pointer_size);
        if val == 0 || !func_entries.contains(&val) {
            i += pointer_size;
            continue;
        }
        // Found the start of a candidate. Count how many consecutive
        // pointers are also function entries.
        let mut count = 0usize;
        let mut methods: Vec<u64> = Vec::new();
        let mut last_va = 0u64;
        let mut j = i;
        while j + pointer_size <= bytes.len() {
            let v = read_pointer(bytes, j, pointer_size);
            if v == 0 || !func_entries.contains(&v) { break; }
            count += 1;
            last_va = v;
            if methods.len() < 64 { methods.push(v); }
            j += pointer_size;
        }
        if count >= MIN_VIRTUAL_METHODS {
            let va_start = region.va_start + i as u64;
            let first_method_va = read_pointer(bytes, i, pointer_size);
            out.push(VTableCandidate {
                va_start,
                section: region.name.clone(),
                virtual_count: count,
                first_method_va,
                last_method_va: last_va,
                methods,
            });
        }
        // Skip past the run we just consumed to avoid emitting
        // overlapping candidates from offset i+pointer_size etc.
        i = j;
    }
}

fn read_pointer(bytes: &[u8], off: usize, size: usize) -> u64 {
    match size {
        8 => {
            if off + 8 > bytes.len() { return 0; }
            u64::from_le_bytes(bytes[off..off+8].try_into().unwrap_or([0u8;8]))
        }
        4 => {
            if off + 4 > bytes.len() { return 0; }
            u32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]) as u64
        }
        _ => 0,
    }
}

fn confidence_for(count: usize, section: &str) -> &'static str {
    // .init_array / .fini_array always look like vtables; mark low.
    if section.contains("init_array") || section.contains("fini_array") {
        return "low";
    }
    if count >= 4 { "high" }
    else if count >= 2 { "medium" }
    else { "low" }
}

fn register_into_graph(
    graph: &mut Graph,
    target: &str,
    tables: &[VTableCandidate],
    format: &str,
) {
    if tables.is_empty() { return; }
    let bin_id = if format == "pe" {
        format!("pe:{target}")
    } else {
        format!("elf:{target}")
    };
    let kind = if format == "pe" { EntityKind::PeBinary } else { EntityKind::ElfBinary };
    graph.ensure_typed_node(&bin_id, kind, &[("path", target)]);

    for t in tables {
        let vt_id = format!("vtable:{target}::{:#x}", t.va_start);
        let conf = confidence_for(t.virtual_count, &t.section);
        let va_str = format!("{:#x}", t.va_start);
        let count_str = t.virtual_count.to_string();
        let first_str = format!("{:#x}", t.first_method_va);
        graph.ensure_typed_node(&vt_id, EntityKind::VTable, &[
            ("vtable_address", va_str.as_str()),
            ("section", t.section.as_str()),
            ("virtual_count", count_str.as_str()),
            ("first_method", first_str.as_str()),
            ("confidence", conf),
        ]);
        graph.add_edge(&bin_id, &vt_id);

        // Edge: vtable → each virtual method (function entry)
        for m in &t.methods {
            let func_id = format!("bin_func:{target}::{m:#x}");
            if graph.nodes.contains_key(&func_id) {
                graph.add_edge(&vt_id, &func_id);
            }
        }
    }
}

fn format_report(
    target: &str,
    func_count: usize,
    regions: &[DataRegion],
    tables: &[VTableCandidate],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== VTable Detection: {} ===\n\n", target));
    out.push_str(&format!("Functions known:       {}\n", func_count));
    out.push_str(&format!("Data regions scanned:  {}\n", regions.len()));
    out.push_str(&format!("VTables detected:      {}\n", tables.len()));
    out.push('\n');

    if tables.is_empty() {
        out.push_str("No vtable candidates found.\n");
        out.push_str("(Heuristic v1: requires ≥ 2 consecutive function-entry pointers in\n");
        out.push_str(" .rodata / .data.rel.ro / similar. Stripped binaries hit fewer\n");
        out.push_str(" function entries → fewer matches.)\n");
        return out;
    }

    // Group by confidence
    use std::collections::BTreeMap;
    let mut by_conf: BTreeMap<&str, Vec<&VTableCandidate>> = BTreeMap::new();
    for t in tables {
        let c = confidence_for(t.virtual_count, &t.section);
        by_conf.entry(c).or_default().push(t);
    }
    let high = by_conf.get("high").map(|v| v.len()).unwrap_or(0);
    let medium = by_conf.get("medium").map(|v| v.len()).unwrap_or(0);
    let low = by_conf.get("low").map(|v| v.len()).unwrap_or(0);
    out.push_str(&format!("Confidence: high={high} medium={medium} low={low}\n\n"));

    let n_show = 30;
    let mut shown = 0usize;
    for conf in ["high", "medium", "low"] {
        let group = by_conf.get(conf);
        let group = match group { Some(g) => g, None => continue };
        if group.is_empty() { continue; }
        out.push_str(&format!("── {} confidence ({}) ──\n", conf, group.len()));
        for t in group {
            if shown >= n_show {
                out.push_str(&format!("  ... and {} more\n", group.len()));
                break;
            }
            out.push_str(&format!(
                "  {:#012x}  vmethods={:>3}  in {:<20} first={:#x}\n",
                t.va_start, t.virtual_count,
                truncate(&t.section, 20),
                t.first_method_va,
            ));
            shown += 1;
        }
    }
    out.push('\n');
    out.push_str("Try: codemap pagerank --type vtable      (most-shared vtables)\n");
    out.push_str("     codemap meta-path \"vtable->bin_func\" (virtual methods per class)\n");
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
    fn confidence_levels() {
        assert_eq!(confidence_for(1, ".rodata"), "low");
        assert_eq!(confidence_for(2, ".rodata"), "medium");
        assert_eq!(confidence_for(3, ".rodata"), "medium");
        assert_eq!(confidence_for(4, ".rodata"), "high");
        assert_eq!(confidence_for(20, ".rodata"), "high");
        // init_array always low — it's not a real vtable
        assert_eq!(confidence_for(10, ".init_array"), "low");
        assert_eq!(confidence_for(10, ".fini_array"), "low");
    }

    #[test]
    fn read_pointer_64bit_le() {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_pointer(&bytes, 0, 8), 0x0000_0000_1234_5678);
    }

    #[test]
    fn read_pointer_32bit_le() {
        let bytes = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_pointer(&bytes, 0, 4), 0x1234_5678);
    }

    #[test]
    fn scan_region_finds_consecutive_function_pointers() {
        // Build a fake data region containing 5 consecutive 8-byte
        // function-entry pointers, then a non-function value, then
        // another 3 pointers (separate vtable).
        let mut data = vec![0u8; 0x100];
        // Region starts at file_offset 0, va 0x1000.
        // Run 1 at offset 0: 5 pointers to 0x2000..0x2004
        for i in 0..5 {
            let v = 0x2000u64 + i as u64;
            data[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        // Gap at offset 40: a non-function pointer (0xDEAD)
        data[40..48].copy_from_slice(&0xDEADu64.to_le_bytes());
        // Run 2 at offset 48: 3 pointers
        for i in 0..3 {
            let v = 0x2010u64 + i as u64;
            data[48 + i * 8..48 + i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }

        let region = DataRegion {
            name: ".rodata".to_string(),
            va_start: 0x1000,
            file_start: 0,
            size: 0x100,
        };
        let func_entries: HashSet<u64> = (0x2000..0x2013).collect();
        let mut tables = Vec::new();
        scan_region(&data, &region, 8, &func_entries, &mut tables);
        // After filter: at least 2 candidates with virtual_count >= 2
        let real: Vec<_> = tables.iter().filter(|t| t.virtual_count >= MIN_VIRTUAL_METHODS).collect();
        assert_eq!(real.len(), 2, "expected 2 candidates, got {}: {:?}",
            real.len(), real.iter().map(|t| (t.va_start, t.virtual_count)).collect::<Vec<_>>());
        assert_eq!(real[0].virtual_count, 5);
        assert_eq!(real[0].va_start, 0x1000);
        assert_eq!(real[1].virtual_count, 3);
        assert_eq!(real[1].va_start, 0x1000 + 48);
    }

    #[test]
    fn scan_region_ignores_runs_below_minimum() {
        // Single function pointer should NOT be flagged
        let mut data = vec![0u8; 0x80];
        data[0..8].copy_from_slice(&0x2000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0xDEADu64.to_le_bytes()); // non-function, terminates run
        let region = DataRegion {
            name: ".rodata".to_string(),
            va_start: 0x1000,
            file_start: 0,
            size: 0x80,
        };
        let func_entries: HashSet<u64> = [0x2000].iter().copied().collect();
        let mut tables = Vec::new();
        scan_region(&data, &region, 8, &func_entries, &mut tables);
        let real: Vec<_> = tables.iter().filter(|t| t.virtual_count >= MIN_VIRTUAL_METHODS).collect();
        assert!(real.is_empty(), "single pointer should not flag");
    }

    #[test]
    fn empty_tables_yields_no_detection() {
        let regions: Vec<DataRegion> = vec![];
        let tables: Vec<VTableCandidate> = vec![];
        let report = format_report("/tmp/test.bin", 100, &regions, &tables);
        assert!(report.contains("No vtable candidates found"));
    }
}
