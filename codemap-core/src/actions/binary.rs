use std::fs;
use std::path::Path;
use crate::types::{Graph, EntityKind};

/// Heterogeneous-graph helper: register a binary node with the appropriate
/// kind. Idempotent — repeated calls only merge attrs.
fn register_binary(graph: &mut Graph, target: &str, kind: EntityKind, prefix: &str) {
    let id = format!("{prefix}:{target}");
    graph.ensure_typed_node(&id, kind, &[("path", target)]);
}

const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024; // 256 MB

// ── Helpers ────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read u32 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err(format!("Read u64 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]))
}

fn read_u16_be(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read u32 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u32::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]))
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < data.len() && data[i] != 0 {
        if data[i] >= 0x20 && data[i] <= 0x7E {
            s.push(data[i] as char);
        } else {
            break;
        }
        i += 1;
    }
    s
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn format_size(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn load_binary(target: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(target);
    if !path.exists() {
        return Err(format!("File not found: {target}"));
    }
    let meta = fs::metadata(path).map_err(|e| format!("Error: {e}"))?;
    if meta.len() > MAX_BINARY_SIZE {
        return Err(format!("File too large ({} bytes, max 256 MB)", meta.len()));
    }
    fs::read(path).map_err(|e| format!("Error reading file: {e}"))
}

/// Decode a LEB128 unsigned integer from `data` starting at `pos`.
/// Returns (value, bytes_consumed).
fn decode_leb128(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        if i >= data.len() {
            return Err(format!("LEB128 truncated at offset 0x{i:X}"));
        }
        let byte = data[i];
        result |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("LEB128 overflow".to_string());
        }
    }
    Ok((result, i - pos))
}

// ── 1. elf_info ────────────────────────────────────────────────────

pub fn elf_info(graph: &mut Graph, target: &str) -> String {
    register_binary(graph, target, EntityKind::ElfBinary, "elf");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    // 5.38.0: stamp os/os_source/language attrs on the ElfBinary node
    // so downstream actions (audit, pagerank --type elf, leiden) can
    // cluster by target OS without a separate elf-os pass. The cascade
    // is cheap (~ms) — same buffer we just loaded for elf_info.
    let bin_id = format!("elf:{target}");
    let guesses = crate::actions::elf_os::detect_elf_os_all(&data);
    if let Some(winner) = guesses.iter().max_by_key(|g| {
        // Same ranking the elf-os action uses; we duplicate here to
        // avoid importing a private helper. confidence() is implicit
        // through the heuristic ordering — pick the strongest fire.
        match g.source {
            crate::actions::elf_os::OsHeuristic::PhNote        => 10u8,
            crate::actions::elf_os::OsHeuristic::ShNote        => 9,
            crate::actions::elf_os::OsHeuristic::Linker        => 8,
            crate::actions::elf_os::OsHeuristic::GlibcVerneed  => 7,
            crate::actions::elf_os::OsHeuristic::NeededDep     => 7,
            crate::actions::elf_os::OsHeuristic::GoBuildinfo   => 6,
            crate::actions::elf_os::OsHeuristic::Symtab        => 5,
            crate::actions::elf_os::OsHeuristic::IdentComment  => 4,
            crate::actions::elf_os::OsHeuristic::OsabiByte     => 3,
        }
    }) {
        let os_str = winner.os.as_str();
        let src_str: &str = match winner.source {
            crate::actions::elf_os::OsHeuristic::PhNote        => "ph-note",
            crate::actions::elf_os::OsHeuristic::ShNote        => "sh-note",
            crate::actions::elf_os::OsHeuristic::Linker        => "linker",
            crate::actions::elf_os::OsHeuristic::GlibcVerneed  => "glibc-verneed",
            crate::actions::elf_os::OsHeuristic::NeededDep     => "needed-dep",
            crate::actions::elf_os::OsHeuristic::IdentComment  => "ident-comment",
            crate::actions::elf_os::OsHeuristic::Symtab        => "symtab",
            crate::actions::elf_os::OsHeuristic::GoBuildinfo   => "go-buildinfo",
            crate::actions::elf_os::OsHeuristic::OsabiByte     => "osabi-byte",
        };
        graph.ensure_typed_node(&bin_id, EntityKind::ElfBinary, &[
            ("os", os_str),
            ("os_source", src_str),
        ]);
    }
    if let Some(lang) = crate::actions::elf_os::detect_elf_language(&data) {
        graph.ensure_typed_node(&bin_id, EntityKind::ElfBinary, &[
            ("language", lang),
        ]);
    }
    match parse_elf_with_deps(&data) {
        Ok((info, needed, entry)) => {
            // Register every NEEDED library as a Dll node with edges from
            // the binary, mirroring pe-imports' PE → Dll structure. Lets
            // pagerank/meta-path see ELF library dependencies.
            let bin_id = format!("elf:{target}");
            for libname in &needed {
                let dll_id = format!("dll:{}", libname.to_ascii_lowercase());
                graph.ensure_typed_node(&dll_id, EntityKind::Dll, &[
                    ("name", libname),
                    ("source_format", "elf"),
                ]);
                graph.add_edge(&bin_id, &dll_id);
            }

            // 5.19.0: promote the ELF entry point (e_entry) to a
            // BinaryFunction node so it participates in centrality /
            // meta-path queries. Mirrors pe_meta.rs's TLS-callback
            // promotion: kind_detail=entry_point + entry_addr attr.
            // Most ELF binaries: entry → _start → __libc_start_main → main.
            if entry != 0 {
                let func_id = format!("bin_func:elf:{target}::entry");
                let entry_str = format!("{entry:#018x}");
                graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                    ("name", "entry_point"),
                    ("binary_format", "elf"),
                    ("kind_detail", "entry_point"),
                    ("entry_addr", &entry_str),
                ]);
                graph.add_edge(&bin_id, &func_id);
            }

            // Extract free-form strings from .rodata + .data and promote
            // each to a StringLiteral node (with classification). URL
            // strings additionally promote to HttpEndpoint via the
            // existing pipeline. Capped at 5000 strings per binary.
            let strings = crate::actions::reverse::common::extract_ascii_strings(&data, 6);
            crate::actions::reverse::common::promote_strings_to_graph(graph, target, "elf", &strings);

            info
        }
        Err(e) => format!("ELF parse error: {e}"),
    }
}

fn parse_elf_with_deps(data: &[u8]) -> Result<(String, Vec<String>, u64), String> {
    if data.len() < 64 {
        return Err("File too small for ELF".to_string());
    }
    // Check ELF magic: 0x7F 'E' 'L' 'F'
    if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err("Not an ELF file (missing magic)".to_string());
    }

    let class = data[4]; // 1=32-bit, 2=64-bit
    let endian = data[5]; // 1=little, 2=big
    let os_abi = data[7];

    let is_64 = class == 2;
    let is_le = endian == 1;

    // We only handle little-endian for now (the vast majority of modern binaries)
    let r16 = if is_le { read_u16_le } else { read_u16_be };
    let r32 = if is_le { read_u32_le } else { read_u32_be };

    let elf_type = r16(data, 16)?;
    let machine = r16(data, 18)?;

    let (entry, sh_off, sh_entsize, sh_num, sh_strndx, _ph_off, _ph_entsize, ph_num) = if is_64 {
        let entry = read_u64_le(data, 24)?;
        let ph_off = read_u64_le(data, 32)? as usize;
        let sh_off = read_u64_le(data, 40)? as usize;
        let ph_entsize = r16(data, 54)? as usize;
        let ph_num = r16(data, 56)? as usize;
        let sh_entsize = r16(data, 58)? as usize;
        let sh_num = r16(data, 60)? as usize;
        let sh_strndx = r16(data, 62)? as usize;
        (entry, sh_off, sh_entsize, sh_num, sh_strndx, ph_off, ph_entsize, ph_num)
    } else {
        let entry = r32(data, 24)? as u64;
        let ph_off = r32(data, 28)? as usize;
        let sh_off = r32(data, 32)? as usize;
        let ph_entsize = r16(data, 42)? as usize;
        let ph_num = r16(data, 44)? as usize;
        let sh_entsize = r16(data, 46)? as usize;
        let sh_num = r16(data, 48)? as usize;
        let sh_strndx = r16(data, 50)? as usize;
        (entry, sh_off, sh_entsize, sh_num, sh_strndx, ph_off, ph_entsize, ph_num)
    };

    let class_str = match class {
        1 => "ELF32",
        2 => "ELF64",
        _ => "Unknown",
    };
    let endian_str = match endian {
        1 => "Little",
        2 => "Big",
        _ => "Unknown",
    };
    let type_str = match elf_type {
        0 => "None",
        1 => "Relocatable",
        2 => "Executable",
        3 => "Shared Object (DLL)",
        4 => "Core Dump",
        _ => "Unknown",
    };
    let machine_str = match machine {
        0x02 => "SPARC",
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x28 => "ARM",
        0x2A => "SuperH",
        0x32 => "IA-64",
        0x3E => "x86_64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0xF7 => "BPF",
        _ => "Unknown",
    };
    let abi_str = match os_abi {
        0 => "UNIX System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "Unknown",
    };

    let mut out = String::new();
    out.push_str("=== ELF Analysis ===\n\n");
    out.push_str(&format!("Class:    {class_str}\n"));
    out.push_str(&format!("Endian:   {endian_str}\n"));
    out.push_str(&format!("OS/ABI:   {abi_str}\n"));
    out.push_str(&format!("Type:     {type_str}\n"));
    out.push_str(&format!("Machine:  {machine_str}\n"));
    out.push_str(&format!("Entry:    0x{entry:X}\n"));
    out.push_str(&format!("Sections: {sh_num}\n"));
    out.push_str(&format!("Segments: {ph_num}\n"));

    // ── Read section header string table ──
    let shstrtab_data = read_elf_section_data(data, sh_off, sh_entsize, sh_strndx, is_64, is_le)?;

    // ── Parse sections ──
    #[derive(Debug)]
    struct ElfSection {
        name: String,
        sh_type: u32,
        flags: u64,
        offset: u64,
        size: u64,
        link: u32,
    }

    let mut sections: Vec<ElfSection> = Vec::new();
    for i in 0..sh_num {
        let base = sh_off + i * sh_entsize;
        if base + sh_entsize > data.len() {
            break;
        }
        let name_idx = r32(data, base)? as usize;
        let sh_type = r32(data, base + 4)?;
        let (flags, offset, size, link) = if is_64 {
            let flags = read_u64_le(data, base + 8)?;
            let offset = read_u64_le(data, base + 24)?;
            let size = read_u64_le(data, base + 32)?;
            let link = r32(data, base + 40)?;
            (flags, offset, size, link)
        } else {
            let flags = r32(data, base + 8)? as u64;
            let offset = r32(data, base + 16)? as u64;
            let size = r32(data, base + 20)? as u64;
            let link = r32(data, base + 28)?;
            (flags, offset, size, link)
        };

        let name = if name_idx < shstrtab_data.len() {
            read_cstring(&shstrtab_data, name_idx)
        } else {
            String::new()
        };

        sections.push(ElfSection { name, sh_type, flags, offset, size, link });
    }

    // ── Display sections ──
    out.push_str("\n\u{2500}\u{2500} Sections \u{2500}\u{2500}\n");
    for sec in &sections {
        if sec.name.is_empty() {
            continue;
        }
        let mut flag_strs = Vec::new();
        if sec.flags & 0x1 != 0 { flag_strs.push("WRITE"); }
        if sec.flags & 0x2 != 0 { flag_strs.push("ALLOC"); }
        if sec.flags & 0x4 != 0 { flag_strs.push("EXEC"); }
        let flags_str = if flag_strs.is_empty() { String::new() } else { format!("  [{}]", flag_strs.join(", ")) };

        let entropy = if sec.size > 0 && (sec.offset as usize) < data.len() {
            let start = sec.offset as usize;
            let end = (start + sec.size as usize).min(data.len());
            if start < end { shannon_entropy(&data[start..end]) } else { 0.0 }
        } else {
            0.0
        };

        out.push_str(&format!(
            "  {:<14}Offset:0x{:<8X}  Size:{:<10}  Entropy:{:<6.2}{}\n",
            sec.name, sec.offset, format_size(sec.size), entropy, flags_str
        ));
    }

    // ── Dependencies (DT_NEEDED from .dynamic section) ──
    let mut needed: Vec<String> = Vec::new();
    if let Some(dynamic_sec) = sections.iter().find(|s| s.sh_type == 6) { // SHT_DYNAMIC = 6
        let dynstr_sec = sections.iter().find(|s| s.name == ".dynstr");
        if let Some(dynstr) = dynstr_sec {
            let dynstr_off = dynstr.offset as usize;
            let dynstr_size = dynstr.size as usize;
            if dynstr_off + dynstr_size <= data.len() {
                let dynstr_data = &data[dynstr_off..dynstr_off + dynstr_size];
                let dyn_off = dynamic_sec.offset as usize;
                let dyn_size = dynamic_sec.size as usize;
                let entry_size: usize = if is_64 { 16 } else { 8 };
                let count = dyn_size / entry_size;
                for i in 0..count {
                    let base = dyn_off + i * entry_size;
                    if base + entry_size > data.len() {
                        break;
                    }
                    let (tag, val) = if is_64 {
                        let t = read_u64_le(data, base).unwrap_or(0);
                        let v = read_u64_le(data, base + 8).unwrap_or(0);
                        (t, v)
                    } else {
                        let t = r32(data, base).unwrap_or(0) as u64;
                        let v = r32(data, base + 4).unwrap_or(0) as u64;
                        (t, v)
                    };
                    if tag == 0 { break; } // DT_NULL
                    if tag == 1 { // DT_NEEDED
                        let name_off = val as usize;
                        if name_off < dynstr_data.len() {
                            let name = read_cstring(dynstr_data, name_off);
                            if !name.is_empty() {
                                needed.push(name);
                            }
                        }
                    }
                }
            }
        }
    }

    if !needed.is_empty() {
        out.push_str(&"\n\u{2500}\u{2500} Dependencies (NEEDED) \u{2500}\u{2500}\n".to_string());
        for n in &needed {
            out.push_str(&format!("  {n}\n"));
        }
    }

    // ── Parse dynamic symbols (.dynsym + .dynstr) ──
    let mut exported: Vec<String> = Vec::new();
    let mut imported: Vec<String> = Vec::new();

    if let Some(dynsym_sec) = sections.iter().find(|s| s.name == ".dynsym" || s.sh_type == 11) {
        let strtab_sec = if (dynsym_sec.link as usize) < sections.len() {
            Some(&sections[dynsym_sec.link as usize])
        } else {
            sections.iter().find(|s| s.name == ".dynstr")
        };

        if let Some(strtab) = strtab_sec {
            let strtab_off = strtab.offset as usize;
            let strtab_size = strtab.size as usize;
            if strtab_off + strtab_size <= data.len() {
                let strtab_data = &data[strtab_off..strtab_off + strtab_size];
                let sym_off = dynsym_sec.offset as usize;
                let sym_entsize: usize = if is_64 { 24 } else { 16 };
                let sym_count = dynsym_sec.size as usize / sym_entsize;

                for i in 1..sym_count { // skip index 0 (undefined)
                    let base = sym_off + i * sym_entsize;
                    if base + sym_entsize > data.len() {
                        break;
                    }

                    let (st_name, st_info, st_shndx) = if is_64 {
                        let name = r32(data, base)? as usize;
                        let info = data[base + 4];
                        let shndx = r16(data, base + 6)?;
                        (name, info, shndx)
                    } else {
                        let name = r32(data, base)? as usize;
                        let info = data[base + 12];
                        let shndx = r16(data, base + 14)?;
                        (name, info, shndx)
                    };

                    let bind = st_info >> 4;
                    let sym_type = st_info & 0xF;

                    // Skip non-function/object symbols
                    if sym_type != 1 && sym_type != 2 { // STT_OBJECT=1, STT_FUNC=2
                        continue;
                    }

                    if st_name < strtab_data.len() {
                        let name = read_cstring(strtab_data, st_name);
                        if name.is_empty() {
                            continue;
                        }
                        if st_shndx == 0 { // SHN_UNDEF = imported
                            imported.push(name);
                        } else if bind == 1 || bind == 2 { // STB_GLOBAL=1, STB_WEAK=2
                            exported.push(name);
                        }
                    }
                }
            }
        }
    }

    if !exported.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Exported Symbols ({}) \u{2500}\u{2500}\n", exported.len()));
        for name in exported.iter().take(200) {
            if let Some(d) = crate::demangle::demangle(name) {
                out.push_str(&format!("  {d}\n     (mangled: {name})\n"));
            } else {
                out.push_str(&format!("  {name}\n"));
            }
        }
        if exported.len() > 200 {
            out.push_str(&format!("  ... and {} more\n", exported.len() - 200));
        }
    }

    if !imported.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Imported Symbols ({}) \u{2500}\u{2500}\n", imported.len()));
        for name in imported.iter().take(200) {
            if let Some(d) = crate::demangle::demangle(name) {
                out.push_str(&format!("  {d}\n     (mangled: {name})\n"));
            } else {
                out.push_str(&format!("  {name}\n"));
            }
        }
        if imported.len() > 200 {
            out.push_str(&format!("  ... and {} more\n", imported.len() - 200));
        }
    }

    Ok((out, needed, entry))
}

fn read_elf_section_data(
    data: &[u8], sh_off: usize, sh_entsize: usize, index: usize,
    is_64: bool, is_le: bool,
) -> Result<Vec<u8>, String> {
    let base = sh_off + index * sh_entsize;
    if base + sh_entsize > data.len() {
        return Err("Section header out of bounds".to_string());
    }
    let r32 = if is_le { read_u32_le } else { read_u32_be };
    let (offset, size) = if is_64 {
        let offset = read_u64_le(data, base + 24)? as usize;
        let size = read_u64_le(data, base + 32)? as usize;
        (offset, size)
    } else {
        let offset = r32(data, base + 16)? as usize;
        let size = r32(data, base + 20)? as usize;
        (offset, size)
    };
    if offset + size > data.len() {
        return Err("Section data out of bounds".to_string());
    }
    Ok(data[offset..offset + size].to_vec())
}

// ── 2. macho_info ──────────────────────────────────────────────────

pub fn macho_info(graph: &mut Graph, target: &str) -> String {
    register_binary(graph, target, EntityKind::MachoBinary, "macho");
    // Snapshot dylibs by parsing once before formatting; we use the
    // formatted string for display and the dylib list for graph
    // registration. The parser stuffs LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
    // names into a list during the load-command walk; we re-walk lightly
    // here to extract them for graphing without disturbing the
    // 1500-line existing macho parser.
    let data_for_dylibs = load_binary(target).unwrap_or_default();
    if !data_for_dylibs.is_empty() {
        let dylibs = extract_macho_dylibs(&data_for_dylibs).unwrap_or_default();
        let bin_id = format!("macho:{target}");
        for libname in &dylibs {
            let dll_id = format!("dll:{}", libname.to_ascii_lowercase());
            graph.ensure_typed_node(&dll_id, EntityKind::Dll, &[
                ("name", libname),
                ("source_format", "macho"),
            ]);
            graph.add_edge(&bin_id, &dll_id);
        }
        // 5.19.0: promote LC_MAIN entryoff to a BinaryFunction node so
        // Mach-O entry points participate in centrality / meta-path
        // queries the same way ELF/PE entry points do. Returns None for
        // older binaries using LC_UNIXTHREAD (rare on modern macOS).
        if let Some(entry) = extract_macho_entry(&data_for_dylibs) {
            let func_id = format!("bin_func:macho:{target}::entry");
            let entry_str = format!("{entry:#018x}");
            graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                ("name", "entry_point"),
                ("binary_format", "macho"),
                ("kind_detail", "entry_point"),
                ("entry_addr", &entry_str),
            ]);
            graph.add_edge(&bin_id, &func_id);
        }
    }

    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match parse_macho(&data) {
        Ok(info) => info,
        Err(e) => format!("Mach-O parse error: {e}"),
    }
}

/// Lightweight LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB
/// extractor for graph registration. Mirrors the inline parsing in
/// parse_macho_detail but skips all the formatting work — just returns
/// the dylib names. Handles single-arch and fat binaries (returns the
/// dylibs from the first contained arch in fat case).
fn extract_macho_dylibs(data: &[u8]) -> Result<Vec<String>, String> {
    if data.len() < 4 { return Ok(Vec::new()); }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (slice, is_64, is_le) = match magic {
        0xFEEDFACE => (data, false, true),     // 32-bit LE
        0xFEEDFACF => (data, true, true),      // 64-bit LE
        0xCEFAEDFE => (data, false, false),    // 32-bit BE
        0xCFFAEDFE => (data, true, false),     // 64-bit BE
        // Fat magic: pick first arch
        0xCAFEBABE | 0xBEBAFECA => {
            if data.len() < 8 { return Ok(Vec::new()); }
            let nfat = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
            if nfat == 0 || data.len() < 8 + 20 { return Ok(Vec::new()); }
            // Each fat_arch is 20 bytes: cputype, cpusubtype, offset, size, align
            let off = u32::from_be_bytes([data[8 + 8], data[8 + 9], data[8 + 10], data[8 + 11]]) as usize;
            let size = u32::from_be_bytes([data[8 + 12], data[8 + 13], data[8 + 14], data[8 + 15]]) as usize;
            if off + size > data.len() { return Ok(Vec::new()); }
            let inner = &data[off..off + size];
            return extract_macho_dylibs(inner);
        }
        _ => return Ok(Vec::new()),
    };
    let r32 = if is_le { read_u32_le } else { read_u32_be };
    let header_size = if is_64 { 32 } else { 28 };
    if slice.len() < header_size { return Ok(Vec::new()); }
    let ncmds = r32(slice, 16)? as usize;
    let mut offset = header_size;
    let mut dylibs = Vec::new();
    for _ in 0..ncmds {
        if offset + 8 > slice.len() { break; }
        let cmd = r32(slice, offset)?;
        let cmdsize = r32(slice, offset + 4)? as usize;
        if cmdsize == 0 { break; }
        // LC_LOAD_DYLIB (0x0C), LC_LOAD_WEAK_DYLIB (0x80000018), LC_REEXPORT_DYLIB (0x1F)
        if cmd == 0x0C || cmd == 0x1F || cmd == 0x80000018 {
            if offset + 12 <= slice.len() {
                let str_offset = r32(slice, offset + 8)? as usize;
                if str_offset < cmdsize && offset + str_offset < slice.len() {
                    let name = read_cstring(slice, offset + str_offset);
                    if !name.is_empty() {
                        dylibs.push(name);
                    }
                }
            }
        }
        offset += cmdsize;
    }
    Ok(dylibs)
}

/// Walk Mach-O load commands looking for LC_MAIN (0x80000028) and return
/// the file-relative entry offset (entryoff). Returns None for fat binaries
/// when the first arch has no LC_MAIN, or for older binaries that use
/// LC_UNIXTHREAD instead. Mirrors extract_macho_dylibs's walking pattern.
fn extract_macho_entry(data: &[u8]) -> Option<u64> {
    if data.len() < 4 { return None; }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (slice, is_64, is_le) = match magic {
        0xFEEDFACE => (data, false, true),
        0xFEEDFACF => (data, true, true),
        0xCEFAEDFE => (data, false, false),
        0xCFFAEDFE => (data, true, false),
        0xCAFEBABE | 0xBEBAFECA => {
            if data.len() < 8 + 20 { return None; }
            let off = u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as usize;
            let size = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as usize;
            if off + size > data.len() { return None; }
            return extract_macho_entry(&data[off..off + size]);
        }
        _ => return None,
    };
    let r32 = if is_le { read_u32_le } else { read_u32_be };
    let header_size = if is_64 { 32 } else { 28 };
    if slice.len() < header_size { return None; }
    let ncmds = r32(slice, 16).ok()? as usize;
    let mut offset = header_size;
    for _ in 0..ncmds {
        if offset + 8 > slice.len() { break; }
        let cmd = r32(slice, offset).ok()?;
        let cmdsize = r32(slice, offset + 4).ok()? as usize;
        if cmdsize == 0 { break; }
        // LC_MAIN: cmd=0x80000028, payload = u64 entryoff + u64 stacksize.
        if cmd == 0x80000028 && offset + 16 <= slice.len() {
            let entry = if is_le {
                read_u64_le(slice, offset + 8).ok()?
            } else {
                let bytes = &slice[offset + 8..offset + 16];
                let mut buf = [0u8; 8];
                buf.copy_from_slice(bytes);
                u64::from_be_bytes(buf)
            };
            return Some(entry);
        }
        offset += cmdsize;
    }
    None
}

fn parse_macho(data: &[u8]) -> Result<String, String> {
    if data.len() < 4 {
        return Err("File too small".to_string());
    }

    let magic = read_u32_le(data, 0)?;

    match magic {
        0xCAFEBABE | 0xBEBAFECA => parse_macho_fat(data),
        0xFEEDFACE => parse_macho_single(data, false, true),  // 32-bit LE
        0xCEFAEDFE => parse_macho_single(data, false, false), // 32-bit BE
        0xFEEDFACF => parse_macho_single(data, true, true),   // 64-bit LE
        0xCFFAEDFE => parse_macho_single(data, true, false),  // 64-bit BE
        _ => Err(format!("Not a Mach-O file (magic: 0x{magic:08X})")),
    }
}

fn parse_macho_fat(data: &[u8]) -> Result<String, String> {
    if data.len() < 8 {
        return Err("Truncated fat header".to_string());
    }

    // Fat headers are always big-endian
    let nfat = read_u32_be(data, 4)? as usize;

    let mut out = String::new();
    out.push_str("=== Mach-O Analysis (Universal/Fat Binary) ===\n\n");
    out.push_str(&format!("Architectures: {nfat}\n\n"));

    for i in 0..nfat {
        let base = 8 + i * 20;
        if base + 20 > data.len() {
            break;
        }
        let cpu_type = read_u32_be(data, base)?;
        let cpu_subtype = read_u32_be(data, base + 4)?;
        let offset = read_u32_be(data, base + 8)? as usize;
        let size = read_u32_be(data, base + 12)? as usize;

        let arch_name = macho_cpu_name(cpu_type, cpu_subtype);
        out.push_str(&format!("\u{2500}\u{2500} Slice {}: {} \u{2500}\u{2500}\n", i + 1, arch_name));
        out.push_str(&format!("  Offset: 0x{offset:X}  Size: {}\n", format_size(size as u64)));

        // Parse the individual slice
        if offset + size <= data.len() {
            let slice = &data[offset..offset + size];
            if slice.len() >= 4 {
                let slice_magic = read_u32_le(slice, 0)?;
                let (is_64, is_le) = match slice_magic {
                    0xFEEDFACE => (false, true),
                    0xCEFAEDFE => (false, false),
                    0xFEEDFACF => (true, true),
                    0xCFFAEDFE => (true, false),
                    _ => {
                        out.push_str("  (unrecognized slice format)\n\n");
                        continue;
                    }
                };
                match parse_macho_detail(slice, is_64, is_le) {
                    Ok(detail) => {
                        for line in detail.lines() {
                            out.push_str(&format!("  {line}\n"));
                        }
                    }
                    Err(e) => out.push_str(&format!("  Parse error: {e}\n")),
                }
            }
        }
        out.push('\n');
    }

    Ok(out)
}

fn parse_macho_single(data: &[u8], is_64: bool, is_le: bool) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("=== Mach-O Analysis ===\n\n");
    let detail = parse_macho_detail(data, is_64, is_le)?;
    out.push_str(&detail);
    Ok(out)
}

fn parse_macho_detail(data: &[u8], is_64: bool, is_le: bool) -> Result<String, String> {
    let header_size: usize = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return Err("Truncated Mach-O header".to_string());
    }

    let r32 = if is_le { read_u32_le } else { read_u32_be };

    let cpu_type = r32(data, 4)?;
    let cpu_subtype = r32(data, 8)?;
    let filetype = r32(data, 12)?;
    let ncmds = r32(data, 16)? as usize;
    let _sizeofcmds = r32(data, 20)? as usize;

    let arch_name = macho_cpu_name(cpu_type, cpu_subtype);
    let type_str = match filetype {
        1 => "Object",
        2 => "Executable",
        3 => "Fixed VM Shared Library",
        4 => "Core Dump",
        5 => "Preloaded Executable",
        6 => "Dynamic Library (dylib)",
        7 => "Dynamic Linker",
        8 => "Bundle",
        9 => "Dylib Stub",
        10 => "Debug Symbols (dSYM)",
        11 => "Kext",
        _ => "Unknown",
    };

    let mut out = String::new();
    out.push_str(&format!("Class:    {}\n", if is_64 { "64-bit" } else { "32-bit" }));
    out.push_str(&format!("Endian:   {}\n", if is_le { "Little" } else { "Big" }));
    out.push_str(&format!("CPU:      {arch_name}\n"));
    out.push_str(&format!("Type:     {type_str}\n"));
    out.push_str(&format!("Commands: {ncmds}\n"));

    // Parse load commands
    let mut offset = header_size;
    let mut dylibs: Vec<String> = Vec::new();
    let mut rpaths: Vec<String> = Vec::new();
    let mut uuid_str: Option<String> = None;
    let mut id_dylib: Option<String> = None;

    struct MachoSection {
        sectname: String,
        segname: String,
        size: u64,
        offset: u64,
    }
    let mut macho_sections: Vec<MachoSection> = Vec::new();

    // Symbol table info
    let mut symtab_off: usize = 0;
    let mut symtab_count: usize = 0;
    let mut strtab_off: usize = 0;
    let mut strtab_size: usize = 0;
    // Dynamic symbol table for classifying imports/exports
    let mut dysymtab_iextdef: usize = 0;
    let mut dysymtab_nextdef: usize = 0;
    let mut dysymtab_iundef: usize = 0;
    let mut dysymtab_nundef: usize = 0;
    let mut has_dysymtab = false;

    for _ in 0..ncmds {
        if offset + 8 > data.len() {
            break;
        }
        let cmd = r32(data, offset)?;
        let cmdsize = r32(data, offset + 4)? as usize;
        if cmdsize < 8 || offset + cmdsize > data.len() {
            break;
        }

        match cmd {
            // LC_SEGMENT (0x01) / LC_SEGMENT_64 (0x19)
            0x01 | 0x19 => {
                let is_seg64 = cmd == 0x19;
                let sect_header_size: usize = if is_seg64 { 80 } else { 68 };
                let nsects_off: usize = if is_seg64 { 64 } else { 48 };
                let sect_start: usize = if is_seg64 { 72 } else { 56 };

                if offset + nsects_off + 4 <= data.len() {
                    let nsects = r32(data, offset + nsects_off)? as usize;
                    let sec_base = offset + sect_start;

                    for s in 0..nsects {
                        let soff = sec_base + s * sect_header_size;
                        if soff + sect_header_size > data.len() {
                            break;
                        }
                        let sectname = read_fixed_string(data, soff, 16);
                        let segname = read_fixed_string(data, soff + 16, 16);
                        let (size, file_offset) = if is_seg64 {
                            let sz = read_u64_le(data, soff + 40).unwrap_or(0);
                            let fo = r32(data, soff + 48).unwrap_or(0) as u64;
                            (sz, fo)
                        } else {
                            let sz = r32(data, soff + 28).unwrap_or(0) as u64;
                            let fo = r32(data, soff + 36).unwrap_or(0) as u64;
                            (sz, fo)
                        };
                        macho_sections.push(MachoSection { sectname, segname, size, offset: file_offset });
                    }
                }
            }
            // LC_LOAD_DYLIB (0x0C), LC_LOAD_WEAK_DYLIB (0x80000018), LC_REEXPORT_DYLIB (0x1F)
            0x0C | 0x1F => {
                if offset + 12 <= data.len() {
                    let str_offset = r32(data, offset + 8)? as usize;
                    if str_offset < cmdsize {
                        let name = read_cstring(data, offset + str_offset);
                        if !name.is_empty() {
                            dylibs.push(name);
                        }
                    }
                }
            }
            cmd_val if cmd_val == 0x80000018u32 => {
                // LC_LOAD_WEAK_DYLIB
                if offset + 12 <= data.len() {
                    let str_offset = r32(data, offset + 8)? as usize;
                    if str_offset < cmdsize {
                        let name = read_cstring(data, offset + str_offset);
                        if !name.is_empty() {
                            dylibs.push(format!("{name} (weak)"));
                        }
                    }
                }
            }
            // LC_ID_DYLIB (0x0D)
            0x0D => {
                if offset + 12 <= data.len() {
                    let str_offset = r32(data, offset + 8)? as usize;
                    if str_offset < cmdsize {
                        let name = read_cstring(data, offset + str_offset);
                        if !name.is_empty() {
                            id_dylib = Some(name);
                        }
                    }
                }
            }
            // LC_RPATH (0x8000001C)
            cmd_val if cmd_val == 0x8000001Cu32 => {
                if offset + 12 <= data.len() {
                    let str_offset = r32(data, offset + 8)? as usize;
                    if str_offset < cmdsize {
                        let name = read_cstring(data, offset + str_offset);
                        if !name.is_empty() {
                            rpaths.push(name);
                        }
                    }
                }
            }
            // LC_UUID (0x1B)
            0x1B => {
                if offset + 24 <= data.len() {
                    let uuid_bytes = &data[offset + 8..offset + 24];
                    let s = format!(
                        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
                        uuid_bytes[4], uuid_bytes[5],
                        uuid_bytes[6], uuid_bytes[7],
                        uuid_bytes[8], uuid_bytes[9],
                        uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15],
                    );
                    uuid_str = Some(s);
                }
            }
            // LC_SYMTAB (0x02)
            0x02 => {
                if offset + 24 <= data.len() {
                    symtab_off = r32(data, offset + 8)? as usize;
                    symtab_count = r32(data, offset + 12)? as usize;
                    strtab_off = r32(data, offset + 16)? as usize;
                    strtab_size = r32(data, offset + 20)? as usize;
                }
            }
            // LC_DYSYMTAB (0x0B)
            0x0B => {
                if offset + 48 <= data.len() {
                    dysymtab_iextdef = r32(data, offset + 12)? as usize;
                    dysymtab_nextdef = r32(data, offset + 16)? as usize;
                    dysymtab_iundef = r32(data, offset + 20)? as usize;
                    dysymtab_nundef = r32(data, offset + 24)? as usize;
                    has_dysymtab = true;
                }
            }
            _ => {}
        }

        offset += cmdsize;
    }

    if let Some(ref uuid) = uuid_str {
        out.push_str(&format!("UUID:     {uuid}\n"));
    }
    if let Some(ref id) = id_dylib {
        out.push_str(&format!("ID:       {id}\n"));
    }

    // ── Sections ──
    if !macho_sections.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Sections ({}) \u{2500}\u{2500}\n", macho_sections.len()));
        for sec in &macho_sections {
            let entropy = if sec.size > 0 && (sec.offset as usize) < data.len() {
                let start = sec.offset as usize;
                let end = (start + sec.size as usize).min(data.len());
                if start < end { shannon_entropy(&data[start..end]) } else { 0.0 }
            } else {
                0.0
            };
            out.push_str(&format!(
                "  {},{:<16} Size:{:<10}  Entropy:{:.2}\n",
                sec.segname, sec.sectname, format_size(sec.size), entropy
            ));
        }
    }

    // ── Dependencies ──
    if !dylibs.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Dependencies ({}) \u{2500}\u{2500}\n", dylibs.len()));
        for lib in &dylibs {
            out.push_str(&format!("  {lib}\n"));
        }
    }

    // ── RPaths ──
    if !rpaths.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} RPaths ({}) \u{2500}\u{2500}\n", rpaths.len()));
        for rp in &rpaths {
            out.push_str(&format!("  {rp}\n"));
        }
    }

    // ── Symbols (from LC_SYMTAB + LC_DYSYMTAB) ──
    if symtab_count > 0 && strtab_off + strtab_size <= data.len() {
        let nlist_size: usize = if is_64 { 16 } else { 12 };
        let strtab_data = &data[strtab_off..strtab_off + strtab_size];

        let mut exported_syms: Vec<String> = Vec::new();
        let mut imported_syms: Vec<String> = Vec::new();

        if has_dysymtab {
            // Use dysymtab ranges for classification
            for i in dysymtab_iextdef..dysymtab_iextdef + dysymtab_nextdef {
                if let Some(name) = read_nlist_name(data, symtab_off, i, nlist_size, strtab_data) {
                    exported_syms.push(name);
                }
            }
            for i in dysymtab_iundef..dysymtab_iundef + dysymtab_nundef {
                if let Some(name) = read_nlist_name(data, symtab_off, i, nlist_size, strtab_data) {
                    imported_syms.push(name);
                }
            }
        } else {
            // Fallback: classify by n_type
            for i in 0..symtab_count {
                let sym_off = symtab_off + i * nlist_size;
                if sym_off + nlist_size > data.len() { break; }
                let str_idx = read_u32_le(data, sym_off).unwrap_or(0) as usize;
                let n_type = data[sym_off + 4];
                let n_ext = n_type & 0x01 != 0;
                let n_type_mask = n_type & 0x0E;
                if !n_ext { continue; }
                if str_idx < strtab_data.len() {
                    let name = read_cstring(strtab_data, str_idx);
                    if name.is_empty() { continue; }
                    if n_type_mask == 0 { // N_UNDF
                        imported_syms.push(name);
                    } else {
                        exported_syms.push(name);
                    }
                }
            }
        }

        if !exported_syms.is_empty() {
            out.push_str(&format!("\n\u{2500}\u{2500} Exported Symbols ({}) \u{2500}\u{2500}\n", exported_syms.len()));
            for name in exported_syms.iter().take(200) {
                out.push_str(&format!("  {name}\n"));
            }
            if exported_syms.len() > 200 {
                out.push_str(&format!("  ... and {} more\n", exported_syms.len() - 200));
            }
        }

        if !imported_syms.is_empty() {
            out.push_str(&format!("\n\u{2500}\u{2500} Imported Symbols ({}) \u{2500}\u{2500}\n", imported_syms.len()));
            for name in imported_syms.iter().take(200) {
                out.push_str(&format!("  {name}\n"));
            }
            if imported_syms.len() > 200 {
                out.push_str(&format!("  ... and {} more\n", imported_syms.len() - 200));
            }
        }
    }

    Ok(out)
}

fn read_nlist_name(data: &[u8], symtab_off: usize, idx: usize, nlist_size: usize, strtab: &[u8]) -> Option<String> {
    let sym_off = symtab_off + idx * nlist_size;
    if sym_off + nlist_size > data.len() { return None; }
    let str_idx = read_u32_le(data, sym_off).unwrap_or(0) as usize;
    if str_idx >= strtab.len() { return None; }
    let name = read_cstring(strtab, str_idx);
    if name.is_empty() { None } else { Some(name) }
}

fn read_fixed_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    let bytes = &data[offset..end];
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..null_pos]
        .iter()
        .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
        .collect()
}

fn macho_cpu_name(cpu_type: u32, _cpu_subtype: u32) -> &'static str {
    // High bit (0x01000000) = ABI64 flag
    match cpu_type {
        1 => "VAX",
        6 => "MC680x0",
        7 => "x86",
        0x01000007 => "x86_64",
        10 => "MC98000",
        11 => "HPPA",
        12 => "ARM",
        0x0100000C => "ARM64",
        13 => "MC88000",
        14 => "SPARC",
        15 => "i860",
        18 => "PowerPC",
        0x01000012 => "PowerPC64",
        _ => "Unknown",
    }
}

// ── 3. java_class ──────────────────────────────────────────────────

pub fn java_class(graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }
    register_binary(graph, target, EntityKind::JavaClass, "java");

    // Check if JAR (ZIP) file
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    if ext == "jar" || ext == "war" || ext == "ear" {
        return parse_jar(target);
    }

    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match parse_java_class(&data) {
        Ok((info, method_names)) => {
            // 5.15.2: register each method as a BinaryFunction node.
            let class_id = format!("jclass:{target}");
            for (i, name) in method_names.iter().enumerate() {
                let func_id = format!("bin_func:jclass:{target}::{i}");
                graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                    ("name", name),
                    ("binary_format", "jvm"),
                    ("kind_detail", "method"),
                ]);
                graph.add_edge(&class_id, &func_id);
            }
            info
        }
        Err(e) => format!("Java class parse error: {e}"),
    }
}

fn parse_java_class(data: &[u8]) -> Result<(String, Vec<String>), String> {
    if data.len() < 10 {
        return Err("File too small for Java class".to_string());
    }
    // Magic: 0xCAFEBABE (big-endian)
    if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
        return Err("Not a Java class file (missing CAFEBABE magic)".to_string());
    }

    let minor = read_u16_be(data, 4)?;
    let major = read_u16_be(data, 6)?;
    let cp_count = read_u16_be(data, 8)? as usize;

    let java_version = match major {
        45 => "Java 1.1",
        46 => "Java 1.2",
        47 => "Java 1.3",
        48 => "Java 1.4",
        49 => "Java 5",
        50 => "Java 6",
        51 => "Java 7",
        52 => "Java 8",
        53 => "Java 9",
        54 => "Java 10",
        55 => "Java 11",
        56 => "Java 12",
        57 => "Java 13",
        58 => "Java 14",
        59 => "Java 15",
        60 => "Java 16",
        61 => "Java 17",
        62 => "Java 18",
        63 => "Java 19",
        64 => "Java 20",
        65 => "Java 21",
        66 => "Java 22",
        67 => "Java 23",
        _ => "Unknown",
    };

    // Parse constant pool
    // The constant pool is indexed from 1 to cp_count-1
    let mut cp_strings: Vec<Option<String>> = vec![None; cp_count];
    let mut cp_class_names: Vec<Option<u16>> = vec![None; cp_count]; // index to UTF8
    let mut cp_name_and_types: Vec<Option<(u16, u16)>> = vec![None; cp_count];
    let mut cp_refs: Vec<Option<(u16, u16)>> = vec![None; cp_count]; // class_idx, name_and_type_idx

    let mut pos = 10;
    let mut i = 1usize;
    while i < cp_count {
        if pos >= data.len() {
            return Err("Truncated constant pool".to_string());
        }
        let tag = data[pos];
        pos += 1;
        match tag {
            1 => { // UTF8
                if pos + 2 > data.len() { return Err("Truncated UTF8 entry".to_string()); }
                let len = read_u16_be(data, pos)? as usize;
                pos += 2;
                if pos + len > data.len() { return Err("Truncated UTF8 data".to_string()); }
                let s = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
                cp_strings[i] = Some(s);
                pos += len;
            }
            3 | 4 => { pos += 4; } // Integer, Float
            5 | 6 => { pos += 8; i += 1; } // Long, Double (takes two slots)
            7 => { // Class
                if pos + 2 > data.len() { return Err("Truncated Class entry".to_string()); }
                let name_idx = read_u16_be(data, pos)?;
                cp_class_names[i] = Some(name_idx);
                pos += 2;
            }
            8 => { pos += 2; } // String
            9..=11 => { // FieldRef, MethodRef, InterfaceMethodRef
                if pos + 4 > data.len() { return Err("Truncated ref entry".to_string()); }
                let class_idx = read_u16_be(data, pos)?;
                let nat_idx = read_u16_be(data, pos + 2)?;
                cp_refs[i] = Some((class_idx, nat_idx));
                pos += 4;
            }
            12 => { // NameAndType
                if pos + 4 > data.len() { return Err("Truncated NameAndType".to_string()); }
                let name_idx = read_u16_be(data, pos)?;
                let desc_idx = read_u16_be(data, pos + 2)?;
                cp_name_and_types[i] = Some((name_idx, desc_idx));
                pos += 4;
            }
            15 => { pos += 3; } // MethodHandle
            16 => { pos += 2; } // MethodType
            17 | 18 => { pos += 4; } // Dynamic, InvokeDynamic
            19 | 20 => { pos += 2; } // Module, Package
            _ => return Err(format!("Unknown constant pool tag {tag} at index {i}")),
        }
        i += 1;
    }

    // Helper to resolve class name from constant pool
    let resolve_class = |idx: u16| -> String {
        let idx = idx as usize;
        if idx < cp_count {
            if let Some(name_idx) = cp_class_names[idx] {
                let ni = name_idx as usize;
                if ni < cp_count {
                    if let Some(ref s) = cp_strings[ni] {
                        return s.replace('/', ".");
                    }
                }
            }
        }
        format!("<class#{idx}>")
    };

    let resolve_utf8 = |idx: u16| -> String {
        let idx = idx as usize;
        if idx < cp_count {
            if let Some(ref s) = cp_strings[idx] {
                return s.clone();
            }
        }
        format!("<utf8#{idx}>")
    };

    // Access flags
    if pos + 8 > data.len() {
        return Err("Truncated after constant pool".to_string());
    }
    let access_flags = read_u16_be(data, pos)?;
    let this_class = read_u16_be(data, pos + 2)?;
    let super_class = read_u16_be(data, pos + 4)?;
    let interfaces_count = read_u16_be(data, pos + 6)? as usize;
    pos += 8;

    let this_name = resolve_class(this_class);
    let super_name = if super_class == 0 { "none".to_string() } else { resolve_class(super_class) };

    let mut flags_list: Vec<&str> = Vec::new();
    if access_flags & 0x0001 != 0 { flags_list.push("public"); }
    if access_flags & 0x0010 != 0 { flags_list.push("final"); }
    if access_flags & 0x0020 != 0 { flags_list.push("super"); }
    if access_flags & 0x0200 != 0 { flags_list.push("interface"); }
    if access_flags & 0x0400 != 0 { flags_list.push("abstract"); }
    if access_flags & 0x1000 != 0 { flags_list.push("synthetic"); }
    if access_flags & 0x2000 != 0 { flags_list.push("annotation"); }
    if access_flags & 0x4000 != 0 { flags_list.push("enum"); }
    if access_flags & 0x8000 != 0 { flags_list.push("module"); }

    let mut out = String::new();
    out.push_str("=== Java Class Analysis ===\n\n");
    out.push_str(&format!("Version:  {major}.{minor} ({java_version})\n"));
    out.push_str(&format!("Class:    {this_name}\n"));
    out.push_str(&format!("Super:    {super_name}\n"));
    out.push_str(&format!("Flags:    [{}]\n", flags_list.join(", ")));
    out.push_str(&format!("Pool:     {cp_count} entries\n"));

    // Interfaces
    let mut interfaces: Vec<String> = Vec::new();
    for _ in 0..interfaces_count {
        if pos + 2 > data.len() { break; }
        let iface_idx = read_u16_be(data, pos)?;
        interfaces.push(resolve_class(iface_idx));
        pos += 2;
    }

    if !interfaces.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Interfaces ({}) \u{2500}\u{2500}\n", interfaces.len()));
        for iface in &interfaces {
            out.push_str(&format!("  {iface}\n"));
        }
    }

    // Fields
    if pos + 2 > data.len() {
        return Ok((out, Vec::new()));
    }
    let fields_count = read_u16_be(data, pos)? as usize;
    pos += 2;

    struct MemberInfo {
        name: String,
        descriptor: String,
        flags: String,
    }

    let mut fields: Vec<MemberInfo> = Vec::new();
    for _ in 0..fields_count {
        if pos + 8 > data.len() { break; }
        let f_access = read_u16_be(data, pos)?;
        let f_name_idx = read_u16_be(data, pos + 2)?;
        let f_desc_idx = read_u16_be(data, pos + 4)?;
        let f_attr_count = read_u16_be(data, pos + 6)? as usize;
        pos += 8;

        let mut fflags: Vec<&str> = Vec::new();
        if f_access & 0x0001 != 0 { fflags.push("public"); }
        if f_access & 0x0002 != 0 { fflags.push("private"); }
        if f_access & 0x0004 != 0 { fflags.push("protected"); }
        if f_access & 0x0008 != 0 { fflags.push("static"); }
        if f_access & 0x0010 != 0 { fflags.push("final"); }
        if f_access & 0x0040 != 0 { fflags.push("volatile"); }
        if f_access & 0x0080 != 0 { fflags.push("transient"); }

        fields.push(MemberInfo {
            name: resolve_utf8(f_name_idx),
            descriptor: resolve_utf8(f_desc_idx),
            flags: fflags.join(", "),
        });

        // Skip attributes
        for _ in 0..f_attr_count {
            if pos + 6 > data.len() { break; }
            let attr_len = read_u32_be(data, pos + 2)? as usize;
            pos += 6 + attr_len;
        }
    }

    if !fields.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Fields ({}) \u{2500}\u{2500}\n", fields.len()));
        for f in &fields {
            out.push_str(&format!("  {} : {}  [{}]\n", f.name, f.descriptor, f.flags));
        }
    }

    // Methods
    if pos + 2 > data.len() {
        return Ok((out, Vec::new()));
    }
    let methods_count = read_u16_be(data, pos)? as usize;
    pos += 2;

    let mut methods: Vec<MemberInfo> = Vec::new();
    for _ in 0..methods_count {
        if pos + 8 > data.len() { break; }
        let m_access = read_u16_be(data, pos)?;
        let m_name_idx = read_u16_be(data, pos + 2)?;
        let m_desc_idx = read_u16_be(data, pos + 4)?;
        let m_attr_count = read_u16_be(data, pos + 6)? as usize;
        pos += 8;

        let mut mflags: Vec<&str> = Vec::new();
        if m_access & 0x0001 != 0 { mflags.push("public"); }
        if m_access & 0x0002 != 0 { mflags.push("private"); }
        if m_access & 0x0004 != 0 { mflags.push("protected"); }
        if m_access & 0x0008 != 0 { mflags.push("static"); }
        if m_access & 0x0010 != 0 { mflags.push("final"); }
        if m_access & 0x0020 != 0 { mflags.push("synchronized"); }
        if m_access & 0x0100 != 0 { mflags.push("native"); }
        if m_access & 0x0400 != 0 { mflags.push("abstract"); }

        methods.push(MemberInfo {
            name: resolve_utf8(m_name_idx),
            descriptor: resolve_utf8(m_desc_idx),
            flags: mflags.join(", "),
        });

        // Skip attributes
        for _ in 0..m_attr_count {
            if pos + 6 > data.len() { break; }
            let attr_len = read_u32_be(data, pos + 2)? as usize;
            pos += 6 + attr_len;
        }
    }

    if !methods.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Methods ({}) \u{2500}\u{2500}\n", methods.len()));
        for m in &methods {
            out.push_str(&format!("  {} : {}  [{}]\n", m.name, m.descriptor, m.flags));
        }
    }

    let method_names: Vec<String> = methods.iter().map(|m| m.name.clone()).collect();
    Ok((out, method_names))
}

fn parse_jar(target: &str) -> String {
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // JAR = ZIP format. Parse local file headers to list .class files.
    // ZIP local file header magic: PK\x03\x04 = 0x04034b50
    let mut out = String::new();
    out.push_str("=== JAR Analysis ===\n\n");

    let mut class_files: Vec<String> = Vec::new();
    let mut other_files: Vec<String> = Vec::new();
    let mut total_files = 0u32;
    let mut pos = 0usize;

    // Try to parse from central directory first (at end of file)
    // Look for End of Central Directory Record (EOCD): PK\x05\x06
    let eocd_pos = find_eocd(&data);

    if let Some(eocd) = eocd_pos {
        // Parse from central directory
        if eocd + 22 <= data.len() {
            let cd_entries = read_u16_le(&data, eocd + 10).unwrap_or(0) as usize;
            let cd_offset = read_u32_le(&data, eocd + 16).unwrap_or(0) as usize;
            pos = cd_offset;
            for _ in 0..cd_entries {
                if pos + 46 > data.len() { break; }
                // Central directory header: PK\x01\x02
                if data[pos] != b'P' || data[pos + 1] != b'K' || data[pos + 2] != 1 || data[pos + 3] != 2 {
                    break;
                }
                let name_len = read_u16_le(&data, pos + 28).unwrap_or(0) as usize;
                let extra_len = read_u16_le(&data, pos + 30).unwrap_or(0) as usize;
                let comment_len = read_u16_le(&data, pos + 32).unwrap_or(0) as usize;
                let compressed_size = read_u32_le(&data, pos + 20).unwrap_or(0);

                if pos + 46 + name_len > data.len() { break; }
                let name = String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).to_string();
                total_files += 1;

                if name.ends_with(".class") {
                    class_files.push(name);
                } else if !name.ends_with('/') {
                    other_files.push(format!("{name} ({} bytes)", compressed_size));
                }

                pos += 46 + name_len + extra_len + comment_len;
            }
        }
    } else {
        // Fallback: scan local file headers
        while pos + 30 <= data.len() {
            if data[pos] != b'P' || data[pos + 1] != b'K' || data[pos + 2] != 3 || data[pos + 3] != 4 {
                break;
            }
            let name_len = read_u16_le(&data, pos + 26).unwrap_or(0) as usize;
            let extra_len = read_u16_le(&data, pos + 28).unwrap_or(0) as usize;
            let compressed_size = read_u32_le(&data, pos + 18).unwrap_or(0) as usize;

            if pos + 30 + name_len > data.len() { break; }
            let name = String::from_utf8_lossy(&data[pos + 30..pos + 30 + name_len]).to_string();
            total_files += 1;

            if name.ends_with(".class") {
                class_files.push(name);
            } else if !name.ends_with('/') {
                other_files.push(name);
            }

            pos += 30 + name_len + extra_len + compressed_size;
        }
    }

    out.push_str(&format!("Total entries:  {total_files}\n"));
    out.push_str(&format!("Class files:    {}\n", class_files.len()));
    out.push_str(&format!("Other files:    {}\n", other_files.len()));

    // Show packages (derive from class file paths)
    let mut packages: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for cf in &class_files {
        let pkg = if let Some(last_slash) = cf.rfind('/') {
            cf[..last_slash].replace('/', ".")
        } else {
            "(default)".to_string()
        };
        *packages.entry(pkg).or_insert(0) += 1;
    }

    if !packages.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Packages ({}) \u{2500}\u{2500}\n", packages.len()));
        let mut sorted: Vec<_> = packages.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (pkg, count) in sorted.iter().take(100) {
            out.push_str(&format!("  {:<50} {} classes\n", pkg, count));
        }
        if sorted.len() > 100 {
            out.push_str(&format!("  ... and {} more packages\n", sorted.len() - 100));
        }
    }

    // Show notable non-class files
    let notable: Vec<&String> = other_files.iter()
        .filter(|f| {
            let fl = f.to_lowercase();
            fl.contains("manifest") || fl.contains("pom.xml") || fl.ends_with(".properties")
                || fl.ends_with(".xml") || fl.ends_with(".json") || fl.ends_with(".yml")
                || fl.ends_with(".yaml")
        })
        .collect();
    if !notable.is_empty() {
        out.push_str(&"\n\u{2500}\u{2500} Notable Files \u{2500}\u{2500}\n".to_string());
        for f in notable.iter().take(50) {
            out.push_str(&format!("  {f}\n"));
        }
    }

    out
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    // Search backwards for PK\x05\x06
    if data.len() < 22 { return None; }
    let search_start = if data.len() > 65557 { data.len() - 65557 } else { 0 };
    let mut i = data.len() - 22;
    while i >= search_start {
        if data[i] == b'P' && data[i + 1] == b'K' && data[i + 2] == 5 && data[i + 3] == 6 {
            return Some(i);
        }
        if i == 0 { break; }
        i -= 1;
    }
    None
}

// ── 4. wasm_info ───────────────────────────────────────────────────

pub fn wasm_info(graph: &mut Graph, target: &str) -> String {
    register_binary(graph, target, EntityKind::WasmModule, "wasm");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    // Function-level graph augmentation (5.14.0 task #42):
    // walk the Code section, register a BinaryFunction node per
    // function body with its call edges. Independent pass from
    // parse_wasm to avoid disturbing the existing report format.
    walk_wasm_code_for_graph(graph, target, &data);
    match parse_wasm(&data) {
        Ok(info) => info,
        Err(e) => format!("WASM parse error: {e}"),
    }
}

/// Walk the WASM module a second time, focused on function-level
/// graph registration: imports + code bodies become BinaryFunction
/// nodes, with edges from the WasmModule + intra-module call edges
/// (`call` opcode 0x10 emits a direct edge to the target function).
/// Reuses BinaryFunction kind via attrs["binary_format"]="wasm".
fn walk_wasm_code_for_graph(graph: &mut Graph, target: &str, data: &[u8]) {
    if data.len() < 8 || &data[..4] != b"\0asm" { return; }

    let module_id = format!("wasm:{target}");

    // Pass 1: walk all sections, build a function-name table and
    // remember the Code section position. Function index space:
    //   [0..n_imports)            — imports
    //   [n_imports..n_imports+n_code) — defined functions
    let mut imports_func: Vec<String> = Vec::new();   // module.field for each import
    let mut export_names: Vec<(u32, String)> = Vec::new(); // (funcidx, name)
    let mut code_section: Option<(usize, usize)> = None;  // (start_offset, size)

    let mut pos = 8usize;
    while pos < data.len() {
        let section_id = data[pos];
        pos += 1;
        let (sec_size, c) = match decode_leb128(data, pos) { Ok(v) => v, Err(_) => return };
        pos += c;
        let sec_start = pos;
        if pos + sec_size as usize > data.len() { return; }
        let sec_end = sec_start + sec_size as usize;

        match section_id {
            2 => { // Import section
                let mut p = sec_start;
                let (count, cc) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                p += cc;
                for _ in 0..count {
                    if p >= sec_end { break; }
                    let (mod_len, c1) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                    p += c1;
                    let mod_end = (p + mod_len as usize).min(sec_end);
                    let module = String::from_utf8_lossy(&data[p..mod_end]).to_string();
                    p = mod_end;
                    let (field_len, c2) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                    p += c2;
                    let field_end = (p + field_len as usize).min(sec_end);
                    let field = String::from_utf8_lossy(&data[p..field_end]).to_string();
                    p = field_end;
                    if p >= sec_end { break; }
                    let kind_byte = data[p]; p += 1;
                    match kind_byte {
                        0 => {
                            let (_, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                            p += c;
                            imports_func.push(format!("{module}.{field}"));
                        }
                        1 => {
                            // table: elem_type byte + limits
                            p += 1;
                            let (flags, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                            p += c;
                            let (_, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                            p += c;
                            if flags & 0x1 != 0 {
                                let (_, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                                p += c;
                            }
                        }
                        2 => {
                            let flags = if p < sec_end { data[p] } else { 0 }; p += 1;
                            let (_, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                            p += c;
                            if flags & 0x1 != 0 {
                                let (_, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                                p += c;
                            }
                        }
                        3 => { p += 2; }  // global: valtype + mutability
                        _ => break,
                    }
                }
            }
            7 => { // Export section
                let mut p = sec_start;
                let (count, cc) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                p += cc;
                for _ in 0..count {
                    if p >= sec_end { break; }
                    let (name_len, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                    p += c;
                    let name_end = (p + name_len as usize).min(sec_end);
                    let name = String::from_utf8_lossy(&data[p..name_end]).to_string();
                    p = name_end;
                    if p >= sec_end { break; }
                    let kind_byte = data[p]; p += 1;
                    let (idx, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
                    p += c;
                    if kind_byte == 0 {
                        // Export of a function — record name for that funcidx
                        export_names.push((idx as u32, name));
                    }
                }
            }
            10 => { // Code section
                code_section = Some((sec_start, sec_size as usize));
            }
            _ => {}
        }
        pos = sec_end;
    }

    // Pass 2: register every import as a BinaryFunction (with the
    // import as both name + linker reference) and walk the code
    // section to register defined functions + their call edges.
    for (i, name) in imports_func.iter().enumerate() {
        let func_id = format!("bin_func:wasm:{target}::imp::{i}");
        let idx_str = i.to_string();
        graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
            ("name", name),
            ("binary_format", "wasm"),
            ("kind_detail", "import"),
            ("funcidx", &idx_str),
        ]);
        graph.add_edge(&module_id, &func_id);
    }

    let n_imports = imports_func.len();
    let mut export_lookup: std::collections::HashMap<u32, String> = export_names.into_iter().collect();

    if let Some((start, size)) = code_section {
        let end = start + size;
        let mut p = start;
        let (count, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => return };
        p += c;
        for body_idx in 0..count {
            if p >= end { break; }
            let funcidx = (n_imports + body_idx as usize) as u32;
            let func_name = export_lookup.remove(&funcidx).unwrap_or_else(|| format!("func_{funcidx}"));
            let (body_size, c) = match decode_leb128(data, p) { Ok(v) => v, Err(_) => break };
            p += c;
            let body_start = p;
            let body_end = (body_start + body_size as usize).min(end);
            if body_end > data.len() { break; }
            let body = &data[body_start..body_end];
            let (instr_count, calls) = scan_wasm_body(body);

            let func_id = format!("bin_func:wasm:{target}::def::{body_idx}");
            let funcidx_str = funcidx.to_string();
            let body_size_str = body_size.to_string();
            let icnt = instr_count.to_string();
            let cnt = calls.len().to_string();
            graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                ("name", &func_name),
                ("binary_format", "wasm"),
                ("kind_detail", "defined"),
                ("funcidx", &funcidx_str),
                ("size", &body_size_str),
                ("instruction_count", &icnt),
                ("direct_calls", &cnt),
            ]);
            graph.add_edge(&module_id, &func_id);

            // Resolve direct call edges. Calls into [0..n_imports)
            // resolve to import nodes; calls into [n_imports..)
            // resolve to defined nodes.
            for callee in &calls {
                let callee_id = if (*callee as usize) < n_imports {
                    format!("bin_func:wasm:{target}::imp::{callee}")
                } else {
                    let body_i = *callee as usize - n_imports;
                    format!("bin_func:wasm:{target}::def::{body_i}")
                };
                graph.add_edge(&func_id, &callee_id);
            }

            p = body_end;
        }
    }
}

/// Walk a WASM function body and return (instruction_count,
/// direct_call_targets). Stops at the terminating 0x0B (end) of the
/// outermost block. Skips immediates per the WASM 1.0 instruction
/// catalog. Imports + indirect calls are NOT in the result — only
/// the `call` opcode 0x10 with its leb128 funcidx.
fn scan_wasm_body(body: &[u8]) -> (usize, Vec<u32>) {
    // Skip locals declaration: count + (count, type) pairs
    let mut p = 0usize;
    let mut instr_count = 0usize;
    let mut calls: Vec<u32> = Vec::new();
    let (n_local_groups, c) = match decode_leb128(body, p) {
        Ok(v) => v,
        Err(_) => return (0, calls),
    };
    p += c;
    for _ in 0..n_local_groups {
        let (_, c1) = match decode_leb128(body, p) { Ok(v) => v, Err(_) => return (0, calls) };
        p += c1;
        if p >= body.len() { return (0, calls); }
        p += 1; // valtype byte
    }

    let mut depth = 0i32;
    while p < body.len() {
        let op = body[p]; p += 1;
        instr_count += 1;
        match op {
            // Control flow with blocktype immediate
            0x02 | 0x03 | 0x04 => {
                // block / loop / if + blocktype
                if p < body.len() {
                    let bt = body[p];
                    if bt == 0x40 || (0x7C..=0x7F).contains(&bt) {
                        p += 1;
                    } else {
                        // signed leb128 type index
                        if let Ok((_, c)) = decode_signed_leb128(body, p) { p += c; }
                    }
                }
                depth += 1;
            }
            0x05 => { /* else */ }
            0x0B => { // end
                if depth == 0 { break; }
                depth -= 1;
            }
            0x0C | 0x0D => {
                // br / br_if labelidx
                if let Ok((_, c)) = decode_leb128(body, p) { p += c; }
            }
            0x0E => {
                // br_table: vec(labelidx) + default
                let (count, c) = match decode_leb128(body, p) { Ok(v) => v, Err(_) => break };
                p += c;
                for _ in 0..=count {
                    if let Ok((_, cc)) = decode_leb128(body, p) { p += cc; } else { break; }
                }
            }
            0x10 => {
                // call funcidx
                let (idx, c) = match decode_leb128(body, p) { Ok(v) => v, Err(_) => break };
                p += c;
                calls.push(idx as u32);
            }
            0x11 => {
                // call_indirect typeidx tableidx
                let (_, c) = match decode_leb128(body, p) { Ok(v) => v, Err(_) => break };
                p += c;
                let (_, c) = match decode_leb128(body, p) { Ok(v) => v, Err(_) => break };
                p += c;
            }
            // Variable + memory + numeric ops with one leb128 immediate
            0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 |
            0x41 |  // i32.const
            0x42 => { // i64.const
                if let Ok((_, c)) = decode_signed_leb128(body, p) { p += c; }
            }
            // f32.const (4 bytes) / f64.const (8 bytes)
            0x43 => p += 4,
            0x44 => p += 8,
            // Memory ops with align + offset (two leb128s)
            0x28..=0x3E => {
                if let Ok((_, c)) = decode_leb128(body, p) { p += c; }
                if let Ok((_, c)) = decode_leb128(body, p) { p += c; }
            }
            // Memory.grow / memory.size: take 0x00 byte
            0x3F | 0x40 => { p += 1; }
            // Single-byte ops (most numeric/bitwise/conversion ops)
            _ => {}
        }
        if instr_count > 1_000_000 { break; }
    }
    (instr_count, calls)
}

fn decode_signed_leb128(data: &[u8], offset: usize) -> Result<(i64, usize), String> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut consumed = 0;
    let mut last_byte = 0u8;
    loop {
        if offset + consumed >= data.len() { return Err("LEB128 EOF".to_string()); }
        let b = data[offset + consumed];
        consumed += 1;
        last_byte = b;
        result |= ((b & 0x7F) as i64) << shift;
        shift += 7;
        if (b & 0x80) == 0 { break; }
        if shift > 63 { return Err("LEB128 too long".to_string()); }
    }
    if shift < 64 && (last_byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok((result, consumed))
}

fn parse_wasm(data: &[u8]) -> Result<String, String> {
    if data.len() < 8 {
        return Err("File too small for WASM".to_string());
    }
    // Magic: \0asm
    if data[0] != 0x00 || data[1] != b'a' || data[2] != b's' || data[3] != b'm' {
        return Err("Not a WASM file (missing \\0asm magic)".to_string());
    }

    let version = read_u32_le(data, 4)?;

    let mut out = String::new();
    out.push_str("=== WASM Analysis ===\n\n");
    out.push_str(&format!("Version:   {version}\n"));
    out.push_str(&format!("File size: {}\n", format_size(data.len() as u64)));

    // Parse sections
    struct WasmSection {
        id: u8,
        name: String,
        size: u64,
        offset: usize,
    }

    let mut sections: Vec<WasmSection> = Vec::new();
    let mut imports: Vec<(String, String, &str)> = Vec::new(); // (module, name, kind)
    let mut exports: Vec<(String, &str)> = Vec::new(); // (name, kind)
    let mut func_count: u64 = 0;
    let mut type_count: u64 = 0;
    let mut code_count: u64 = 0;

    let mut pos = 8usize;
    while pos < data.len() {
        if pos >= data.len() { break; }
        let section_id = data[pos];
        pos += 1;

        let (section_size, consumed) = decode_leb128(data, pos)?;
        pos += consumed;
        let section_data_start = pos;

        if pos + section_size as usize > data.len() {
            break;
        }

        let section_name = match section_id {
            0 => {
                // Custom section: first field is a name string
                let (name_len, nc) = decode_leb128(data, pos)?;
                let name_start = pos + nc;
                let name_end = (name_start + name_len as usize).min(data.len());
                let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                format!("Custom ({})", name)
            }
            1 => {
                // Type section
                let (count, _) = decode_leb128(data, pos)?;
                type_count = count;
                "Type".to_string()
            }
            2 => {
                // Import section
                let mut ipos = pos;
                let (count, consumed) = decode_leb128(data, ipos)?;
                ipos += consumed;
                for _ in 0..count {
                    if ipos >= section_data_start + section_size as usize { break; }
                    // module name
                    let (mod_len, c1) = decode_leb128(data, ipos)?;
                    ipos += c1;
                    let mod_end = (ipos + mod_len as usize).min(data.len());
                    let module = String::from_utf8_lossy(&data[ipos..mod_end]).to_string();
                    ipos += mod_len as usize;
                    // field name
                    let (field_len, c2) = decode_leb128(data, ipos)?;
                    ipos += c2;
                    let field_end = (ipos + field_len as usize).min(data.len());
                    let field = String::from_utf8_lossy(&data[ipos..field_end]).to_string();
                    ipos += field_len as usize;
                    // import kind
                    if ipos >= data.len() { break; }
                    let kind_byte = data[ipos];
                    ipos += 1;
                    let kind = match kind_byte {
                        0 => { // function (type index)
                            let (_, c) = decode_leb128(data, ipos)?;
                            ipos += c;
                            "func"
                        }
                        1 => { // table
                            ipos += 1; // elem type
                            let (_, c) = decode_leb128(data, ipos)?; // limits flag
                            ipos += c;
                            let (_, c) = decode_leb128(data, ipos)?; // min
                            ipos += c;
                            if ipos > 0 && data.get(ipos - 1 - c).copied().unwrap_or(0) & 0x1 != 0 {
                                let (_, c) = decode_leb128(data, ipos)?;
                                ipos += c;
                            }
                            "table"
                        }
                        2 => { // memory
                            let flags = if ipos < data.len() { data[ipos] } else { 0 };
                            ipos += 1;
                            let (_, c) = decode_leb128(data, ipos)?;
                            ipos += c;
                            if flags & 0x1 != 0 {
                                let (_, c) = decode_leb128(data, ipos)?;
                                ipos += c;
                            }
                            "memory"
                        }
                        3 => { // global
                            ipos += 1; // value type
                            ipos += 1; // mutability
                            "global"
                        }
                        _ => { "unknown" }
                    };
                    imports.push((module, field, kind));
                }
                "Import".to_string()
            }
            3 => {
                // Function section
                let (count, _) = decode_leb128(data, pos)?;
                func_count = count;
                "Function".to_string()
            }
            4 => "Table".to_string(),
            5 => "Memory".to_string(),
            6 => "Global".to_string(),
            7 => {
                // Export section
                let mut epos = pos;
                let (count, consumed) = decode_leb128(data, epos)?;
                epos += consumed;
                for _ in 0..count {
                    if epos >= section_data_start + section_size as usize { break; }
                    let (name_len, c) = decode_leb128(data, epos)?;
                    epos += c;
                    let name_end = (epos + name_len as usize).min(data.len());
                    let name = String::from_utf8_lossy(&data[epos..name_end]).to_string();
                    epos += name_len as usize;
                    if epos >= data.len() { break; }
                    let kind_byte = data[epos];
                    epos += 1;
                    let (_, c) = decode_leb128(data, epos)?; // index
                    epos += c;
                    let kind = match kind_byte {
                        0 => "func",
                        1 => "table",
                        2 => "memory",
                        3 => "global",
                        _ => "unknown",
                    };
                    exports.push((name, kind));
                }
                "Export".to_string()
            }
            8 => "Start".to_string(),
            9 => "Element".to_string(),
            10 => {
                // Code section
                let (count, _) = decode_leb128(data, pos)?;
                code_count = count;
                "Code".to_string()
            }
            11 => "Data".to_string(),
            12 => "DataCount".to_string(),
            _ => format!("Unknown({})", section_id),
        };

        sections.push(WasmSection {
            id: section_id,
            name: section_name,
            size: section_size,
            offset: section_data_start,
        });

        pos = section_data_start + section_size as usize;
    }

    out.push_str(&format!("Types:     {type_count}\n"));
    out.push_str(&format!("Functions: {func_count}\n"));
    out.push_str(&format!("Code:      {code_count} bodies\n"));
    out.push_str(&format!("Imports:   {}\n", imports.len()));
    out.push_str(&format!("Exports:   {}\n", exports.len()));

    // ── Sections ──
    out.push_str(&format!("\n\u{2500}\u{2500} Sections ({}) \u{2500}\u{2500}\n", sections.len()));
    for sec in &sections {
        let entropy = if sec.size > 0 && sec.offset < data.len() {
            let end = (sec.offset + sec.size as usize).min(data.len());
            if sec.offset < end { shannon_entropy(&data[sec.offset..end]) } else { 0.0 }
        } else {
            0.0
        };
        out.push_str(&format!(
            "  [{:>2}] {:<20} Offset:0x{:<8X}  Size:{:<10}  Entropy:{:.2}\n",
            sec.id, sec.name, sec.offset, format_size(sec.size), entropy
        ));
    }

    // ── Imports ──
    if !imports.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Imports ({}) \u{2500}\u{2500}\n", imports.len()));
        for (module, name, kind) in imports.iter().take(200) {
            out.push_str(&format!("  {module}.{name}  ({kind})\n"));
        }
        if imports.len() > 200 {
            out.push_str(&format!("  ... and {} more\n", imports.len() - 200));
        }
    }

    // ── Exports ──
    if !exports.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Exports ({}) \u{2500}\u{2500}\n", exports.len()));
        for (name, kind) in exports.iter().take(200) {
            out.push_str(&format!("  {name}  ({kind})\n"));
        }
        if exports.len() > 200 {
            out.push_str(&format!("  ... and {} more\n", exports.len() - 200));
        }
    }

    Ok(out)
}
