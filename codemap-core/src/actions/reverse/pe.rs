use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use crate::types::{Graph, EntityKind};
use crate::utils;

use super::common::*;

/// Heterogeneous-graph helper: register the analyzed PE binary as a typed
/// node so subsequent passes (pe_imports, pe_exports, etc.) can attach
/// edges to the same node, and so graph-theory actions (pagerank, hubs,
/// dot, mermaid) see it. Idempotent — multiple actions on the same
/// target merge their attrs into a single node.
fn ensure_pe_binary_node(graph: &mut Graph, target: &str, source: &str) {
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[
        ("path", target),
        ("source_action", source),
    ]);
}

// ── 1. pe_strings ───────────────────────────────────────────────────

pub fn pe_strings(graph: &mut Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    ensure_pe_binary_node(graph, target, "pe_strings");

    // Extract ASCII strings of length >= 6
    let strings = extract_ascii_strings(&data, 6);

    if strings.is_empty() {
        return "No strings found in binary.".to_string();
    }

    // Promote each extracted string to a StringLiteral node.
    promote_strings_to_graph(graph, target, "pe", &strings);

    // Categorize
    let mut sql_strings: BTreeSet<String> = BTreeSet::new();
    let mut table_strings: BTreeSet<String> = BTreeSet::new();
    let mut url_strings: BTreeSet<String> = BTreeSet::new();
    let mut path_strings: BTreeSet<String> = BTreeSet::new();
    let mut field_strings: BTreeSet<String> = BTreeSet::new();

    let sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "FROM", "WHERE", "JOIN"];

    for s in &strings {
        let upper = s.to_uppercase();

        // SQL
        if sql_keywords.iter().any(|kw| upper.contains(kw)) {
            sql_strings.insert(s.clone());
            continue;
        }

        // Tables (dbo.xxx pattern)
        if s.contains("dbo.") {
            table_strings.insert(s.clone());
            continue;
        }

        // URLs
        if s.contains("http://") || s.contains("https://") {
            url_strings.insert(s.clone());
            continue;
        }

        // Paths
        if s.contains("C:\\") || s.contains("c:\\") || s.contains("\\\\") {
            path_strings.insert(s.clone());
            continue;
        }

        // Fields: short identifiers (alphanumeric + underscore, starts with letter, 6-40 chars)
        if s.len() <= 40 && is_identifier(s) {
            field_strings.insert(s.clone());
        }
    }

    let mut out = String::new();
    out.push_str("=== PE String Analysis ===\n\n");
    out.push_str(&format!("Total strings extracted: {}\n", strings.len()));
    out.push_str(&format!("SQL statements: {}\n", sql_strings.len()));
    out.push_str(&format!("Table references: {}\n", table_strings.len()));
    out.push_str(&format!("URLs: {}\n", url_strings.len()));
    out.push_str(&format!("Paths: {}\n", path_strings.len()));
    out.push_str(&format!("Identifiers: {}\n", field_strings.len()));
    out.push('\n');

    if !sql_strings.is_empty() {
        out.push_str("── SQL ──\n");
        for s in sql_strings.iter().take(100) {
            out.push_str(&format!("  {}\n", truncate_str(s, 120)));
        }
        out.push('\n');
    }

    if !table_strings.is_empty() {
        out.push_str("── Tables ──\n");
        for s in table_strings.iter().take(100) {
            out.push_str(&format!("  {}\n", s));
        }
        out.push('\n');
    }

    if !url_strings.is_empty() {
        out.push_str("── URLs ──\n");
        for s in url_strings.iter().take(50) {
            out.push_str(&format!("  {}\n", s));
        }
        out.push('\n');
    }

    if !path_strings.is_empty() {
        out.push_str("── Paths ──\n");
        for s in path_strings.iter().take(50) {
            out.push_str(&format!("  {}\n", s));
        }
        out.push('\n');
    }

    if !field_strings.is_empty() {
        out.push_str("── Identifiers ──\n");
        for s in field_strings.iter().take(100) {
            out.push_str(&format!("  {}\n", s));
        }
        out.push('\n');
    }

    out
}

// ── 2. pe_exports ───────────────────────────────────────────────────

pub fn pe_exports(graph: &mut Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match parse_pe_exports(&data) {
        Ok(exports) => {
            // Register binary + each export as a Symbol node (with the
            // binary as the export source), so reverse lookups work:
            // "what binary exports symbol X?" via imported_by traversal.
            ensure_pe_binary_node(graph, target, "pe_exports");
            let bin_id = format!("pe:{target}");
            for sym in &exports {
                let demangled = crate::demangle::demangle(sym);
                let display = demangled.as_deref().unwrap_or(sym);
                let sym_id = format!("sym:{target}::{display}");
                let mut attrs: Vec<(&str, &str)> = vec![
                    ("name", display),
                    ("exported_by", target),
                ];
                if demangled.is_some() { attrs.push(("mangled", sym)); }
                graph.ensure_typed_node(&sym_id, EntityKind::Symbol, &attrs);
                graph.add_edge(&bin_id, &sym_id);
            }
            if exports.is_empty() {
                return "No exports found in PE binary.".to_string();
            }
            let mut out = String::new();
            out.push_str("=== PE Export Table ===\n\n");
            out.push_str(&format!("Exports: {}\n\n", exports.len()));
            for (i, name) in exports.iter().enumerate() {
                let demangled = crate::demangle::demangle(name);
                if let Some(d) = demangled {
                    out.push_str(&format!("  {:4}  {}\n         (mangled: {})\n", i + 1, d, name));
                } else {
                    out.push_str(&format!("  {:4}  {}\n", i + 1, name));
                }
            }
            out
        }
        Err(e) => {
            // Fall back to heuristic extraction
            let fallback = extract_export_names_heuristic(&data);
            if fallback.is_empty() {
                return format!("PE parse error: {e}\nNo export-like names found via heuristic.");
            }
            let mut out = String::new();
            out.push_str(&format!("=== PE Export Table (heuristic, parse failed: {e}) ===\n\n"));
            out.push_str(&format!("Candidate exports: {}\n\n", fallback.len()));
            for (i, name) in fallback.iter().enumerate().take(200) {
                out.push_str(&format!("  {:4}  {}\n", i + 1, name));
            }
            out
        }
    }
}

fn parse_pe_exports(data: &[u8]) -> Result<Vec<String>, String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }

    // Check DOS header magic "MZ"
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    // e_lfanew at offset 0x3C (4 bytes, little-endian)
    let e_lfanew = read_u32(data, 0x3C)? as usize;

    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew offset".to_string());
    }

    // Check PE signature "PE\0\0"
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    // COFF header starts at e_lfanew + 4
    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    // Optional header starts after COFF header (20 bytes)
    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    // Determine PE32 vs PE32+
    let opt_magic = read_u16(data, opt_start)?;
    let (data_dir_offset, _is_pe32_plus) = match opt_magic {
        0x10B => (opt_start + 96, false),   // PE32: data directories at offset 96
        0x20B => (opt_start + 112, true),   // PE32+: data directories at offset 112
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    // Export table is data directory entry 0 (first entry, 8 bytes: RVA + Size)
    if data_dir_offset + 8 > data.len() {
        return Err("No data directory entries".to_string());
    }

    let export_rva = read_u32(data, data_dir_offset)? as usize;
    let export_size = read_u32(data, data_dir_offset + 4)? as usize;

    if export_rva == 0 || export_size == 0 {
        return Err("No export directory".to_string());
    }

    // Parse section headers to resolve RVA -> file offset
    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let export_offset = rva_to_offset(export_rva, &sections)
        .ok_or_else(|| "Cannot resolve export RVA to file offset".to_string())?;

    if export_offset + 40 > data.len() {
        return Err("Truncated export directory".to_string());
    }

    // Export directory table structure (40 bytes):
    // Offset 24: NumberOfNames (4 bytes)
    // Offset 32: AddressOfNames (RVA, 4 bytes)
    let num_names = read_u32(data, export_offset + 24)? as usize;
    let names_rva = read_u32(data, export_offset + 32)? as usize;

    if num_names == 0 {
        return Ok(Vec::new());
    }

    let names_offset = rva_to_offset(names_rva, &sections)
        .ok_or_else(|| "Cannot resolve names RVA".to_string())?;

    let mut exports = Vec::new();

    for i in 0..num_names {
        let name_ptr_offset = names_offset + i * 4;
        if name_ptr_offset + 4 > data.len() {
            break;
        }

        let name_rva = read_u32(data, name_ptr_offset)? as usize;
        let name_offset = match rva_to_offset(name_rva, &sections) {
            Some(o) => o,
            None => continue,
        };

        if name_offset >= data.len() {
            continue;
        }

        // Read null-terminated string
        let name = read_cstring(data, name_offset);
        if !name.is_empty() {
            exports.push(name);
        }
    }

    exports.sort();
    Ok(exports)
}

fn extract_export_names_heuristic(data: &[u8]) -> Vec<String> {
    // Heuristic: look for sequences of PascalCase or snake_case identifiers
    // near the beginning of the file (first 10% or 1MB, whichever is smaller)
    let search_len = data.len().min(1_048_576);
    let strings = extract_ascii_strings(&data[..search_len], 4);

    let mut candidates: BTreeSet<String> = BTreeSet::new();

    for s in &strings {
        if s.len() < 4 || s.len() > 200 {
            continue;
        }

        // PascalCase: starts with uppercase, has mixed case, no spaces
        let is_pascal = s.starts_with(|c: char| c.is_ascii_uppercase())
            && s.chars().any(|c| c.is_ascii_lowercase())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');

        // snake_case: lowercase with underscores
        let is_snake = s.contains('_')
            && s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');

        // Decorated names (MSVC mangling): starts with ? or @
        let is_decorated = s.starts_with('?') || s.starts_with('@');

        if is_pascal || is_snake || is_decorated {
            candidates.insert(s.clone());
        }
    }

    candidates.into_iter().collect()
}

// ── 3. pe_imports ──────────────────────────────────────────────────

pub fn pe_imports(graph: &mut Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match parse_pe_imports_structured(&data) {
        Ok(dlls) => {
            register_pe_imports_into_graph(graph, target, &dlls);
            format_pe_imports_result(&dlls)
        }
        Err(e) => format!("PE import parse error: {e}"),
    }
}

/// Heterogeneous-graph pass: register the analyzed PE binary, every DLL it
/// imports, and every imported symbol as typed nodes, with edges from the
/// binary to its DLLs and from each DLL to its symbols. Lets pagerank/hubs/
/// bridges/clusters/dot operate on PE binary networks the same way they
/// operate on source-code import graphs.
fn register_pe_imports_into_graph(graph: &mut Graph, target: &str, dlls: &[ImportedDll]) {
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(
        &bin_id,
        crate::types::EntityKind::PeBinary,
        &[("path", target), ("dll_count", &dlls.len().to_string())],
    );

    for dll in dlls {
        let dll_id = format!("dll:{}", dll.name.to_ascii_lowercase());
        graph.ensure_typed_node(
            &dll_id,
            crate::types::EntityKind::Dll,
            &[("name", &dll.name), ("symbol_count", &dll.functions.len().to_string())],
        );
        graph.add_edge(&bin_id, &dll_id);

        for sym in &dll.functions {
            let demangled = crate::demangle::demangle(sym);
            let display = demangled.as_deref().unwrap_or(sym);
            let sym_id = format!("sym:{}::{}", dll.name.to_ascii_lowercase(), display);
            let mut attrs: Vec<(&str, &str)> = vec![
                ("name", display),
                ("dll", &dll.name),
            ];
            if demangled.is_some() { attrs.push(("mangled", sym)); }
            graph.ensure_typed_node(
                &sym_id,
                crate::types::EntityKind::Symbol,
                &attrs,
            );
            graph.add_edge(&dll_id, &sym_id);
        }
    }
}

/// Represents a single imported DLL and its functions.
struct ImportedDll {
    name: String,
    functions: Vec<String>,
}

/// Format parsed PE imports into a human-readable report.
/// Used by both `pe_imports` (public action) and `binary_diff`.
fn format_pe_imports_result(dlls: &[ImportedDll]) -> String {
    if dlls.is_empty() {
        return "No imports found in PE binary.".to_string();
    }

    let total_functions: usize = dlls.iter().map(|d| d.functions.len()).sum();

    let mut out = String::new();
    out.push_str("=== PE Import Analysis ===\n\n");
    out.push_str(&format!("DLLs: {}\n", dlls.len()));
    out.push_str(&format!("Total imported functions: {total_functions}\n\n"));

    for dll in dlls {
        out.push_str(&format!("── {} ({} functions) ──\n", dll.name, dll.functions.len()));
        for func in &dll.functions {
            out.push_str(&format!("  {func}\n"));
        }
        out.push('\n');
    }

    // Categorized interesting imports
    let mut db_imports: Vec<(String, Vec<String>)> = Vec::new();
    let mut net_imports: Vec<(String, Vec<String>)> = Vec::new();
    let mut reg_imports: Vec<(String, Vec<String>)> = Vec::new();
    let mut file_imports: Vec<(String, Vec<String>)> = Vec::new();
    let mut crypto_imports: Vec<(String, Vec<String>)> = Vec::new();
    let mut com_imports: Vec<(String, Vec<String>)> = Vec::new();

    for dll in dlls {
        let dll_lower = dll.name.to_ascii_lowercase();

        // Database/SQL
        if dll_lower == "odbc32.dll"
            || dll_lower.starts_with("sqlsrv")
            || dll_lower.starts_with("msodbcsql")
        {
            db_imports.push((dll.name.clone(), dll.functions.clone()));
            continue;
        }

        // Network
        if dll_lower == "ws2_32.dll"
            || dll_lower == "wsock32.dll"
            || dll_lower == "winhttp.dll"
            || dll_lower == "wininet.dll"
        {
            net_imports.push((dll.name.clone(), dll.functions.clone()));
            continue;
        }

        // COM/OLE
        if dll_lower == "ole32.dll" || dll_lower == "oleaut32.dll" {
            com_imports.push((dll.name.clone(), dll.functions.clone()));
            continue;
        }

        // Registry (advapi32 functions containing "Reg")
        if dll_lower == "advapi32.dll" {
            let reg_funcs: Vec<String> = dll.functions.iter()
                .filter(|f| f.contains("Reg"))
                .cloned()
                .collect();
            if !reg_funcs.is_empty() {
                reg_imports.push((dll.name.clone(), reg_funcs));
            }

            let crypto_funcs: Vec<String> = dll.functions.iter()
                .filter(|f| f.contains("Crypt") || f.contains("Hash"))
                .cloned()
                .collect();
            if !crypto_funcs.is_empty() {
                crypto_imports.push((dll.name.clone(), crypto_funcs));
            }
        }

        // Crypto (bcrypt, ncrypt)
        if dll_lower == "bcrypt.dll" || dll_lower == "ncrypt.dll" {
            let crypto_funcs: Vec<String> = dll.functions.iter()
                .filter(|f| f.contains("Crypt") || f.contains("Hash") || f.starts_with("BCrypt") || f.starts_with("NCrypt"))
                .cloned()
                .collect();
            if !crypto_funcs.is_empty() {
                crypto_imports.push((dll.name.clone(), crypto_funcs));
            }
        }

        // File I/O (kernel32 functions containing "File" or "Directory")
        if dll_lower == "kernel32.dll" {
            let file_funcs: Vec<String> = dll.functions.iter()
                .filter(|f| f.contains("File") || f.contains("Directory"))
                .cloned()
                .collect();
            if !file_funcs.is_empty() {
                file_imports.push((dll.name.clone(), file_funcs));
            }
        }
    }

    // Append categorized sections
    let categories: Vec<(&str, &Vec<(String, Vec<String>)>)> = vec![
        ("Database/SQL Imports", &db_imports),
        ("Network Imports", &net_imports),
        ("Registry Imports", &reg_imports),
        ("File I/O Imports", &file_imports),
        ("Crypto Imports", &crypto_imports),
        ("COM/OLE Imports", &com_imports),
    ];

    let has_any = categories.iter().any(|(_, v)| !v.is_empty());
    if has_any {
        for (label, entries) in &categories {
            if entries.is_empty() {
                continue;
            }
            out.push_str(&format!("=== {label} ===\n"));
            for (dll_name, funcs) in *entries {
                out.push_str(&format!("  {dll_name}: {}\n", funcs.join(", ")));
            }
            out.push('\n');
        }
    }

    out
}

// ── 4. pe_resources ────────────────────────────────────────────────

pub fn pe_resources(graph: &mut Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    ensure_pe_binary_node(graph, target, "pe_resources");

    match parse_pe_resources(&data) {
        Ok(info) => info,
        Err(e) => format!("PE parse error: {e}"),
    }
}

fn resource_type_name(id: u32) -> &'static str {
    match id {
        1 => "Cursor",
        2 => "Bitmap",
        3 => "Icon",
        4 => "Menu",
        5 => "Dialog",
        6 => "StringTable",
        7 => "FontDir",
        8 => "Font",
        9 => "Accelerator",
        10 => "RCData",
        11 => "MessageTable",
        12 => "GroupCursor",
        14 => "GroupIcon",
        16 => "VersionInfo",
        24 => "Manifest",
        _ => "Unknown",
    }
}

struct ResourceDataEntry {
    rva: usize,
    size: usize,
}

struct ResourceInfo {
    type_id: u32,
    type_name: Option<String>,
    entries: Vec<ResourceDataEntry>,
}

fn parse_pe_resources(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }

    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew offset".to_string());
    }

    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    let opt_magic = read_u16(data, opt_start)?;

    // Resource directory is data directory entry 2 (index 2)
    // Each data directory entry is 8 bytes (RVA + Size)
    // Entry 0 = Export, Entry 1 = Import, Entry 2 = Resource
    let data_dir_base = match opt_magic {
        0x10B => opt_start + 96,   // PE32
        0x20B => opt_start + 112,  // PE32+
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    // Resource directory is entry index 2: offset = base + 2*8 = base + 16
    let rsrc_dir_offset = data_dir_base + 16;
    if rsrc_dir_offset + 8 > data.len() {
        return Err("No resource data directory entry".to_string());
    }

    let rsrc_rva = read_u32(data, rsrc_dir_offset)? as usize;
    let rsrc_size = read_u32(data, rsrc_dir_offset + 4)? as usize;

    if rsrc_rva == 0 || rsrc_size == 0 {
        return Err("No resource directory".to_string());
    }

    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let rsrc_file_offset = rva_to_offset(rsrc_rva, &sections)
        .ok_or_else(|| "Cannot resolve resource RVA to file offset".to_string())?;

    // Parse the top-level resource directory table
    let resources = parse_rsrc_directory_top(data, rsrc_file_offset, rsrc_file_offset, &sections)?;

    if resources.is_empty() {
        return Ok("No resources found in PE binary.".to_string());
    }

    let total_entries: usize = resources.iter().map(|r| r.entries.len()).sum();

    let mut out = String::new();
    out.push_str("=== PE Resource Analysis ===\n\n");
    out.push_str(&format!("Resource types: {}\n", resources.len()));
    out.push_str(&format!("Total resources: {}\n\n", total_entries));

    // Collect counts and parse special types
    let mut cursor_count = 0usize;
    let mut bitmap_count = 0usize;
    let mut icon_count = 0usize;
    let mut menu_count = 0usize;
    let mut dialog_count = 0usize;
    let mut string_table_blocks = 0usize;
    let mut total_strings = 0usize;
    let mut version_info_text = String::new();
    let mut manifest_text = String::new();
    let mut all_strings: Vec<String> = Vec::new();

    for res in &resources {
        match res.type_id {
            1 => cursor_count += res.entries.len(),
            2 => bitmap_count += res.entries.len(),
            3 => icon_count += res.entries.len(),
            4 => menu_count += res.entries.len(),
            5 => dialog_count += res.entries.len(),
            6 => {
                string_table_blocks += res.entries.len();
                for entry in &res.entries {
                    if let Some(offset) = rva_to_offset(entry.rva, &sections) {
                        let strings = parse_string_table_block(data, offset, entry.size);
                        total_strings += strings.len();
                        all_strings.extend(strings);
                    }
                }
            }
            12 => cursor_count += res.entries.len(),
            14 => icon_count += res.entries.len(),
            16 => {
                for entry in &res.entries {
                    if let Some(offset) = rva_to_offset(entry.rva, &sections) {
                        version_info_text = parse_version_info(data, offset, entry.size);
                    }
                }
            }
            24 => {
                for entry in &res.entries {
                    if let Some(offset) = rva_to_offset(entry.rva, &sections) {
                        let end = (offset + entry.size).min(data.len());
                        manifest_text = String::from_utf8_lossy(&data[offset..end]).trim().to_string();
                    }
                }
            }
            _ => {}
        }
    }

    if !version_info_text.is_empty() {
        out.push_str(&format!("── Version Info ──\n{}\n", version_info_text));
    }

    if !manifest_text.is_empty() {
        out.push_str("── Manifest ──\n");
        for line in manifest_text.lines() {
            out.push_str(&format!("  {}\n", line));
        }
        out.push('\n');
    }

    if !all_strings.is_empty() {
        out.push_str(&format!(
            "── String Tables ({} blocks, {} strings) ──\n",
            string_table_blocks, total_strings
        ));
        for (i, s) in all_strings.iter().enumerate().take(200) {
            out.push_str(&format!("  [{}] \"{}\"\n", i, s));
        }
        if all_strings.len() > 200 {
            out.push_str(&format!("  ... and {} more\n", all_strings.len() - 200));
        }
        out.push('\n');
    }

    if dialog_count > 0 {
        out.push_str(&format!("── Dialogs: {}\n", dialog_count));
    }
    if menu_count > 0 {
        out.push_str(&format!("── Menus: {}\n", menu_count));
    }
    if icon_count > 0 {
        out.push_str(&format!("── Icons: {}\n", icon_count));
    }
    if bitmap_count > 0 {
        out.push_str(&format!("── Bitmaps: {}\n", bitmap_count));
    }
    if cursor_count > 0 {
        out.push_str(&format!("── Cursors: {}\n", cursor_count));
    }

    for res in &resources {
        match res.type_id {
            1 | 2 | 3 | 4 | 5 | 6 | 12 | 14 | 16 | 24 => {}
            _ => {
                let name = res.type_name.as_deref()
                    .unwrap_or(resource_type_name(res.type_id));
                out.push_str(&format!(
                    "── {} (type {}): {}\n",
                    name, res.type_id, res.entries.len()
                ));
            }
        }
    }

    out.push_str("\n=== Summary ===\n");
    if total_strings > 0 {
        out.push_str(&format!("  Strings: {} (potential UI labels and messages)\n", total_strings));
    }
    if dialog_count > 0 {
        out.push_str(&format!("  Dialogs: {} (application forms/windows)\n", dialog_count));
    }
    if menu_count > 0 {
        out.push_str(&format!("  Menus: {} (menu structures)\n", menu_count));
    }
    if icon_count > 0 {
        out.push_str(&format!("  Icons: {}\n", icon_count));
    }
    if bitmap_count > 0 {
        out.push_str(&format!("  Bitmaps: {}\n", bitmap_count));
    }

    Ok(out)
}

/// Parse top-level resource directory: each entry is a resource type
fn parse_rsrc_directory_top(
    data: &[u8],
    dir_offset: usize,
    rsrc_base: usize,
    sections: &[Section],
) -> Result<Vec<ResourceInfo>, String> {
    if dir_offset + 16 > data.len() {
        return Err("Truncated resource directory".to_string());
    }

    let num_named = read_u16(data, dir_offset + 12)? as usize;
    let num_id = read_u16(data, dir_offset + 14)? as usize;
    let total = num_named + num_id;

    let mut resources = Vec::new();
    let entries_start = dir_offset + 16;

    for i in 0..total {
        let entry_offset = entries_start + i * 8;
        if entry_offset + 8 > data.len() {
            break;
        }

        let name_or_id = read_u32(data, entry_offset)?;
        let offset_val = read_u32(data, entry_offset + 4)?;

        let (type_id, type_name) = if name_or_id & 0x8000_0000 != 0 {
            let name_offset = (name_or_id & 0x7FFF_FFFF) as usize;
            let name = read_rsrc_name(data, rsrc_base + name_offset);
            (0, Some(name))
        } else {
            (name_or_id, None)
        };

        let mut entries = Vec::new();
        if offset_val & 0x8000_0000 != 0 {
            let subdir_offset = rsrc_base + (offset_val & 0x7FFF_FFFF) as usize;
            collect_rsrc_data_entries(data, subdir_offset, rsrc_base, sections, &mut entries, 0);
        } else {
            let data_entry_offset = rsrc_base + offset_val as usize;
            if let Some(entry) = read_rsrc_data_entry(data, data_entry_offset) {
                entries.push(entry);
            }
        }

        resources.push(ResourceInfo {
            type_id,
            type_name,
            entries,
        });
    }

    Ok(resources)
}

/// Recursively collect all leaf data entries from a resource directory subtree
fn collect_rsrc_data_entries(
    data: &[u8],
    dir_offset: usize,
    rsrc_base: usize,
    sections: &[Section],
    out: &mut Vec<ResourceDataEntry>,
    depth: usize,
) {
    if depth > 16 {
        return;
    }
    if dir_offset + 16 > data.len() {
        return;
    }

    let num_named = match read_u16(data, dir_offset + 12) {
        Ok(v) => v as usize,
        Err(_) => return,
    };
    let num_id = match read_u16(data, dir_offset + 14) {
        Ok(v) => v as usize,
        Err(_) => return,
    };
    let total = num_named + num_id;
    let entries_start = dir_offset + 16;

    for i in 0..total {
        let entry_offset = entries_start + i * 8;
        if entry_offset + 8 > data.len() {
            break;
        }

        let offset_val = match read_u32(data, entry_offset + 4) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if offset_val & 0x8000_0000 != 0 {
            let sub_offset = rsrc_base + (offset_val & 0x7FFF_FFFF) as usize;
            if sub_offset != dir_offset && sub_offset < data.len() {
                collect_rsrc_data_entries(data, sub_offset, rsrc_base, sections, out, depth + 1);
            }
        } else {
            let data_entry_offset = rsrc_base + offset_val as usize;
            if let Some(entry) = read_rsrc_data_entry(data, data_entry_offset) {
                out.push(entry);
            }
        }
    }
}

/// Read a resource data entry (16 bytes): RVA(4), Size(4), CodePage(4), Reserved(4)
fn read_rsrc_data_entry(data: &[u8], offset: usize) -> Option<ResourceDataEntry> {
    if offset + 16 > data.len() {
        return None;
    }
    let rva = read_u32(data, offset).ok()? as usize;
    let size = read_u32(data, offset + 4).ok()? as usize;
    Some(ResourceDataEntry { rva, size })
}

/// Read a resource directory string (length-prefixed UTF-16LE)
fn read_rsrc_name(data: &[u8], offset: usize) -> String {
    if offset + 2 > data.len() {
        return String::new();
    }
    let len = match read_u16(data, offset) {
        Ok(v) => v as usize,
        Err(_) => return String::new(),
    };
    let start = offset + 2;
    let end = (start + len * 2).min(data.len());
    read_utf16le(data, start, end)
}

/// Parse a string table block: 16 length-prefixed UTF-16LE strings
fn parse_string_table_block(data: &[u8], offset: usize, size: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let end = (offset + size).min(data.len());
    let mut pos = offset;

    for _ in 0..16 {
        if pos + 2 > end {
            break;
        }
        let len = match read_u16(data, pos) {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        pos += 2;

        if len == 0 {
            continue;
        }

        let str_end = (pos + len * 2).min(end);
        if str_end > pos {
            let s = read_utf16le(data, pos, str_end);
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                strings.push(trimmed.to_string());
            }
        }
        pos = (pos + len * 2).max(pos);
    }

    strings
}

/// Parse VS_VERSION_INFO structure
fn parse_version_info(data: &[u8], offset: usize, size: usize) -> String {
    let end = (offset + size).min(data.len());
    if offset + 6 > end {
        return String::new();
    }

    let _w_length = match read_u16(data, offset) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let w_value_length = match read_u16(data, offset + 2) {
        Ok(v) => v as usize,
        Err(_) => return String::new(),
    };
    let _w_type = match read_u16(data, offset + 4) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    // Read key string (UTF-16LE, null-terminated) starting at offset+6
    let mut pos = offset + 6;
    let key_start = pos;
    while pos + 1 < end {
        let ch = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if ch == 0 {
            break;
        }
    }
    let key = read_utf16le(data, key_start, pos.saturating_sub(2));

    // Align to 4-byte boundary
    pos = align4(pos);

    let mut out = String::new();

    if key == "VS_VERSION_INFO" && w_value_length >= 52 && pos + 52 <= end {
        let sig = read_u32(data, pos).unwrap_or(0);

        if sig == 0xFEEF04BD {
            let file_ver_ms = read_u32(data, pos + 8).unwrap_or(0);
            let file_ver_ls = read_u32(data, pos + 12).unwrap_or(0);
            let prod_ver_ms = read_u32(data, pos + 16).unwrap_or(0);
            let prod_ver_ls = read_u32(data, pos + 20).unwrap_or(0);

            let file_ver = format!(
                "{}.{}.{}.{}",
                file_ver_ms >> 16, file_ver_ms & 0xFFFF,
                file_ver_ls >> 16, file_ver_ls & 0xFFFF
            );
            let prod_ver = format!(
                "{}.{}.{}.{}",
                prod_ver_ms >> 16, prod_ver_ms & 0xFFFF,
                prod_ver_ls >> 16, prod_ver_ls & 0xFFFF
            );

            out.push_str(&format!("  File Version: {}\n", file_ver));
            out.push_str(&format!("  Product Version: {}\n", prod_ver));
        }

        pos += w_value_length;
        pos = align4(pos);
    }

    // Parse children (StringFileInfo / VarFileInfo)
    let string_values = parse_version_children(data, pos, end, 0);
    for (k, v) in &string_values {
        out.push_str(&format!("  {}: {}\n", k, v));
    }

    out
}

/// Parse StringFileInfo children to extract key-value pairs
fn parse_version_children(data: &[u8], start: usize, end: usize, depth: usize) -> Vec<(String, String)> {
    if depth > 16 {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut pos = start;

    while pos + 6 < end {
        let child_length = match read_u16(data, pos) {
            Ok(v) => v as usize,
            Err(_) => break,
        };

        if child_length == 0 || pos + child_length > end {
            break;
        }

        let child_end = pos + child_length;
        let value_length = match read_u16(data, pos + 2) {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        let child_type = match read_u16(data, pos + 4) {
            Ok(v) => v,
            Err(_) => break,
        };

        // Read key
        let mut key_pos = pos + 6;
        let key_start = key_pos;
        while key_pos + 1 < child_end {
            let ch = u16::from_le_bytes([data[key_pos], data[key_pos + 1]]);
            key_pos += 2;
            if ch == 0 {
                break;
            }
        }
        let child_key = read_utf16le(data, key_start, key_pos.saturating_sub(2));

        let val_pos = align4(key_pos);

        if child_key == "StringFileInfo" || child_key == "VarFileInfo" {
            let sub_results = parse_version_children(data, val_pos, child_end, depth + 1);
            results.extend(sub_results);
        } else if value_length > 0 && child_type == 1 {
            // Text value (UTF-16LE)
            let val_end = (val_pos + value_length * 2).min(child_end);
            if val_pos < val_end {
                let value = read_utf16le(data, val_pos, val_end);
                let value = value.trim_end_matches('\0').trim().to_string();
                if !value.is_empty() && !child_key.is_empty() {
                    results.push((child_key, value));
                }
            }
        } else if child_key.len() == 8 && child_key.chars().all(|c| c.is_ascii_hexdigit()) {
            // StringTable entry (codepage+language ID like "040904B0")
            let sub_results = parse_version_children(data, val_pos, child_end, depth + 1);
            results.extend(sub_results);
        }

        pos = align4(child_end);
        if pos <= start {
            break;
        }
    }

    results
}

// ── 5. pe_debug ───────────────────────────────────────────────────

pub fn pe_debug(graph: &mut Graph, target: &str) -> String {
    ensure_pe_binary_node(graph, target, "pe_debug");
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match parse_pe_debug_info(&data) {
        Ok(info) => info,
        Err(e) => format!("PE parse error: {e}"),
    }
}

fn parse_pe_debug_info(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew offset".to_string());
    }
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    let opt_magic = read_u16(data, opt_start)?;
    let debug_dir_rva_offset = match opt_magic {
        0x10B => opt_start + 144,  // PE32: debug data dir RVA
        0x20B => opt_start + 160,  // PE32+: debug data dir RVA
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    if debug_dir_rva_offset + 8 > data.len() {
        return Err("No debug data directory".to_string());
    }

    let debug_rva = read_u32(data, debug_dir_rva_offset)? as usize;
    let debug_size = read_u32(data, debug_dir_rva_offset + 4)? as usize;

    if debug_rva == 0 || debug_size == 0 {
        return Err("No debug directory present".to_string());
    }

    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let debug_offset = rva_to_offset(debug_rva, &sections)
        .ok_or_else(|| "Cannot resolve debug directory RVA to file offset".to_string())?;

    let entry_count = debug_size / 28;
    if entry_count == 0 {
        return Err("Debug directory is empty".to_string());
    }

    struct DebugEntry {
        type_id: u32,
        timestamp: u32,
        major_version: u16,
        minor_version: u16,
        size_of_data: u32,
        pointer_to_raw_data: u32,
    }

    let mut build_timestamp: Option<u32> = None;
    let mut entries: Vec<DebugEntry> = Vec::new();

    for i in 0..entry_count {
        let base = debug_offset + i * 28;
        if base + 28 > data.len() {
            break;
        }
        let timestamp = read_u32(data, base + 4)?;
        let major_version = read_u16(data, base + 8)?;
        let minor_version = read_u16(data, base + 10)?;
        let type_id = read_u32(data, base + 12)?;
        let size_of_data = read_u32(data, base + 16)?;
        let pointer_to_raw_data = read_u32(data, base + 24)?;

        if build_timestamp.is_none() && timestamp != 0 {
            build_timestamp = Some(timestamp);
        }

        entries.push(DebugEntry {
            type_id,
            timestamp,
            major_version,
            minor_version,
            size_of_data,
            pointer_to_raw_data,
        });
    }

    let mut out = String::new();
    out.push_str("=== PE Debug Info ===\n\n");

    if let Some(ts) = build_timestamp {
        out.push_str(&format!("Build timestamp: {}\n", format_unix_timestamp(ts)));
    }
    out.push_str(&format!("Debug entries: {}\n", entries.len()));

    for entry in &entries {
        let type_name = pe_debug_type_name(entry.type_id);
        out.push_str(&format!("\n\u{2500}\u{2500} {} \u{2500}\u{2500}\n", type_name));

        if entry.major_version != 0 || entry.minor_version != 0 {
            out.push_str(&format!("  Version: {}.{}\n", entry.major_version, entry.minor_version));
        }
        if entry.timestamp != 0 && Some(entry.timestamp) != build_timestamp {
            out.push_str(&format!("  Timestamp: {}\n", format_unix_timestamp(entry.timestamp)));
        }

        // CodeView (type 2)
        if entry.type_id == 2 && entry.pointer_to_raw_data != 0 && entry.size_of_data >= 24 {
            let ptr = entry.pointer_to_raw_data as usize;
            if ptr + 4 <= data.len() {
                let sig = &data[ptr..ptr + 4];
                if sig == b"RSDS" && ptr + 24 <= data.len() {
                    let guid = format_pe_guid(&data[ptr + 4..ptr + 20]);
                    let age = read_u32(data, ptr + 20).unwrap_or(0);
                    let pdb_path = read_cstring(data, ptr + 24);
                    out.push_str(&format!("  PDB: {}\n", pdb_path));
                    out.push_str(&format!("  GUID: {}\n", guid));
                    out.push_str(&format!("  Age: {}\n", age));
                } else if sig == b"NB10" && ptr + 16 <= data.len() {
                    let nb_timestamp = read_u32(data, ptr + 8).unwrap_or(0);
                    let age = read_u32(data, ptr + 12).unwrap_or(0);
                    let pdb_path = read_cstring(data, ptr + 16);
                    out.push_str(&format!("  PDB: {}\n", pdb_path));
                    out.push_str(&format!("  Timestamp: {}\n", format_unix_timestamp(nb_timestamp)));
                    out.push_str(&format!("  Age: {}\n", age));
                } else {
                    let sig_str: String = sig.iter().map(|&b| {
                        if (0x20..=0x7E).contains(&b) { b as char } else { '.' }
                    }).collect();
                    out.push_str(&format!("  Signature: {} (unknown)\n", sig_str));
                }
            }
        }

        // VC Feature (type 12)
        if entry.type_id == 12 && entry.pointer_to_raw_data != 0 {
            let ptr = entry.pointer_to_raw_data as usize;
            if ptr + 20 <= data.len() {
                let pre_vc11 = read_u32(data, ptr).unwrap_or(0);
                let c_cpp = read_u32(data, ptr + 4).unwrap_or(0);
                let gs = read_u32(data, ptr + 8).unwrap_or(0);
                let sdl = read_u32(data, ptr + 12).unwrap_or(0);
                let guard_n = read_u32(data, ptr + 16).unwrap_or(0);
                out.push_str(&format!("  Pre-VC++ 11.00: {}\n", pre_vc11));
                out.push_str(&format!("  C/C++: {}\n", c_cpp));
                out.push_str(&format!("  /GS: {}\n", gs));
                out.push_str(&format!("  /sdl: {}\n", sdl));
                out.push_str(&format!("  guardN: {}\n", guard_n));
            }
        }

        // POGO (type 13)
        if entry.type_id == 13 && entry.pointer_to_raw_data != 0 {
            out.push_str(&format!("  Data size: {} bytes\n", entry.size_of_data));
        }

        // Repro (type 16) -- reproducible build hash
        if entry.type_id == 16 && entry.pointer_to_raw_data != 0 {
            let ptr = entry.pointer_to_raw_data as usize;
            let end = ptr + entry.size_of_data as usize;
            if end <= data.len() && entry.size_of_data >= 4 {
                let hash_len = read_u32(data, ptr).unwrap_or(0) as usize;
                if hash_len > 0 && ptr + 4 + hash_len <= data.len() {
                    let hash_bytes = &data[ptr + 4..ptr + 4 + hash_len];
                    let hash_hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    out.push_str(&format!("  Hash: {}\n", hash_hex));
                }
            }
        }
    }

    Ok(out)
}

fn pe_debug_type_name(type_id: u32) -> String {
    match type_id {
        0 => "Unknown".to_string(),
        1 => "COFF".to_string(),
        2 => "CodeView".to_string(),
        3 => "FPO".to_string(),
        4 => "Misc".to_string(),
        5 => "Exception".to_string(),
        6 => "Fixup".to_string(),
        7 => "OMAP_TO_SRC".to_string(),
        8 => "OMAP_FROM_SRC".to_string(),
        9 => "Borland".to_string(),
        10 => "Reserved10".to_string(),
        11 => "CLSID".to_string(),
        12 => "VC Feature".to_string(),
        13 => "POGO".to_string(),
        14 => "ILTCG".to_string(),
        16 => "Repro".to_string(),
        20 => "ExDllCharacteristics".to_string(),
        _ => format!("Type({})", type_id),
    }
}

fn format_pe_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "invalid".to_string();
    }
    // GUID: Data1 (LE u32), Data2 (LE u16), Data3 (LE u16), Data4 (8 bytes big-endian)
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn format_unix_timestamp(ts: u32) -> String {
    let mut remaining = ts as i64;

    let secs = remaining % 60;
    remaining /= 60;
    let mins = remaining % 60;
    remaining /= 60;
    let hours = remaining % 24;
    remaining /= 24;

    let mut days = remaining;
    let mut year: i64 = 1970;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month: usize = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i;
            break;
        }
        days -= md;
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month + 1, days + 1, hours, mins, secs
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── 6. pe_sections ──────────────────────────────────────────────────

pub fn pe_sections(graph: &mut Graph, target: &str) -> String {
    ensure_pe_binary_node(graph, target, "pe_sections");
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Auto-flag the binary as packed if any section has entropy > 7.0,
    // and detect overlay (post-section trailing data) in the same pass.
    flag_packed_and_overlay(graph, target, &data);

    match parse_pe_sections_info(&data) {
        Ok(info) => info,
        Err(e) => format!("PE parse error: {e}"),
    }
}

/// Walk the PE section table, compute per-section entropy, and tag
/// the PE binary node with `attrs["packed"] = "true"` if any section
/// crosses the 7.0 bits/byte threshold (indicates UPX-style packing
/// or section-level encryption). Also runs the overlay detector and
/// registers an Overlay node + binary→overlay edge if found.
fn flag_packed_and_overlay(graph: &mut Graph, target: &str, data: &[u8]) {
    let bin_id = format!("pe:{target}");
    if let Some(overlay) = crate::actions::overlay::detect_pe_overlay(data) {
        let overlay_id = format!("overlay:{target}:{:x}", overlay.offset);
        let off = format!("{:#x}", overlay.offset);
        let size = overlay.size.to_string();
        let entropy = format!("{:.3}", overlay.entropy);
        graph.ensure_typed_node(&overlay_id, EntityKind::Overlay, &[
            ("source_binary", target),
            ("offset", &off),
            ("size", &size),
            ("entropy", &entropy),
            ("kind", overlay.kind.as_str()),
        ]);
        graph.add_edge(&bin_id, &overlay_id);
    }

    // Quick section-entropy scan: if any has H > 7.0, mark the binary.
    if data.len() < 0x40 || &data[..2] != b"MZ" { return; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return; }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;
    let mut max_entropy = 0.0_f64;
    for i in 0..n_sections.min(64) {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { break; }
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as usize;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
        if raw_size == 0 || raw_off >= data.len() { continue; }
        let end = (raw_off + raw_size).min(data.len());
        let h = crate::actions::overlay::shannon_entropy(&data[raw_off..end]);
        if h > max_entropy { max_entropy = h; }
    }
    if let Some(node) = graph.nodes.get_mut(&bin_id) {
        node.attrs.insert("max_section_entropy".into(), format!("{max_entropy:.3}"));
        if max_entropy > 7.0 {
            node.attrs.insert("packed".into(), "true".into());
        }
    }
}

fn parse_pe_sections_info(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew offset".to_string());
    }
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    let opt_magic = read_u16(data, opt_start)?;
    let image_base: u64 = match opt_magic {
        0x10B => read_u32(data, opt_start + 28)? as u64, // PE32: ImageBase at +28
        0x20B => read_u64(data, opt_start + 24)?,         // PE64: ImageBase at +24
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    let sections_start = opt_start + optional_header_size;

    let mut out = String::new();
    out.push_str("=== PE Sections ===\n\n");
    out.push_str(&format!("Sections: {}\n", num_sections));
    out.push_str(&format!("Image base: 0x{:08X}\n\n", image_base));

    let mut has_high_entropy = false;

    for i in 0..num_sections {
        let offset = sections_start + i * 40;
        if offset + 40 > data.len() {
            break;
        }

        // Section name: 8 bytes, null-padded
        let name_bytes = &data[offset..offset + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name: String = name_bytes[..name_end]
            .iter()
            .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
            .collect();

        let virtual_size = read_u32(data, offset + 8)?;
        let virtual_address = read_u32(data, offset + 12)?;
        let raw_size = read_u32(data, offset + 16)?;
        let raw_offset = read_u32(data, offset + 20)?;
        let characteristics = read_u32(data, offset + 36)?;

        // Calculate Shannon entropy of the section data
        let entropy = if raw_size > 0 && (raw_offset as usize) < data.len() {
            let start = raw_offset as usize;
            let end = (start + raw_size as usize).min(data.len());
            if start < end {
                shannon_entropy(&data[start..end])
            } else {
                0.0
            }
        } else {
            0.0
        };

        if entropy > 7.0 {
            has_high_entropy = true;
        }

        // Decode characteristics flags
        let mut flags = Vec::new();
        if characteristics & 0x00000020 != 0 { flags.push("CODE"); }
        if characteristics & 0x00000040 != 0 { flags.push("INIT_DATA"); }
        if characteristics & 0x00000080 != 0 { flags.push("UNINIT_DATA"); }
        if characteristics & 0x02000000 != 0 { flags.push("DISCARDABLE"); }
        if characteristics & 0x10000000 != 0 { flags.push("SHARED"); }
        if characteristics & 0x20000000 != 0 { flags.push("EXEC"); }
        if characteristics & 0x40000000 != 0 { flags.push("READ"); }
        if characteristics & 0x80000000 != 0 { flags.push("WRITE"); }

        let flags_str = if flags.is_empty() {
            String::from("NONE")
        } else {
            flags.join(", ")
        };

        out.push_str(&format!(
            "  {:<10}VA:0x{:<8X} Size:{:<10} Raw:{:<10} Entropy:{:<6.2} [{}]\n",
            name, virtual_address, utils::format_number(virtual_size as usize),
            utils::format_number(raw_size as usize), entropy, flags_str
        ));
    }

    out.push('\n');
    if has_high_entropy {
        out.push_str("  \u{26a0} High-entropy section detected (possible packing/encryption)\n");
    } else {
        out.push_str("  \u{26a0} No high-entropy sections detected (no packing/encryption)\n");
    }

    Ok(out)
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

// ── 7. dotnet_meta ──────────────────────────────────────────────────

pub fn dotnet_meta(graph: &mut Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Register the .NET-specific binary as both a PeBinary (it's still a PE)
    // and a DotnetAssembly (with managed-code attrs). Two-tier registration
    // lets you query via either kind: `pagerank --type pe` includes .NET
    // assemblies; `--type assembly` filters to just managed.
    ensure_pe_binary_node(graph, target, "dotnet_meta");
    let asm_id = format!("asm:{target}");
    graph.ensure_typed_node(&asm_id, EntityKind::DotnetAssembly, &[
        ("path", target),
    ]);
    graph.add_edge(&format!("pe:{target}"), &asm_id);

    match parse_dotnet_metadata_with_methods(&data) {
        Ok((info, methods)) => {
            // 5.15.2: register each MethodDef as a BinaryFunction node
            // hanging off the DotnetAssembly. Reuses the BinaryFunction
            // EntityKind via attrs["binary_format"]="dotnet".
            for (i, (name, rva)) in methods.iter().enumerate() {
                let func_id = format!("bin_func:dotnet:{target}::{i}");
                let rva_str = format!("{:#x}", rva);
                graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                    ("name", name),
                    ("binary_format", "dotnet"),
                    ("kind_detail", "method"),
                    ("rva", &rva_str),
                ]);
                graph.add_edge(&asm_id, &func_id);
            }
            info
        }
        Err(e) => format!("Not a .NET assembly or parse error: {e}"),
    }
}

/// Parse PE headers and locate the CLR runtime header data directory.
fn find_clr_header(data: &[u8]) -> Result<(usize, Vec<Section>, bool), String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew offset".to_string());
    }
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    let opt_magic = read_u16(data, opt_start)?;

    // CLR Runtime Header is data directory entry 14
    // PE32: data dirs start at opt_start + 96, entry 14 => 96 + 14*8 = 96 + 112 = 208
    // PE64: data dirs start at opt_start + 112, entry 14 => 112 + 14*8 = 112 + 112 = 224
    let (clr_dir_offset, is_pe64) = match opt_magic {
        0x10B => (opt_start + 208, false),
        0x20B => (opt_start + 224, true),
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    if clr_dir_offset + 8 > data.len() {
        return Err("No CLR data directory entry (not a .NET binary)".to_string());
    }

    let clr_rva = read_u32(data, clr_dir_offset)? as usize;
    let clr_size = read_u32(data, clr_dir_offset + 4)? as usize;

    if clr_rva == 0 || clr_size == 0 {
        return Err("No CLR runtime header (not a .NET binary)".to_string());
    }

    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let clr_offset = rva_to_offset(clr_rva, &sections)
        .ok_or_else(|| "Cannot resolve CLR header RVA".to_string())?;

    Ok((clr_offset, sections, is_pe64))
}

fn parse_dotnet_metadata(data: &[u8]) -> Result<String, String> {
    let (out, _methods) = parse_dotnet_metadata_with_methods(data)?;
    Ok(out)
}

fn parse_dotnet_metadata_with_methods(data: &[u8]) -> Result<(String, Vec<(String, u64)>), String> {
    let mut method_records: Vec<(String, u64)> = Vec::new();
    let (clr_offset, sections, _is_pe64) = find_clr_header(data)?;

    // Read CLR header (72 bytes)
    if clr_offset + 72 > data.len() {
        return Err("Truncated CLR header".to_string());
    }

    let cb = read_u32(data, clr_offset)?;
    let major_runtime = read_u16(data, clr_offset + 4)?;
    let minor_runtime = read_u16(data, clr_offset + 6)?;
    let metadata_rva = read_u32(data, clr_offset + 8)? as usize;
    let metadata_size = read_u32(data, clr_offset + 12)? as usize;
    let flags = read_u32(data, clr_offset + 16)?;
    let entry_point_token = read_u32(data, clr_offset + 20)?;

    if metadata_rva == 0 || metadata_size == 0 {
        return Err("No metadata in CLR header".to_string());
    }

    let metadata_offset = rva_to_offset(metadata_rva, &sections)
        .ok_or_else(|| "Cannot resolve metadata RVA".to_string())?;

    if metadata_offset + 16 > data.len() {
        return Err("Truncated metadata root".to_string());
    }

    // Check BSJB signature
    let signature = read_u32(data, metadata_offset)?;
    if signature != 0x424A5342 {
        return Err(format!("Invalid metadata signature: 0x{:08X} (expected BSJB = 0x424A5342)", signature));
    }

    let _meta_major = read_u16(data, metadata_offset + 4)?;
    let _meta_minor = read_u16(data, metadata_offset + 6)?;
    let _reserved = read_u32(data, metadata_offset + 8)?;
    let version_length = read_u32(data, metadata_offset + 12)? as usize;

    let version_start = metadata_offset + 16;
    if version_start + version_length > data.len() {
        return Err("Truncated version string".to_string());
    }

    let version_string = read_cstring(data, version_start);

    // After version string (aligned to 4 bytes)
    let after_version = align4(version_start + version_length);
    if after_version + 4 > data.len() {
        return Err("Truncated stream header area".to_string());
    }

    let _stream_flags = read_u16(data, after_version)?;
    let num_streams = read_u16(data, after_version + 2)? as usize;

    // Parse stream headers
    struct StreamHeader {
        offset: usize,
        size: usize,
        name: String,
    }

    let mut streams: Vec<StreamHeader> = Vec::new();
    let mut pos = after_version + 4;

    for _ in 0..num_streams {
        if pos + 8 > data.len() {
            break;
        }
        let stream_offset = read_u32(data, pos)? as usize;
        let stream_size = read_u32(data, pos + 4)? as usize;
        pos += 8;

        // Read null-terminated name, aligned to 4 bytes
        let name_start = pos;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        let name = String::from_utf8_lossy(&data[name_start..pos]).to_string();
        pos += 1; // skip null
        pos = align4(pos);

        streams.push(StreamHeader {
            offset: metadata_offset + stream_offset,
            size: stream_size,
            name,
        });
    }

    // Find streams by name
    let strings_stream = streams.iter().find(|s| s.name == "#Strings");
    let us_stream = streams.iter().find(|s| s.name == "#US");
    let tilde_stream = streams.iter().find(|s| s.name == "#~" || s.name == "#-");

    // Build output
    let mut out = String::new();
    out.push_str("=== .NET Assembly Metadata ===\n\n");
    out.push_str(&format!("Runtime: v{}.{}\n", major_runtime, minor_runtime));
    out.push_str(&format!("Version: {}\n", version_string));
    out.push_str(&format!("CLR Header Size: {}\n", cb));
    out.push_str(&format!("Entry Point Token: 0x{:08X}\n", entry_point_token));

    // Decode flags
    let mut flag_strs = Vec::new();
    if flags & 0x01 != 0 { flag_strs.push("IL Only"); }
    if flags & 0x02 != 0 { flag_strs.push("32-Bit Required"); }
    if flags & 0x04 != 0 { flag_strs.push("Strong Name Signed"); }
    if flags & 0x08 != 0 { flag_strs.push("Native Entry Point"); }
    if flags & 0x10000 != 0 { flag_strs.push("32-Bit Preferred"); }
    if flag_strs.is_empty() {
        out.push_str("Flags: (none)\n");
    } else {
        out.push_str(&format!("Flags: {}\n", flag_strs.join(", ")));
    }

    out.push_str(&format!("\nStreams: {}\n",
        streams.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")));

    // Parse #~ stream for table metadata
    if let Some(tilde) = tilde_stream {
        if tilde.offset + 24 <= data.len() {
            let _tbl_reserved = read_u32(data, tilde.offset)?;
            let tbl_major = data.get(tilde.offset + 4).copied().unwrap_or(0);
            let tbl_minor = data.get(tilde.offset + 5).copied().unwrap_or(0);
            let heap_sizes = data.get(tilde.offset + 6).copied().unwrap_or(0);

            let string_idx_size: usize = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
            let _guid_idx_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
            let _blob_idx_size: usize = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

            if tilde.offset + 24 <= data.len() {
                let valid = read_u64(data, tilde.offset + 8)?;
                let _sorted = read_u64(data, tilde.offset + 16)?;

                // Count how many tables exist and read their row counts
                let mut row_counts: Vec<(usize, u32)> = Vec::new();
                let mut row_pos = tilde.offset + 24;

                for bit in 0..64u32 {
                    if valid & (1u64 << bit) != 0
                        && row_pos + 4 <= data.len() {
                            let count = read_u32(data, row_pos)?;
                            row_counts.push((bit as usize, count));
                            row_pos += 4;
                        }
                }

                let table_data_start = row_pos;

                // Table names for display
                let table_names: [&str; 64] = [
                    "Module", "TypeRef", "TypeDef", "FieldPtr", "Field",
                    "MethodPtr", "MethodDef", "ParamPtr", "Param", "InterfaceImpl",
                    "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity",
                    "ClassLayout", "FieldLayout", "StandAloneSig", "EventMap", "EventPtr",
                    "Event", "PropertyMap", "PropertyPtr", "Property", "MethodSemantics",
                    "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA",
                    "EncLog", "EncMap", "Assembly", "AssemblyProcessor", "AssemblyOS",
                    "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType",
                    "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint",
                    "Reserved45", "Reserved46", "Reserved47", "Reserved48", "Reserved49",
                    "Reserved50", "Reserved51", "Reserved52", "Reserved53", "Reserved54",
                    "Reserved55", "Reserved56", "Reserved57", "Reserved58", "Reserved59",
                    "Reserved60", "Reserved61", "Reserved62", "Reserved63",
                ];

                out.push_str(&format!("\nMetadata Tables (schema {}.{})\n", tbl_major, tbl_minor));

                // Show table row counts
                let mut total_rows: u64 = 0;
                for &(idx, count) in &row_counts {
                    let name = if idx < 64 { table_names[idx] } else { "Unknown" };
                    out.push_str(&format!("  {:2}: {:<28} {} rows\n", idx, name, count));
                    total_rows += count as u64;
                }
                out.push_str(&format!("\n  Total rows: {}\n", total_rows));

                // Helper to get row count for a table
                let get_row_count = |table_id: usize| -> u32 {
                    row_counts.iter().find(|&&(id, _)| id == table_id).map(|&(_, c)| c).unwrap_or(0)
                };

                // Now parse specific tables if #Strings is available
                if let Some(strings_s) = strings_stream {
                    let strings_data_start = strings_s.offset;
                    let strings_data_end = (strings_s.offset + strings_s.size).min(data.len());

                    let read_string_from_heap = |idx: usize| -> String {
                        let abs = strings_data_start + idx;
                        if abs >= strings_data_end {
                            return String::new();
                        }
                        read_cstring(data, abs)
                    };

                    let read_string_idx = |pos: usize| -> Result<(usize, usize), String> {
                        if string_idx_size == 4 {
                            Ok((read_u32(data, pos)? as usize, 4))
                        } else {
                            Ok((read_u16(data, pos)? as usize, 2))
                        }
                    };

                    // Table row sizes (simplified -- assumes small coded indexes where row counts < 65536)
                    fn coded_idx_size(tables: &[(usize, u32)], tag_bits: u32, table_ids: &[usize]) -> usize {
                        let max_rows = table_ids.iter()
                            .map(|&id| tables.iter().find(|&&(tid, _)| tid == id).map(|&(_, c)| c).unwrap_or(0))
                            .max()
                            .unwrap_or(0);
                        if max_rows < (1u32 << (16 - tag_bits)) { 2 } else { 4 }
                    }

                    fn simple_idx_size(tables: &[(usize, u32)], table_id: usize) -> usize {
                        let rows = tables.iter().find(|&&(id, _)| id == table_id).map(|&(_, c)| c).unwrap_or(0);
                        if rows < 65536 { 2 } else { 4 }
                    }

                    // TypeDefOrRef coded index: 2-bit tag, tables 0x02, 0x01, 0x1B
                    let typedef_or_ref_size = coded_idx_size(&row_counts, 2, &[2, 1, 27]);
                    // ResolutionScope: 2-bit tag, tables 0x00, 0x1A, 0x23, 0x01
                    let resolution_scope_size = coded_idx_size(&row_counts, 2, &[0, 26, 35, 1]);
                    // MemberRefParent: 3-bit tag
                    let member_ref_parent_size = coded_idx_size(&row_counts, 3, &[2, 1, 26, 6, 27]);

                    let field_idx_size = simple_idx_size(&row_counts, 4);
                    let method_idx_size = simple_idx_size(&row_counts, 6);
                    let param_idx_size = simple_idx_size(&row_counts, 8);

                    let blob_idx_size: usize = if heap_sizes & 0x04 != 0 { 4 } else { 2 };
                    let guid_idx_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };

                    // Row sizes for each table
                    let row_size = |table_id: usize| -> usize {
                        match table_id {
                            0 => 2 + string_idx_size + guid_idx_size * 3, // Module
                            1 => resolution_scope_size + string_idx_size * 2, // TypeRef
                            2 => 4 + string_idx_size * 2 + typedef_or_ref_size + field_idx_size + method_idx_size, // TypeDef
                            4 => 2 + string_idx_size + blob_idx_size, // Field
                            6 => 4 + 2 + 2 + string_idx_size + blob_idx_size + param_idx_size, // MethodDef
                            8 => 2 + 2 + string_idx_size, // Param
                            10 => member_ref_parent_size + string_idx_size + blob_idx_size, // MemberRef
                            35 => { // AssemblyRef
                                2 + 2 + 2 + 2 + 4 + blob_idx_size + string_idx_size * 2 + blob_idx_size
                            }
                            32 => { // Assembly
                                4 + 2 + 2 + 2 + 2 + 4 + blob_idx_size + string_idx_size * 2
                            }
                            _ => 0, // Unknown -- can't compute
                        }
                    };

                    // Calculate byte offset of each table in the table data area
                    let mut table_offsets: HashMap<usize, usize> = HashMap::new();
                    let mut tbl_pos = table_data_start;
                    for &(idx, count) in &row_counts {
                        table_offsets.insert(idx, tbl_pos);
                        let rs = row_size(idx);
                        if rs == 0 {
                            // Unknown row size -- can't advance
                            break;
                        }
                        tbl_pos += rs * count as usize;
                    }

                    // Parse TypeDef table (table 2)
                    let typedef_count = get_row_count(2);
                    if typedef_count > 0 {
                        if let Some(&typedef_offset) = table_offsets.get(&2) {
                            let rs = row_size(2);
                            if rs > 0 {
                                out.push_str(&format!("\n\u{2500}\u{2500} Types ({}) \u{2500}\u{2500}\n", typedef_count));
                                let limit = (typedef_count as usize).min(200);
                                for i in 0..limit {
                                    let row_start = typedef_offset + i * rs;
                                    if row_start + rs > data.len() { break; }

                                    // TypeDef: Flags(4) + TypeName(str) + TypeNamespace(str) + Extends(coded) + FieldList + MethodList
                                    let _type_flags = read_u32(data, row_start)?;
                                    let (name_idx, _) = read_string_idx(row_start + 4)?;
                                    let (ns_idx, _) = read_string_idx(row_start + 4 + string_idx_size)?;

                                    let type_name = read_string_from_heap(name_idx);
                                    let type_ns = read_string_from_heap(ns_idx);

                                    if type_name.is_empty() || type_name == "<Module>" {
                                        continue;
                                    }

                                    if type_ns.is_empty() {
                                        out.push_str(&format!("  {}\n", type_name));
                                    } else {
                                        out.push_str(&format!("  {}.{}\n", type_ns, type_name));
                                    }
                                }
                                if typedef_count > 200 {
                                    out.push_str(&format!("  ... and {} more\n", typedef_count - 200));
                                }
                            }
                        }
                    }

                    // Parse MethodDef table (table 6)
                    let methoddef_count = get_row_count(6);
                    if methoddef_count > 0 {
                        if let Some(&method_offset) = table_offsets.get(&6) {
                            let rs = row_size(6);
                            if rs > 0 {
                                out.push_str(&format!("\n\u{2500}\u{2500} Methods ({}) \u{2500}\u{2500}\n", methoddef_count));
                                let limit = (methoddef_count as usize).min(200);
                                for i in 0..limit {
                                    let row_start = method_offset + i * rs;
                                    if row_start + rs > data.len() { break; }

                                    // MethodDef: RVA(4) + ImplFlags(2) + Flags(2) + Name(str) + Signature(blob) + ParamList
                                    let rva = read_u32(data, row_start)? as u64;
                                    let name_pos = row_start + 4 + 2 + 2;
                                    let (name_idx, _) = read_string_idx(name_pos)?;
                                    let method_name = read_string_from_heap(name_idx);

                                    if !method_name.is_empty() {
                                        out.push_str(&format!("  {}\n", method_name));
                                        method_records.push((method_name, rva));
                                    }
                                }
                                if methoddef_count > 200 {
                                    out.push_str(&format!("  ... and {} more\n", methoddef_count - 200));
                                }
                            }
                        }
                    }

                    // Parse AssemblyRef table (table 35)
                    let asmref_count = get_row_count(35);
                    if asmref_count > 0 {
                        if let Some(&asmref_offset) = table_offsets.get(&35) {
                            let rs = row_size(35);
                            if rs > 0 {
                                out.push_str(&format!("\n\u{2500}\u{2500} Assembly References ({}) \u{2500}\u{2500}\n", asmref_count));
                                let limit = (asmref_count as usize).min(100);
                                for i in 0..limit {
                                    let row_start = asmref_offset + i * rs;
                                    if row_start + rs > data.len() { break; }

                                    // AssemblyRef: MajorVersion(2) + MinorVersion(2) + BuildNumber(2) + RevisionNumber(2) + Flags(4) + PublicKeyOrToken(blob) + Name(str) + Culture(str) + HashValue(blob)
                                    let major = read_u16(data, row_start)?;
                                    let minor = read_u16(data, row_start + 2)?;
                                    let build = read_u16(data, row_start + 4)?;
                                    let revision = read_u16(data, row_start + 6)?;

                                    let name_pos = row_start + 2 + 2 + 2 + 2 + 4 + blob_idx_size;
                                    if name_pos + string_idx_size <= data.len() {
                                        let (name_idx, _) = read_string_idx(name_pos)?;
                                        let asm_name = read_string_from_heap(name_idx);
                                        if !asm_name.is_empty() {
                                            out.push_str(&format!("  {} {}.{}.{}.{}\n",
                                                asm_name, major, minor, build, revision));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Parse TypeRef table (table 1)
                    let typeref_count = get_row_count(1);
                    if typeref_count > 0 {
                        if let Some(&typeref_offset) = table_offsets.get(&1) {
                            let rs = row_size(1);
                            if rs > 0 {
                                out.push_str(&format!("\n\u{2500}\u{2500} Type References ({}) \u{2500}\u{2500}\n", typeref_count));
                                let limit = (typeref_count as usize).min(200);
                                for i in 0..limit {
                                    let row_start = typeref_offset + i * rs;
                                    if row_start + rs > data.len() { break; }

                                    // TypeRef: ResolutionScope(coded) + TypeName(str) + TypeNamespace(str)
                                    let name_pos = row_start + resolution_scope_size;
                                    let ns_pos = name_pos + string_idx_size;

                                    if ns_pos + string_idx_size <= data.len() {
                                        let (name_idx, _) = read_string_idx(name_pos)?;
                                        let (ns_idx, _) = read_string_idx(ns_pos)?;
                                        let type_name = read_string_from_heap(name_idx);
                                        let type_ns = read_string_from_heap(ns_idx);

                                        if !type_name.is_empty() {
                                            if type_ns.is_empty() {
                                                out.push_str(&format!("  {}\n", type_name));
                                            } else {
                                                out.push_str(&format!("  {}.{}\n", type_ns, type_name));
                                            }
                                        }
                                    }
                                }
                                if typeref_count > 200 {
                                    out.push_str(&format!("  ... and {} more\n", typeref_count - 200));
                                }
                            }
                        }
                    }
                }

                // Read #US (User Strings) stream
                if let Some(us_s) = us_stream {
                    let us_start = us_s.offset;
                    let us_end = (us_s.offset + us_s.size).min(data.len());

                    let mut user_strings: Vec<String> = Vec::new();
                    let mut us_pos = us_start + 1; // skip first null byte

                    while us_pos < us_end {
                        // Each entry: compressed length, then UTF-16LE data
                        let (blob_len, len_bytes) = read_compressed_uint(data, us_pos);
                        us_pos += len_bytes;

                        if blob_len == 0 || us_pos + blob_len > us_end {
                            break;
                        }

                        // The blob is UTF-16LE, last byte may be a terminal flag byte
                        let str_len = if blob_len > 0 { blob_len - 1 } else { 0 }; // strip terminal byte
                        if str_len >= 2 {
                            let s = read_utf16le(data, us_pos, us_pos + (str_len & !1));
                            let trimmed = s.trim().to_string();
                            if !trimmed.is_empty() && trimmed.len() >= 2 {
                                user_strings.push(trimmed);
                            }
                        }

                        us_pos += blob_len;
                    }

                    if !user_strings.is_empty() {
                        out.push_str(&format!("\n\u{2500}\u{2500} User Strings ({}) \u{2500}\u{2500}\n", user_strings.len()));
                        for s in user_strings.iter().take(200) {
                            out.push_str(&format!("  \"{}\"\n", truncate_str(s, 120)));
                        }
                        if user_strings.len() > 200 {
                            out.push_str(&format!("  ... and {} more\n", user_strings.len() - 200));
                        }
                    }
                }
            }
        }
    }

    Ok((out, method_records))
}

/// Read a compressed unsigned integer from .NET metadata (1, 2, or 4 bytes).
/// Returns (value, bytes_consumed).
fn read_compressed_uint(data: &[u8], offset: usize) -> (usize, usize) {
    if offset >= data.len() {
        return (0, 1);
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        // 1 byte: 0xxxxxxx
        (first as usize, 1)
    } else if first & 0xC0 == 0x80 {
        // 2 bytes: 10xxxxxx xxxxxxxx
        if offset + 1 >= data.len() {
            return (0, 1);
        }
        let val = ((first as usize & 0x3F) << 8) | data[offset + 1] as usize;
        (val, 2)
    } else if first & 0xE0 == 0xC0 {
        // 4 bytes: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if offset + 3 >= data.len() {
            return (0, 1);
        }
        let val = ((first as usize & 0x1F) << 24)
            | ((data[offset + 1] as usize) << 16)
            | ((data[offset + 2] as usize) << 8)
            | (data[offset + 3] as usize);
        (val, 4)
    } else {
        (0, 1)
    }
}

// ── 8. binary_diff ─────────────────────────────────────────────────

pub fn binary_diff(_graph: &mut Graph, target: &str) -> String {
    let parts: Vec<&str> = target.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return "Usage: binary-diff <file1> <file2>\nCompare two PE binaries.".to_string();
    }

    let path1 = Path::new(parts[0]);
    let path2 = Path::new(parts[1]);

    if !path1.exists() {
        return format!("File not found: {}", parts[0]);
    }
    if !path2.exists() {
        return format!("File not found: {}", parts[1]);
    }

    if let Ok(m) = fs::metadata(path1) {
        if m.len() > MAX_BINARY_SIZE {
            return format!("File too large ({} bytes, max 256 MB): {}", m.len(), parts[0]);
        }
    }
    if let Ok(m) = fs::metadata(path2) {
        if m.len() > MAX_BINARY_SIZE {
            return format!("File too large ({} bytes, max 256 MB): {}", m.len(), parts[1]);
        }
    }

    let data1 = match fs::read(path1) {
        Ok(d) => d,
        Err(e) => return format!("Error reading {}: {e}", parts[0]),
    };
    let data2 = match fs::read(path2) {
        Ok(d) => d,
        Err(e) => return format!("Error reading {}: {e}", parts[1]),
    };

    let fname1 = path1.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| parts[0].to_string());
    let fname2 = path2.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| parts[1].to_string());

    let mut out = String::new();
    out.push_str("=== Binary Diff ===\n\n");

    let size1 = data1.len();
    let size2 = data2.len();
    out.push_str(&format!("File 1: {} ({})\n", fname1, format_file_size(size1)));
    out.push_str(&format!("File 2: {} ({})\n", fname2, format_file_size(size2)));

    let delta = size2 as i64 - size1 as i64;
    let delta_str = if delta >= 0 {
        format!("+{}", format_file_size(delta as usize))
    } else {
        format!("-{}", format_file_size((-delta) as usize))
    };
    out.push_str(&format!("Size delta: {}\n\n", delta_str));

    // Compare imports
    let imports1 = parse_pe_imports_structured(&data1);
    let imports2 = parse_pe_imports_structured(&data2);

    out.push_str("\u{2500}\u{2500} Import Changes \u{2500}\u{2500}\n");
    if let (Ok(imp1), Ok(imp2)) = (&imports1, &imports2) {
        let dlls1: BTreeSet<String> = imp1.iter().map(|d| d.name.to_ascii_lowercase()).collect();
        let dlls2: BTreeSet<String> = imp2.iter().map(|d| d.name.to_ascii_lowercase()).collect();

        let added_dlls: Vec<&String> = dlls2.difference(&dlls1).collect();
        let removed_dlls: Vec<&String> = dlls1.difference(&dlls2).collect();

        if added_dlls.is_empty() {
            out.push_str("  Added DLLs: (none)\n");
        } else {
            out.push_str(&format!("  Added DLLs: {}\n", added_dlls.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if removed_dlls.is_empty() {
            out.push_str("  Removed DLLs: (none)\n");
        } else {
            out.push_str(&format!("  Removed DLLs: {}\n", removed_dlls.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }

        // Compare functions
        let all_funcs1: BTreeSet<String> = imp1.iter()
            .flat_map(|d| d.functions.iter().map(|f| format!("{}!{}", d.name.to_ascii_lowercase(), f)))
            .collect();
        let all_funcs2: BTreeSet<String> = imp2.iter()
            .flat_map(|d| d.functions.iter().map(|f| format!("{}!{}", d.name.to_ascii_lowercase(), f)))
            .collect();

        let added_funcs: usize = all_funcs2.difference(&all_funcs1).count();
        let removed_funcs: usize = all_funcs1.difference(&all_funcs2).count();

        out.push_str(&format!("  Added functions: {}\n", added_funcs));
        out.push_str(&format!("  Removed functions: {}\n", removed_funcs));
    } else {
        out.push_str("  (could not parse imports from one or both files)\n");
    }
    out.push('\n');

    // Compare strings -- focus on SQL and table references
    let strings1: BTreeSet<String> = extract_ascii_strings(&data1, 8).into_iter().collect();
    let strings2: BTreeSet<String> = extract_ascii_strings(&data2, 8).into_iter().collect();

    let new_strings: Vec<&String> = strings2.difference(&strings1).collect();
    let removed_strings: Vec<&String> = strings1.difference(&strings2).collect();

    let sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER"];
    let new_sql: Vec<&&String> = new_strings.iter()
        .filter(|s| sql_keywords.iter().any(|kw| s.to_uppercase().contains(kw)))
        .collect();
    let removed_sql: Vec<&&String> = removed_strings.iter()
        .filter(|s| sql_keywords.iter().any(|kw| s.to_uppercase().contains(kw)))
        .collect();

    // Find new table references
    let tables1 = collect_table_names(&strings1);
    let tables2 = collect_table_names(&strings2);
    let new_tables: Vec<&String> = tables2.difference(&tables1).collect();
    let removed_tables: Vec<&String> = tables1.difference(&tables2).collect();

    out.push_str("\u{2500}\u{2500} String Changes \u{2500}\u{2500}\n");
    out.push_str(&format!("  Total strings: {} -> {} (delta: {})\n",
        strings1.len(), strings2.len(),
        strings2.len() as i64 - strings1.len() as i64));
    out.push_str(&format!("  New SQL statements: {}\n", new_sql.len()));
    out.push_str(&format!("  Removed SQL statements: {}\n", removed_sql.len()));

    if !new_tables.is_empty() {
        out.push_str(&format!("  New table references: {}\n",
            new_tables.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    if !removed_tables.is_empty() {
        out.push_str(&format!("  Removed table references: {}\n",
            removed_tables.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    out.push('\n');

    // Show new SQL statements (first 20)
    if !new_sql.is_empty() {
        out.push_str("\u{2500}\u{2500} New SQL Statements \u{2500}\u{2500}\n");
        for s in new_sql.iter().take(20) {
            out.push_str(&format!("  {}\n", truncate_str(s, 120)));
        }
        if new_sql.len() > 20 {
            out.push_str(&format!("  ... and {} more\n", new_sql.len() - 20));
        }
        out.push('\n');
    }

    // Compare version info (from resources)
    let ver1 = extract_version_string(&data1);
    let ver2 = extract_version_string(&data2);
    if ver1.is_some() || ver2.is_some() {
        out.push_str("\u{2500}\u{2500} Version Info \u{2500}\u{2500}\n");
        out.push_str(&format!("  {}: {}\n", fname1, ver1.unwrap_or_else(|| "(none)".to_string())));
        out.push_str(&format!("  {}: {}\n", fname2, ver2.unwrap_or_else(|| "(none)".to_string())));
        out.push('\n');
    }

    out
}

fn parse_pe_imports_structured(data: &[u8]) -> Result<Vec<ImportedDll>, String> {
    if data.len() < 64 {
        return Err("File too small".to_string());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file".to_string());
    }

    let e_lfanew = read_u32(data, 0x3C)? as usize;
    if e_lfanew + 4 > data.len() {
        return Err("Invalid e_lfanew".to_string());
    }
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0
    {
        return Err("Invalid PE signature".to_string());
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    let opt_magic = read_u16(data, opt_start)?;
    let is_pe64 = match opt_magic {
        0x10B => false,
        0x20B => true,
        _ => return Err("Unknown PE magic".to_string()),
    };

    let import_dir_offset = if is_pe64 { opt_start + 120 } else { opt_start + 104 };
    if import_dir_offset + 8 > data.len() {
        return Err("No import directory".to_string());
    }

    let import_rva = read_u32(data, import_dir_offset)? as usize;
    let import_size = read_u32(data, import_dir_offset + 4)? as usize;

    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }

    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let import_offset = rva_to_offset(import_rva, &sections)
        .ok_or_else(|| "Cannot resolve import RVA".to_string())?;

    let mut dlls: Vec<ImportedDll> = Vec::new();
    let mut entry_offset = import_offset;

    loop {
        if entry_offset + 20 > data.len() { break; }

        let original_first_thunk = read_u32(data, entry_offset)? as usize;
        let name_rva = read_u32(data, entry_offset + 12)? as usize;
        let first_thunk = read_u32(data, entry_offset + 16)? as usize;

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = if name_rva != 0 {
            rva_to_offset(name_rva, &sections)
                .map(|off| read_cstring(data, off))
                .unwrap_or_else(|| "<unknown>".to_string())
        } else {
            "<unknown>".to_string()
        };

        let ilt_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        let mut functions: Vec<String> = Vec::new();

        if ilt_rva != 0 {
            if let Some(ilt_offset) = rva_to_offset(ilt_rva, &sections) {
                let entry_size = if is_pe64 { 8 } else { 4 };
                let mut i = 0usize;
                loop {
                    let p = ilt_offset + i * entry_size;
                    if p + entry_size > data.len() { break; }

                    if is_pe64 {
                        let val = read_u64(data, p)?;
                        if val == 0 { break; }
                        if val & (1u64 << 63) != 0 {
                            functions.push(format!("Ordinal({})", val & 0xFFFF));
                        } else {
                            let hn_rva = (val & 0x7FFFFFFF) as usize;
                            if let Some(hn_off) = rva_to_offset(hn_rva, &sections) {
                                if hn_off + 2 < data.len() {
                                    let name = read_cstring(data, hn_off + 2);
                                    if !name.is_empty() { functions.push(name); }
                                }
                            }
                        }
                    } else {
                        let val = read_u32(data, p)?;
                        if val == 0 { break; }
                        if val & (1u32 << 31) != 0 {
                            functions.push(format!("Ordinal({})", val & 0xFFFF));
                        } else {
                            let hn_rva = (val & 0x7FFFFFFF) as usize;
                            if let Some(hn_off) = rva_to_offset(hn_rva, &sections) {
                                if hn_off + 2 < data.len() {
                                    let name = read_cstring(data, hn_off + 2);
                                    if !name.is_empty() { functions.push(name); }
                                }
                            }
                        }
                    }

                    i += 1;
                    if i > 10_000 { break; }
                }
            }
        }

        dlls.push(ImportedDll { name: dll_name, functions });
        entry_offset += 20;
        if dlls.len() > 500 { break; }
    }

    Ok(dlls)
}

fn collect_table_names(strings: &BTreeSet<String>) -> BTreeSet<String> {
    let mut tables = BTreeSet::new();
    for s in strings {
        if s.contains("dbo.") {
            // Extract table name from dbo.xxx patterns
            for part in s.split_whitespace() {
                if part.contains("dbo.") {
                    let clean = part.trim_matches(|c: char| c == '[' || c == ']' || c == '\'' || c == '"' || c == ',');
                    if let Some(dot_pos) = clean.rfind('.') {
                        let tname = &clean[dot_pos + 1..];
                        if !tname.is_empty() {
                            tables.insert(tname.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    tables
}

fn extract_version_string(data: &[u8]) -> Option<String> {
    // Quick scan for VS_VERSION_INFO signature in the binary
    let pattern = b"VS_VERSION_INFO";
    // Look for it as UTF-16LE: V\0S\0_\0V\0...
    let utf16_pattern: Vec<u8> = pattern.iter().flat_map(|&b| vec![b, 0]).collect();

    for i in 0..data.len().saturating_sub(utf16_pattern.len()) {
        if data[i..].starts_with(&utf16_pattern) {
            // Found it -- try to extract the fixed version info
            // The VS_FIXEDFILEINFO should be shortly after, at a 4-byte aligned offset
            // Look backwards for the wLength field (should be at i - 6)
            if i >= 6 {
                let struct_start = i - 6;
                let ver_info = parse_version_info(data, struct_start, 512);
                if !ver_info.trim().is_empty() {
                    // Return first line (File Version)
                    let lines: Vec<&str> = ver_info.trim().lines().collect();
                    return Some(lines.iter().map(|l| l.trim()).collect::<Vec<_>>().join("; "));
                }
            }
        }
    }

    None
}
