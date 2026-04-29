use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use crate::types::Graph;
use crate::utils;

const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024; // 256 MB

// ── Clarion Schema Types ────────────────────────────────────────────

#[derive(Debug)]
struct ClarionTable {
    name: String,
    sql_name: String,
    prefix: String,
    keys: Vec<ClarionKey>,
    fields: Vec<ClarionField>,
}

#[derive(Debug)]
struct ClarionKey {
    name: String,
    fields: Vec<String>,
    is_dup: bool,
}

#[derive(Debug, Clone)]
struct ClarionField {
    name: String,
    field_type: String,
    size: String,
}

// ── 1. clarion_schema ───────────────────────────────────────────────

pub fn clarion_schema(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            // Fallback: read as bytes and decode as Latin-1 (ISO-8859-1)
            match fs::read(path) {
                Ok(bytes) => bytes.iter().map(|&b| b as char).collect::<String>(),
                Err(e) => return format!("Error reading file: {e}"),
            }
        }
    };

    let tables = parse_clarion_ddl(&content);

    if tables.is_empty() {
        return "No tables found in file.".to_string();
    }

    let total_fields: usize = tables.iter().map(|t| t.fields.len()).sum();
    let total_keys: usize = tables.iter().map(|t| t.keys.len()).sum();

    let mut out = String::new();
    out.push_str("=== Clarion Schema Analysis ===\n\n");
    out.push_str(&format!("Tables: {}\n", tables.len()));
    out.push_str(&format!("Total fields: {total_fields}\n"));
    out.push_str(&format!("Total keys: {total_keys}\n"));
    out.push_str("\n");

    // Table details
    for table in &tables {
        out.push_str(&format!("── {} ──\n", table.name));
        if !table.sql_name.is_empty() {
            out.push_str(&format!("  SQL: {}\n", table.sql_name));
        }
        if !table.prefix.is_empty() {
            out.push_str(&format!("  Prefix: {}\n", table.prefix));
        }

        if !table.keys.is_empty() {
            out.push_str("  Keys:\n");
            for key in &table.keys {
                let dup_str = if key.is_dup { " (DUP)" } else { "" };
                out.push_str(&format!("    {} [{}]{}\n", key.name, key.fields.join(", "), dup_str));
            }
        }

        if !table.fields.is_empty() {
            out.push_str("  Fields:\n");
            for field in &table.fields {
                if field.size.is_empty() {
                    out.push_str(&format!("    {} : {}\n", field.name, field.field_type));
                } else {
                    out.push_str(&format!("    {} : {}({})\n", field.name, field.field_type, field.size));
                }
            }
        }
        out.push_str("\n");
    }

    // Relationship inference
    let relationships = infer_relationships(&tables);
    if !relationships.is_empty() {
        out.push_str("── Inferred Relationships ──\n");
        for rel in &relationships {
            out.push_str(&format!("  {}\n", rel));
        }
    }

    out
}

fn parse_clarion_ddl(content: &str) -> Vec<ClarionTable> {
    let mut tables: Vec<ClarionTable> = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with('!') {
            i += 1;
            continue;
        }

        // Skip empty lines
        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Check for table start: word  file,
        if let Some(table) = try_parse_table_start(trimmed) {
            let mut current_table = table;
            i += 1;

            // Parse keys and record
            while i < lines.len() {
                let inner = lines[i].trim();

                if inner.starts_with('!') || inner.is_empty() {
                    i += 1;
                    continue;
                }

                // Check for key line
                if let Some(key) = try_parse_key(inner, &current_table.prefix) {
                    current_table.keys.push(key);
                    i += 1;
                    continue;
                }

                // Check for record start
                if is_record_start(inner) {
                    i += 1;
                    // Parse fields until end of record
                    while i < lines.len() {
                        let field_line = lines[i].trim();

                        if field_line.starts_with('!') {
                            i += 1;
                            continue;
                        }

                        // Record end: ". ." or just "."
                        if is_record_end(field_line) {
                            i += 1;
                            break;
                        }

                        if let Some(field) = try_parse_field(field_line) {
                            current_table.fields.push(field);
                        }

                        i += 1;
                    }
                    break;
                }

                // If we hit another table start, break
                if try_parse_table_start(inner).is_some() {
                    break;
                }

                i += 1;
            }

            tables.push(current_table);
        } else {
            i += 1;
        }
    }

    tables
}

fn try_parse_table_start(line: &str) -> Option<ClarionTable> {
    // Pattern: word  file,pre(XXX),name('dbo.XXX'),...
    let lower = line.to_lowercase();
    let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.len() < 2 {
        return None;
    }

    let rest = parts[1].trim();
    if !rest.to_lowercase().starts_with("file,") && !rest.to_lowercase().starts_with("file ") {
        return None;
    }

    let name = parts[0].to_string();

    // Extract prefix from pre(XXX)
    let prefix = extract_paren_value(&lower, "pre(");

    // Extract SQL name from name('dbo.XXX') or name('XXX')
    let sql_name = extract_quoted_paren_value(line, "name(");

    Some(ClarionTable {
        name,
        sql_name,
        prefix,
        keys: Vec::new(),
        fields: Vec::new(),
    })
}

fn extract_paren_value(line: &str, prefix: &str) -> String {
    if let Some(start) = line.find(prefix) {
        let after = &line[start + prefix.len()..];
        if let Some(end) = after.find(')') {
            return after[..end].to_string();
        }
    }
    String::new()
}

fn extract_quoted_paren_value(line: &str, prefix: &str) -> String {
    let lower = line.to_lowercase();
    if let Some(start) = lower.find(&prefix.to_lowercase()) {
        let after = &line[start + prefix.len()..];
        // Look for quoted value: 'xxx'
        if let Some(q1) = after.find('\'') {
            let rest = &after[q1 + 1..];
            if let Some(q2) = rest.find('\'') {
                return rest[..q2].to_string();
            }
        }
        // No quotes, just get until )
        if let Some(end) = after.find(')') {
            return after[..end].to_string();
        }
    }
    String::new()
}

fn try_parse_key(line: &str, _prefix: &str) -> Option<ClarionKey> {
    // Pattern: key_name  key(fields),dup
    let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.len() < 2 {
        return None;
    }

    let rest = parts[1].trim().to_lowercase();
    if !rest.starts_with("key(") {
        return None;
    }

    let name = parts[0].to_string();

    // Extract fields from key(field1, field2)
    let after_key = &parts[1].trim()[4..]; // skip "key("
    let fields_str = if let Some(end) = after_key.find(')') {
        &after_key[..end]
    } else {
        after_key
    };

    let fields: Vec<String> = fields_str
        .split(',')
        .map(|f| {
            let f = f.trim();
            // Remove prefix: prefix:field -> field
            if let Some(colon) = f.find(':') {
                f[colon + 1..].to_string()
            } else {
                f.to_string()
            }
        })
        .filter(|f| !f.is_empty())
        .collect();

    let is_dup = rest.contains(",dup") || rest.contains("+dup") || rest.ends_with("dup");

    Some(ClarionKey { name, fields, is_dup })
}

fn is_record_start(line: &str) -> bool {
    let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.len() < 2 {
        return false;
    }
    parts[1].trim().to_lowercase().starts_with("record")
}

fn is_record_end(line: &str) -> bool {
    let trimmed = line.trim();
    // ". ." pattern or just "." or ".  ."
    trimmed == "." || trimmed == ". ." || trimmed == ".."
        || (trimmed.starts_with('.') && trimmed.ends_with('.') && trimmed.len() <= 5)
        || trimmed == "end"
        || trimmed.starts_with(". .")
}

fn try_parse_field(line: &str) -> Option<ClarionField> {
    let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].to_string();
    let type_str = parts[1].trim().to_lowercase();

    // Known Clarion types
    let known_types = [
        "string", "cstring", "long", "short", "byte", "decimal", "real",
        "group", "date", "time", "ulong", "ushort", "pstring", "like",
        "memo", "blob", "any",
    ];

    for known in &known_types {
        if type_str.starts_with(known) {
            let size = extract_paren_value(&type_str, &format!("{known}("));
            return Some(ClarionField {
                name,
                field_type: known.to_string(),
                size,
            });
        }
    }

    None
}

fn infer_relationships(tables: &[ClarionTable]) -> Vec<String> {
    let mut relationships = Vec::new();

    // Build a map of table names (lowercased) to their key fields
    let mut table_keys: HashMap<String, Vec<String>> = HashMap::new();
    let table_names: Vec<String> = tables.iter().map(|t| t.name.to_lowercase()).collect();

    for table in tables {
        let key_fields: Vec<String> = table.keys.iter()
            .flat_map(|k| k.fields.clone())
            .collect();
        table_keys.insert(table.name.to_lowercase(), key_fields);
    }

    // For each table, look at fields that might reference another table
    for table in tables {
        for field in &table.fields {
            let fname = field.name.to_lowercase();

            // Pattern: field ends with _id or _key or _code
            let suffixes = ["_id", "_key", "_code", "_no", "_num"];
            for suffix in &suffixes {
                if fname.ends_with(suffix) {
                    let potential_table = &fname[..fname.len() - suffix.len()];
                    // Check if a table with this name or similar exists
                    for tname in &table_names {
                        if tname == &table.name.to_lowercase() {
                            continue;
                        }
                        // Match: vendor_id -> vendor table, cust_id -> customer table
                        if tname.starts_with(potential_table) || potential_table.starts_with(&tname[..tname.len().min(4)]) {
                            // Verify the target table has a key on this field
                            if let Some(keys) = table_keys.get(tname) {
                                let has_matching_key = keys.iter().any(|k| {
                                    let kl = k.to_lowercase();
                                    kl == fname || kl.ends_with(&fname) || fname.ends_with(&kl)
                                });
                                if has_matching_key {
                                    relationships.push(format!(
                                        "{}.{} -> {} (FK via key match)",
                                        table.name, field.name, tname
                                    ));
                                }
                            } else {
                                // Even without key match, the naming suggests a relationship
                                relationships.push(format!(
                                    "{}.{} -> {} (FK inferred from naming)",
                                    table.name, field.name, tname
                                ));
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    relationships.sort();
    relationships.dedup();
    relationships
}

// ── 2. pe_strings ───────────────────────────────────────────────────

pub fn pe_strings(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    // Extract ASCII strings of length >= 6
    let strings = extract_ascii_strings(&data, 6);

    if strings.is_empty() {
        return "No strings found in binary.".to_string();
    }

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
    out.push_str("\n");

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

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    const MAX_STRINGS: usize = 50_000;
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
                if strings.len() >= MAX_STRINGS {
                    return strings;
                }
            }
            current.clear();
        }
    }

    // Don't forget the last string
    if current.len() >= min_len && strings.len() < MAX_STRINGS {
        strings.push(current);
    }

    strings
}

fn is_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

// ── 3. pe_exports ───────────────────────────────────────────────────

pub fn pe_exports(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_pe_exports(&data) {
        Ok(exports) => {
            if exports.is_empty() {
                return "No exports found in PE binary.".to_string();
            }
            let mut out = String::new();
            out.push_str("=== PE Export Table ===\n\n");
            out.push_str(&format!("Exports: {}\n\n", exports.len()));
            for (i, name) in exports.iter().enumerate() {
                out.push_str(&format!("  {:4}  {}\n", i + 1, name));
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

struct Section {
    virtual_address: usize,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
}

fn parse_sections(data: &[u8], start: usize, count: usize) -> Result<Vec<Section>, String> {
    let mut sections = Vec::new();
    for i in 0..count {
        let offset = start + i * 40;
        if offset + 40 > data.len() {
            return Err("Truncated section headers".to_string());
        }
        let virtual_size = read_u32(data, offset + 8)? as usize;
        let virtual_address = read_u32(data, offset + 12)? as usize;
        let raw_size = read_u32(data, offset + 16)? as usize;
        let raw_offset = read_u32(data, offset + 20)? as usize;

        sections.push(Section {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
    }
    Ok(sections)
}

fn rva_to_offset(rva: usize, sections: &[Section]) -> Option<usize> {
    for section in sections {
        let section_end = section.virtual_address + section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address && rva < section_end {
            let offset_within = rva - section.virtual_address;
            if offset_within < section.raw_size {
                return Some(section.raw_offset + offset_within);
            }
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset {offset}"));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read u32 out of bounds at offset {offset}"));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
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

// ── 4. pe_imports ──────────────────────────────────────────────────

pub fn pe_imports(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_pe_imports_structured(&data) {
        Ok(dlls) => format_pe_imports_result(&dlls),
        Err(e) => format!("PE import parse error: {e}"),
    }
}

/// Represents a single imported DLL and its functions.
struct ImportedDll {
    name: String,
    functions: Vec<String>,
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err(format!("Read u64 out of bounds at offset {offset}"));
    }
    Ok(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
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
        let dll_lower = dll.name.to_lowercase();

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

// ── 5. pe_resources ────────────────────────────────────────────────

pub fn pe_resources(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

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

/// Decode UTF-16LE bytes to String
fn read_utf16le(data: &[u8], start: usize, end: usize) -> String {
    let mut chars: Vec<u16> = Vec::new();
    let mut i = start;
    while i + 1 < end {
        chars.push(u16::from_le_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&chars)
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

fn align4(pos: usize) -> usize {
    (pos + 3) & !3
}

// ── 6. pe_debug ───────────────────────────────────────────────────

pub fn pe_debug(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
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
                        if b >= 0x20 && b <= 0x7E { b as char } else { '.' }
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

// ── 7. dbf_schema ─────────────────────────────────────────────────

pub fn dbf_schema(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_dbf_header(&data, target) {
        Ok(info) => info,
        Err(e) => format!("DBF parse error: {e}"),
    }
}

fn parse_dbf_header(data: &[u8], filename: &str) -> Result<String, String> {
    if data.len() < 32 {
        return Err("File too small for DBF header (need at least 32 bytes)".to_string());
    }

    let version_byte = data[0];
    let version_name = dbf_version_name(version_byte);

    let last_yy = data[1] as u16;
    let last_mm = data[2];
    let last_dd = data[3];
    let last_year = if last_yy < 100 { 2000 + last_yy } else { 1900 + last_yy };

    let num_records = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let header_size = u16::from_le_bytes([data[8], data[9]]) as usize;
    let record_size = u16::from_le_bytes([data[10], data[11]]);

    let mut fields: Vec<DbfField> = Vec::new();
    let mut offset = 32;

    while offset + 32 <= data.len() && offset < header_size {
        if data[offset] == 0x0D {
            break;
        }

        let name_bytes = &data[offset..offset + 11];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(11);
        let name: String = name_bytes[..name_end]
            .iter()
            .map(|&b| if b >= 0x20 && b <= 0x7E { b as char } else { '?' })
            .collect();

        let field_type = data[offset + 11] as char;
        let field_length = data[offset + 16];
        let decimal_count = data[offset + 17];

        fields.push(DbfField {
            name,
            field_type,
            length: field_length,
            decimals: decimal_count,
        });

        offset += 32;
    }

    let fname = Path::new(filename)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| filename.to_string());

    let mut out = String::new();
    out.push_str("=== DBF Schema ===\n\n");
    out.push_str(&format!("File: {}\n", fname));
    out.push_str(&format!("Version: {}\n", version_name));
    out.push_str(&format!("Last updated: {:04}-{:02}-{:02}\n", last_year, last_mm, last_dd));
    out.push_str(&format!("Records: {}\n", format_dbf_number(num_records)));
    out.push_str(&format!("Header size: {} bytes\n", header_size));
    out.push_str(&format!("Record size: {} bytes\n", record_size));
    out.push_str(&format!("\nFields ({}):\n", fields.len()));

    let max_name_len = fields.iter().map(|f| f.name.len()).max().unwrap_or(10);
    let pad = max_name_len.max(10);

    for field in &fields {
        let type_name = dbf_field_type_name(field.field_type);
        let size_str = if field.decimals > 0 {
            format!("{},{}", field.length, field.decimals)
        } else {
            format!("{}", field.length)
        };
        out.push_str(&format!(
            "  {:pad$}  {}({})\n",
            field.name, type_name, size_str, pad = pad
        ));
    }

    Ok(out)
}

struct DbfField {
    name: String,
    field_type: char,
    length: u8,
    decimals: u8,
}

fn dbf_version_name(v: u8) -> &'static str {
    match v {
        0x02 => "FoxBASE",
        0x03 => "dBASE III",
        0x04 => "dBASE IV",
        0x05 => "dBASE V",
        0x30 => "Visual FoxPro",
        0x31 => "Visual FoxPro (autoincrement)",
        0x32 => "Visual FoxPro (varchar/varbinary)",
        0x43 => "dBASE IV SQL table, no memo",
        0x63 => "dBASE IV SQL system, no memo",
        0x7B => "dBASE IV with memo",
        0x83 => "dBASE III+ with memo",
        0x8B => "dBASE IV with memo",
        0x8E => "dBASE IV with SQL table",
        0xCB => "dBASE IV SQL table with memo",
        0xF5 => "FoxPro 2.x with memo",
        0xFB => "FoxBASE",
        _ => "Unknown",
    }
}

fn dbf_field_type_name(t: char) -> &'static str {
    match t {
        'C' => "Character",
        'N' => "Numeric",
        'F' => "Float",
        'D' => "Date",
        'L' => "Logical",
        'M' => "Memo",
        'B' => "Binary",
        'G' => "General",
        'P' => "Picture",
        'Y' => "Currency",
        'T' => "DateTime",
        'I' => "Integer",
        'V' => "Varchar",
        'X' => "Variant",
        'O' => "Double",
        '+' => "Autoincrement",
        '@' => "Timestamp",
        _ => "Unknown",
    }
}

fn format_dbf_number(n: u32) -> String {
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

// ── 8. pe_sections ──────────────────────────────────────────────────

pub fn pe_sections(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_pe_sections_info(&data) {
        Ok(info) => info,
        Err(e) => format!("PE parse error: {e}"),
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
            .map(|&b| if b >= 0x20 && b <= 0x7E { b as char } else { '.' })
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

// ── 9. dotnet_meta ──────────────────────────────────────────────────

pub fn dotnet_meta(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_dotnet_metadata(&data) {
        Ok(info) => info,
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
                    if valid & (1u64 << bit) != 0 {
                        if row_pos + 4 <= data.len() {
                            let count = read_u32(data, row_pos)?;
                            row_counts.push((bit as usize, count));
                            row_pos += 4;
                        }
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

                    // Calculate row sizes and table offsets
                    // We need to compute the offset of each table in the table data stream.
                    // This requires knowing the size of each row for each table. For a
                    // simplified approach, we compute sizes for the tables we care about
                    // and skip past tables we don't care about.

                    // Compute sizes for tables 0..max so we can find offsets.
                    // Row sizes depend on heap index sizes and other table row counts (coded indexes).
                    // For simplicity, we'll compute the important ones.

                    // Table row sizes (simplified — assumes small coded indexes where row counts < 65536)
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
                            _ => 0, // Unknown — can't compute
                        }
                    };

                    // Calculate byte offset of each table in the table data area
                    let mut table_offsets: HashMap<usize, usize> = HashMap::new();
                    let mut tbl_pos = table_data_start;
                    for &(idx, count) in &row_counts {
                        table_offsets.insert(idx, tbl_pos);
                        let rs = row_size(idx);
                        if rs == 0 {
                            // Unknown row size — use a heuristic: skip this table
                            // We can't proceed past this table accurately
                            // but we'll try to continue for tables we already found
                            // can't advance — unknown row size
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
                                    let name_pos = row_start + 4 + 2 + 2;
                                    let (name_idx, _) = read_string_idx(name_pos)?;
                                    let method_name = read_string_from_heap(name_idx);

                                    if !method_name.is_empty() {
                                        out.push_str(&format!("  {}\n", method_name));
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

    Ok(out)
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

// ── 10. sql_extract ─────────────────────────────────────────────────

pub fn sql_extract(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);

    if path.is_dir() {
        // Directory mode: scan all EXE/DLL files
        return sql_extract_directory(path);
    }

    if !path.exists() {
        return format!("File not found: {target}");
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("Error: {e}"),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return format!("File too large ({} bytes, max 256 MB)", meta.len());
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let result = extract_sql_from_binary(&data);
    format_sql_extraction(&result, None)
}

struct SqlExtraction {
    statements: Vec<SqlStatement>,
    table_ops: HashMap<String, TableOps>,
    join_relationships: HashMap<(String, String), usize>,
}

struct SqlStatement {
    op_type: SqlOp,
    tables: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum SqlOp {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Alter,
    Exec,
    Declare,
    Other,
}

impl SqlOp {
    fn name(&self) -> &'static str {
        match self {
            SqlOp::Select => "SELECT",
            SqlOp::Insert => "INSERT",
            SqlOp::Update => "UPDATE",
            SqlOp::Delete => "DELETE",
            SqlOp::Create => "CREATE",
            SqlOp::Alter => "ALTER",
            SqlOp::Exec => "EXEC",
            SqlOp::Declare => "DECLARE",
            SqlOp::Other => "OTHER",
        }
    }
}

#[derive(Default)]
struct TableOps {
    selects: usize,
    inserts: usize,
    updates: usize,
    deletes: usize,
}

fn extract_sql_from_binary(data: &[u8]) -> SqlExtraction {
    let strings = extract_ascii_strings(data, 8);

    let sql_keywords_upper = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "EXEC", "DECLARE"];

    let mut statements: Vec<SqlStatement> = Vec::new();
    let mut table_ops: HashMap<String, TableOps> = HashMap::new();
    let mut join_relationships: HashMap<(String, String), usize> = HashMap::new();

    for s in &strings {
        let upper = s.to_uppercase();
        let has_sql = sql_keywords_upper.iter().any(|kw| upper.contains(kw));
        if !has_sql {
            continue;
        }

        // Determine operation type
        let op_type = if upper.contains("SELECT") && (upper.contains("FROM") || upper.contains("*")) {
            SqlOp::Select
        } else if upper.contains("INSERT") && upper.contains("INTO") {
            SqlOp::Insert
        } else if upper.starts_with("UPDATE") || upper.contains(" UPDATE ") {
            SqlOp::Update
        } else if upper.starts_with("DELETE") || upper.contains(" DELETE ") {
            SqlOp::Delete
        } else if upper.contains("CREATE") {
            SqlOp::Create
        } else if upper.contains("ALTER") {
            SqlOp::Alter
        } else if upper.contains("EXEC") {
            SqlOp::Exec
        } else if upper.contains("DECLARE") {
            SqlOp::Declare
        } else {
            SqlOp::Other
        };

        // Extract table names from the SQL
        let tables = extract_sql_tables(&upper);

        // Update table-operation matrix
        for table in &tables {
            let entry = table_ops.entry(table.clone()).or_default();
            match op_type {
                SqlOp::Select => entry.selects += 1,
                SqlOp::Insert => entry.inserts += 1,
                SqlOp::Update => entry.updates += 1,
                SqlOp::Delete => entry.deletes += 1,
                _ => {}
            }
        }

        // Extract JOIN relationships
        let join_pairs = extract_join_pairs(&upper);
        for (a, b) in join_pairs {
            let key = if a < b { (a, b) } else { (b, a) };
            *join_relationships.entry(key).or_insert(0) += 1;
        }

        statements.push(SqlStatement {
            op_type,
            tables,
        });
    }

    SqlExtraction {
        statements,
        table_ops,
        join_relationships,
    }
}

fn extract_sql_tables(upper: &str) -> Vec<String> {
    let mut tables = BTreeSet::new();

    // Extract tables from FROM clause
    extract_tables_after_keyword(upper, "FROM ", &mut tables);
    // Extract tables from JOIN clauses
    extract_tables_after_keyword(upper, "JOIN ", &mut tables);
    // Extract tables from INTO clause
    extract_tables_after_keyword(upper, "INTO ", &mut tables);
    // Extract tables from UPDATE clause
    extract_tables_after_keyword(upper, "UPDATE ", &mut tables);

    tables.into_iter().collect()
}

fn extract_tables_after_keyword(upper: &str, keyword: &str, tables: &mut BTreeSet<String>) {
    let mut search_pos = 0;
    while let Some(idx) = upper[search_pos..].find(keyword) {
        let abs_idx = search_pos + idx + keyword.len();
        if abs_idx >= upper.len() {
            break;
        }

        let remaining = &upper[abs_idx..];
        // Extract table names (comma-separated, possibly with aliases)
        let stop_keywords = ["WHERE", "SET", "VALUES", "ORDER", "GROUP", "HAVING",
            "UNION", "ON", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS",
            "JOIN", "SELECT", "INSERT", "UPDATE", "DELETE", "("];
        for part in remaining.split(',') {
            let part = part.trim();
            let end_pos = stop_keywords.iter()
                .filter_map(|kw| part.find(kw))
                .min()
                .unwrap_or(part.len());

            let table_part = part[..end_pos].trim();
            if table_part.is_empty() {
                break;
            }

            // Get first token (table name, possibly qualified like dbo.xxx)
            let table_name = table_part.split_whitespace().next().unwrap_or("");
            let table_name = table_name.trim_matches(|c: char| c == '[' || c == ']' || c == '"' || c == '`');

            if !table_name.is_empty()
                && table_name.len() >= 2
                && table_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '#')
                && !["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "SET", "AND", "OR", "NOT", "IN", "AS"].contains(&table_name)
            {
                // Strip schema prefix for the key
                let clean = if let Some(dot_pos) = table_name.rfind('.') {
                    &table_name[dot_pos + 1..]
                } else {
                    table_name
                };
                if !clean.is_empty() {
                    tables.insert(clean.to_lowercase());
                }
            }

            // If we hit a stop keyword, don't continue to the next comma-separated part
            if end_pos < part.len() {
                break;
            }
        }

        search_pos = abs_idx;
    }
}

fn extract_join_pairs(upper: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    // Look for patterns: table1 JOIN table2 ON table1.col = table2.col
    let join_types = ["JOIN ", "INNER JOIN ", "LEFT JOIN ", "RIGHT JOIN ",
        "LEFT OUTER JOIN ", "RIGHT OUTER JOIN ", "CROSS JOIN "];

    for jt in &join_types {
        let mut search_pos = 0;
        while let Some(idx) = upper[search_pos..].find(jt) {
            let abs_idx = search_pos + idx + jt.len();
            if abs_idx >= upper.len() {
                break;
            }

            // Get the table after JOIN
            let remaining = &upper[abs_idx..];
            let join_table = remaining.split_whitespace().next().unwrap_or("");
            let join_table = join_table.trim_matches(|c: char| c == '[' || c == ']');

            // Try to find the table before this JOIN by looking for FROM or another JOIN
            if !join_table.is_empty() && join_table.len() >= 2 {
                // Look for ON clause to find the other table
                if let Some(on_pos) = remaining.find(" ON ") {
                    let on_clause = &remaining[on_pos + 4..];
                    // Extract table names from ON clause (table.col = table.col)
                    let on_tables: Vec<&str> = on_clause.split(|c: char| c == '=' || c == ' ')
                        .filter_map(|part| {
                            let part = part.trim();
                            if part.contains('.') {
                                Some(part.split('.').next().unwrap_or(""))
                            } else {
                                None
                            }
                        })
                        .filter(|t| !t.is_empty() && t.len() >= 2)
                        .collect();

                    for t in &on_tables {
                        let clean_t = t.trim_matches(|c: char| c == '[' || c == ']').to_lowercase();
                        let clean_join = if let Some(dot) = join_table.rfind('.') {
                            join_table[dot + 1..].to_lowercase()
                        } else {
                            join_table.to_lowercase()
                        };

                        if clean_t != clean_join && !clean_t.is_empty() {
                            pairs.push((clean_t, clean_join.clone()));
                        }
                    }
                }
            }

            search_pos = abs_idx;
        }
    }

    pairs
}

fn format_sql_extraction(result: &SqlExtraction, binary_name: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("=== SQL Extraction ===\n\n");

    if let Some(name) = binary_name {
        out.push_str(&format!("Binary: {}\n", name));
    }

    out.push_str(&format!("Statements: {}\n", result.statements.len()));
    out.push_str(&format!("Unique tables: {}\n\n", result.table_ops.len()));

    // Operation counts
    let mut op_counts: HashMap<SqlOp, usize> = HashMap::new();
    for stmt in &result.statements {
        *op_counts.entry(stmt.op_type).or_insert(0) += 1;
    }

    out.push_str("\u{2500}\u{2500} Operations \u{2500}\u{2500}\n");
    let op_order = [SqlOp::Select, SqlOp::Insert, SqlOp::Update, SqlOp::Delete,
        SqlOp::Create, SqlOp::Alter, SqlOp::Exec, SqlOp::Declare, SqlOp::Other];
    for op in &op_order {
        if let Some(&count) = op_counts.get(op) {
            out.push_str(&format!("  {}: {}\n", op.name(), count));
        }
    }
    out.push('\n');

    // Table access map (sorted by total access count)
    if !result.table_ops.is_empty() {
        let mut table_list: Vec<(&String, &TableOps)> = result.table_ops.iter().collect();
        table_list.sort_by(|a, b| {
            let total_a = a.1.selects + a.1.inserts + a.1.updates + a.1.deletes;
            let total_b = b.1.selects + b.1.inserts + b.1.updates + b.1.deletes;
            total_b.cmp(&total_a)
        });

        out.push_str("\u{2500}\u{2500} Table Access Map \u{2500}\u{2500}\n");
        for (name, ops) in table_list.iter().take(100) {
            let mut parts = Vec::new();
            if ops.selects > 0 { parts.push(format!("SELECT({})", ops.selects)); }
            if ops.inserts > 0 { parts.push(format!("INSERT({})", ops.inserts)); }
            if ops.updates > 0 { parts.push(format!("UPDATE({})", ops.updates)); }
            if ops.deletes > 0 { parts.push(format!("DELETE({})", ops.deletes)); }
            let max_name = 20;
            let padded = format!("{:width$}", name, width = max_name.min(name.len() + 5));
            out.push_str(&format!("  {}{}\n", padded, parts.join(" ")));
        }
        out.push('\n');
    }

    // JOIN relationships
    if !result.join_relationships.is_empty() {
        let mut joins: Vec<(&(String, String), &usize)> = result.join_relationships.iter().collect();
        joins.sort_by(|a, b| b.1.cmp(a.1));

        out.push_str("\u{2500}\u{2500} JOIN Relationships \u{2500}\u{2500}\n");
        for ((a, b), count) in joins.iter().take(50) {
            out.push_str(&format!("  {} \u{2194} {} ({} queries)\n", a, b, count));
        }
        out.push('\n');
    }

    out
}

fn sql_extract_directory(dir: &Path) -> String {
    let mut per_binary: Vec<(String, SqlExtraction)> = Vec::new();
    let mut combined_table_ops: HashMap<String, TableOps> = HashMap::new();
    let mut combined_join_rels: HashMap<(String, String), usize> = HashMap::new();
    let mut total_statements = 0usize;
    let mut binary_table_usage: Vec<(String, Vec<(String, usize)>)> = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return format!("Error reading directory: {e}"),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if ext != "exe" && ext != "dll" {
            continue;
        }

        if let Ok(m) = fs::metadata(&path) {
            if m.len() > MAX_BINARY_SIZE {
                continue;
            }
        }

        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = extract_sql_from_binary(&data);
        if result.statements.is_empty() {
            continue;
        }

        let fname = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        total_statements += result.statements.len();

        // Build per-binary table usage
        let mut binary_tables: HashMap<String, usize> = HashMap::new();
        for stmt in &result.statements {
            for table in &stmt.tables {
                *binary_tables.entry(table.clone()).or_insert(0) += 1;
            }
        }
        let mut bt_sorted: Vec<(String, usize)> = binary_tables.into_iter().collect();
        bt_sorted.sort_by(|a, b| b.1.cmp(&a.1));
        binary_table_usage.push((fname.clone(), bt_sorted));

        // Merge into combined
        for (table, ops) in &result.table_ops {
            let entry = combined_table_ops.entry(table.clone()).or_default();
            entry.selects += ops.selects;
            entry.inserts += ops.inserts;
            entry.updates += ops.updates;
            entry.deletes += ops.deletes;
        }
        for ((a, b), count) in &result.join_relationships {
            *combined_join_rels.entry((a.clone(), b.clone())).or_insert(0) += count;
        }

        per_binary.push((fname, result));
    }

    if per_binary.is_empty() {
        return "No EXE/DLL files with SQL found in directory.".to_string();
    }

    let combined = SqlExtraction {
        statements: Vec::new(), // not needed for formatting
        table_ops: combined_table_ops,
        join_relationships: combined_join_rels,
    };

    let mut out = format_sql_extraction(&combined, None);

    // Replace statement count with the real total
    out = out.replace(
        "Statements: 0",
        &format!("Statements: {}", total_statements),
    );

    // Add per-binary table usage
    out.push_str("\u{2500}\u{2500} Per-Binary Table Usage \u{2500}\u{2500}\n");
    binary_table_usage.sort_by(|a, b| a.0.cmp(&b.0));
    for (fname, tables) in &binary_table_usage {
        let table_strs: Vec<String> = tables.iter().take(10)
            .map(|(t, c)| format!("{}({})", t, c))
            .collect();
        out.push_str(&format!("  {}: {}\n", fname, table_strs.join(", ")));
    }
    out.push('\n');

    out
}

// ── 11. binary_diff ─────────────────────────────────────────────────

pub fn binary_diff(_graph: &Graph, target: &str) -> String {
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
        let dlls1: BTreeSet<String> = imp1.iter().map(|d| d.name.to_lowercase()).collect();
        let dlls2: BTreeSet<String> = imp2.iter().map(|d| d.name.to_lowercase()).collect();

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
            .flat_map(|d| d.functions.iter().map(|f| format!("{}!{}", d.name.to_lowercase(), f)))
            .collect();
        let all_funcs2: BTreeSet<String> = imp2.iter()
            .flat_map(|d| d.functions.iter().map(|f| format!("{}!{}", d.name.to_lowercase(), f)))
            .collect();

        let added_funcs: usize = all_funcs2.difference(&all_funcs1).count();
        let removed_funcs: usize = all_funcs1.difference(&all_funcs2).count();

        out.push_str(&format!("  Added functions: {}\n", added_funcs));
        out.push_str(&format!("  Removed functions: {}\n", removed_funcs));
    } else {
        out.push_str("  (could not parse imports from one or both files)\n");
    }
    out.push('\n');

    // Compare strings — focus on SQL and table references
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
                            tables.insert(tname.to_lowercase());
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
            // Found it — try to extract the fixed version info
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

fn format_file_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

// ── 12. web_api ────────────────────────────────────────────────────

pub fn web_api(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => return format!("Invalid JSON in HAR file: {e}"),
    };

    let entries = match json.get("log").and_then(|l| l.get("entries")).and_then(|e| e.as_array()) {
        Some(e) => e,
        None => return "No log.entries found in HAR file.".to_string(),
    };

    if entries.is_empty() {
        return "No entries in HAR file.".to_string();
    }

    // Collect endpoint data
    let mut endpoints: HashMap<(String, String), HarEndpoint> = HashMap::new();
    let mut static_assets: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    let mut auth_headers: BTreeSet<String> = BTreeSet::new();
    let mut base_urls: HashMap<String, usize> = HashMap::new();
    let mut total_requests = 0usize;

    let static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ];

    for entry in entries {
        let request = match entry.get("request") {
            Some(r) => r,
            None => continue,
        };
        let response = match entry.get("response") {
            Some(r) => r,
            None => continue,
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_uppercase();
        let url_str = match request.get("url").and_then(|u| u.as_str()) {
            Some(u) => u,
            None => continue,
        };

        total_requests += 1;

        // Parse URL manually
        let (base_url, path_str, _query) = parse_url_simple(url_str);
        if !base_url.is_empty() {
            *base_urls.entry(base_url.clone()).or_insert(0) += 1;
        }

        // Check for auth headers
        if let Some(headers) = request.get("headers").and_then(|h| h.as_array()) {
            for header in headers {
                let name = header.get("name").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();
                if name == "authorization" {
                    let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if val.to_lowercase().starts_with("bearer") {
                        auth_headers.insert("Bearer token in Authorization header".to_string());
                    } else if val.to_lowercase().starts_with("basic") {
                        auth_headers.insert("Basic auth in Authorization header".to_string());
                    } else {
                        auth_headers.insert("Authorization header".to_string());
                    }
                } else if name == "x-api-key" {
                    auth_headers.insert("X-API-Key header".to_string());
                } else if name == "cookie" {
                    let val = header.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if val.contains("session") || val.contains("token") || val.contains("auth") {
                        auth_headers.insert("Session cookie".to_string());
                    }
                }
            }
        }

        // Check if this is a static asset
        let path_lower = path_str.to_lowercase();
        let is_static = static_extensions.iter().any(|ext| path_lower.ends_with(ext));

        if is_static {
            let ext = if let Some(dot_pos) = path_lower.rfind('.') {
                path_lower[dot_pos..].to_string()
            } else {
                ".other".to_string()
            };
            let size = response.get("content")
                .and_then(|c| c.get("size"))
                .and_then(|s| s.as_u64())
                .unwrap_or(0) as usize;
            static_assets.entry(ext).or_default().push((path_str.clone(), size));
            continue;
        }

        // Normalize path: replace numeric segments and UUIDs with {id}
        let normalized = normalize_api_path(&path_str);

        let key = (method.clone(), normalized.clone());
        let ep = endpoints.entry(key).or_insert_with(|| HarEndpoint {
            method: method.clone(),
            path: normalized,
            query_params: BTreeSet::new(),
            body_fields: BTreeSet::new(),
            status_codes: BTreeSet::new(),
            content_types: BTreeSet::new(),
            total_time: 0.0,
            call_count: 0,
        });

        ep.call_count += 1;

        // Query parameters
        if let Some(qs) = request.get("queryString").and_then(|q| q.as_array()) {
            for param in qs {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    ep.query_params.insert(name.to_string());
                }
            }
        }

        // Request body fields (JSON only, first level)
        if let Some(post_data) = request.get("postData") {
            let mime = post_data.get("mimeType").and_then(|m| m.as_str()).unwrap_or("");
            if mime.contains("json") {
                if let Some(text) = post_data.get("text").and_then(|t| t.as_str()) {
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(text) {
                        if let Some(obj) = body.as_object() {
                            for key in obj.keys() {
                                ep.body_fields.insert(key.clone());
                            }
                        }
                    }
                }
            }
        }

        // Response status
        let status = response.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
        if status > 0 {
            ep.status_codes.insert(status);
        }

        // Response content type
        if let Some(content) = response.get("content") {
            if let Some(mime) = content.get("mimeType").and_then(|m| m.as_str()) {
                let clean_mime = mime.split(';').next().unwrap_or(mime).trim().to_string();
                if !clean_mime.is_empty() {
                    ep.content_types.insert(clean_mime);
                }
            }
        }

        // Response time
        let time = entry.get("time").and_then(|t| t.as_f64()).unwrap_or(0.0);
        ep.total_time += time;
    }

    if endpoints.is_empty() && static_assets.is_empty() {
        return "No API endpoints or static assets found in HAR file.".to_string();
    }

    // Determine primary base URL
    let primary_base = base_urls.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(url, _)| url.clone())
        .unwrap_or_default();

    // Sort endpoints by path then method
    let mut sorted_eps: Vec<&HarEndpoint> = endpoints.values().collect();
    sorted_eps.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    // Build output
    let mut out = String::new();
    out.push_str("=== Web API Analysis ===\n\n");

    let filename = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| target.to_string());
    out.push_str(&format!("Source: {filename}\n"));
    if !primary_base.is_empty() {
        out.push_str(&format!("Base URL: {primary_base}\n"));
    }
    out.push_str(&format!("Endpoints: {}\n", endpoints.len()));
    out.push_str(&format!("Total requests: {total_requests}\n\n"));

    // Endpoint details
    for ep in &sorted_eps {
        let avg_ms = if ep.call_count > 0 { ep.total_time / ep.call_count as f64 } else { 0.0 };
        out.push_str(&format!("── {} {} ({} calls, avg {:.0}ms) ──\n", ep.method, ep.path, ep.call_count, avg_ms));

        if !ep.query_params.is_empty() {
            let params: Vec<&str> = ep.query_params.iter().map(|s| s.as_str()).collect();
            out.push_str(&format!("  Query params: {}\n", params.join(", ")));
        }

        if !ep.body_fields.is_empty() {
            let fields: Vec<&str> = ep.body_fields.iter().map(|s| s.as_str()).collect();
            out.push_str(&format!("  Body fields: {}\n", fields.join(", ")));
        }

        if !ep.status_codes.is_empty() {
            let status_parts: Vec<String> = ep.status_codes.iter().map(|s| {
                let ct: Vec<&str> = ep.content_types.iter().map(|c| c.as_str()).collect();
                if ct.is_empty() {
                    format!("{s}")
                } else {
                    format!("{s} ({})", ct.join(", "))
                }
            }).collect();
            out.push_str(&format!("  Response: {}\n", status_parts.join(", ")));
        }

        out.push('\n');
    }

    // API Summary
    out.push_str("=== API Summary ===\n");

    // Infer resources from paths
    let mut resources: HashMap<String, [bool; 4]> = HashMap::new(); // [create, read, update, delete]
    for ep in &sorted_eps {
        let segments: Vec<&str> = ep.path.split('/').filter(|s| !s.is_empty() && *s != "{id}").collect();
        if let Some(resource) = segments.last() {
            let resource = resource.to_string();
            let crud = resources.entry(resource).or_insert([false; 4]);
            match ep.method.as_str() {
                "POST" => crud[0] = true,
                "GET" => crud[1] = true,
                "PUT" | "PATCH" => crud[2] = true,
                "DELETE" => crud[3] = true,
                _ => {}
            }
        }
    }

    if !resources.is_empty() {
        let mut res_names: Vec<&String> = resources.keys().collect();
        res_names.sort();
        out.push_str(&format!("  Resources: {}\n", res_names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    if !auth_headers.is_empty() {
        for auth in &auth_headers {
            out.push_str(&format!("  Auth pattern: {auth}\n"));
        }
    }

    if !resources.is_empty() {
        out.push_str("  CRUD coverage:\n");
        let mut res_vec: Vec<(&String, &[bool; 4])> = resources.iter().collect();
        res_vec.sort_by_key(|(name, _)| name.to_lowercase());
        let max_name_len = res_vec.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (name, crud) in &res_vec {
            let c = if crud[0] { "\u{2713}" } else { "\u{2717}" };
            let r = if crud[1] { "\u{2713}" } else { "\u{2717}" };
            let u = if crud[2] { "\u{2713}" } else { "\u{2717}" };
            let d = if crud[3] { "\u{2713}" } else { "\u{2717}" };
            out.push_str(&format!("    {:width$}  CREATE {}  READ {}  UPDATE {}  DELETE {}\n",
                name, c, r, u, d, width = max_name_len));
        }
    }
    out.push('\n');

    // Static assets summary
    if !static_assets.is_empty() {
        out.push_str("=== Static Assets ===\n");

        let asset_categories: &[(&str, &[&str])] = &[
            ("JavaScript", &[".js"]),
            ("CSS", &[".css"]),
            ("Images", &[".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico"]),
            ("Fonts", &[".woff", ".woff2", ".ttf", ".eot"]),
        ];

        for (label, exts) in asset_categories {
            let mut count = 0usize;
            let mut total_size = 0usize;
            for ext in *exts {
                if let Some(assets) = static_assets.get(&ext.to_string()) {
                    count += assets.len();
                    total_size += assets.iter().map(|(_, s)| s).sum::<usize>();
                }
            }
            if count > 0 {
                out.push_str(&format!("  {label}: {count} files ({})\n", format_file_size(total_size)));
            }
        }

        // Other static assets
        let known_exts: BTreeSet<&str> = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".eot"].iter().copied().collect();
        let mut other_count = 0usize;
        let mut other_size = 0usize;
        for (ext, assets) in &static_assets {
            if !known_exts.contains(ext.as_str()) {
                other_count += assets.len();
                other_size += assets.iter().map(|(_, s)| s).sum::<usize>();
            }
        }
        if other_count > 0 {
            out.push_str(&format!("  Other: {other_count} files ({})\n", format_file_size(other_size)));
        }
    }

    out
}

struct HarEndpoint {
    method: String,
    path: String,
    query_params: BTreeSet<String>,
    body_fields: BTreeSet<String>,
    status_codes: BTreeSet<u16>,
    content_types: BTreeSet<String>,
    total_time: f64,
    call_count: usize,
}

fn parse_url_simple(url: &str) -> (String, String, String) {
    // Returns (base_url, path, query)
    // e.g. "https://app.example.com/api/users?page=1"
    //   -> ("https://app.example.com", "/api/users", "page=1")

    let (scheme_host, rest) = if let Some(pos) = url.find("://") {
        let after_scheme = &url[pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            let base = &url[..pos + 3 + slash_pos];
            let rest = &after_scheme[slash_pos..];
            (base.to_string(), rest.to_string())
        } else {
            (url.to_string(), "/".to_string())
        }
    } else {
        (String::new(), url.to_string())
    };

    // Split path and query
    let (path, query) = if let Some(q_pos) = rest.find('?') {
        (rest[..q_pos].to_string(), rest[q_pos + 1..].to_string())
    } else {
        (rest, String::new())
    };

    (scheme_host, path, query)
}

fn normalize_api_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments.iter().map(|seg| {
        if seg.is_empty() {
            String::new()
        } else if is_id_segment(seg) {
            "{id}".to_string()
        } else {
            seg.to_string()
        }
    }).collect();
    normalized.join("/")
}

fn is_id_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }

    // All digits
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // UUID-like: hex chars and dashes, 32+ chars (e.g. 550e8400-e29b-41d4-a716-446655440000)
    if seg.len() >= 32 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }

    false
}

// ── 13. web_dom ────────────────────────────────────────────────────

pub fn web_dom(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading file: {e}"),
    };

    let filename = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| target.to_string());

    // Count total elements by tag
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    let total_elements = count_html_tags(&content, &mut tag_counts);

    // Extract forms
    let forms = extract_forms(&content);

    // Extract tables
    let tables = extract_tables(&content);

    // Extract navigation
    let navs = extract_navs(&content);

    // Extract buttons
    let buttons = extract_buttons(&content);

    // Extract click handlers
    let click_count = count_click_handlers(&content);

    // Extract modals/dialogs
    let modal_count = count_component_patterns(&content, &["modal", "dialog", "popup", "overlay"]);

    // Extract script sources
    let scripts = extract_script_srcs(&content);

    // Extract iframes
    let iframes = extract_iframes(&content);

    // Extract API references from inline JS
    let api_refs = extract_inline_api_refs(&content);

    // Extract data attributes
    let data_attrs = extract_data_attributes(&content);

    // Extract links
    let links = extract_links(&content);

    // Build output
    let mut out = String::new();
    out.push_str("=== Web DOM Analysis ===\n\n");
    out.push_str(&format!("File: {filename}\n"));
    out.push_str(&format!("Total elements: {total_elements}\n\n"));

    // Forms
    if !forms.is_empty() {
        out.push_str(&format!("── Forms ({}) ──\n", forms.len()));
        for form in &forms {
            let id_or_class = if !form.id.is_empty() {
                format!("#{}", form.id)
            } else if !form.class.is_empty() {
                format!(".{}", form.class)
            } else {
                "(unnamed)".to_string()
            };

            let method_action = if !form.action.is_empty() {
                format!("{} {}", form.method.to_uppercase(), form.action)
            } else {
                form.method.to_uppercase()
            };
            out.push_str(&format!("  {} ({})\n", id_or_class, method_action));

            for field in &form.fields {
                let mut desc = format!("    {}: {}", field.name, field.field_type);
                if field.required {
                    desc.push_str(" (required)");
                }
                if !field.placeholder.is_empty() {
                    desc.push_str(&format!(" (placeholder: \"{}\")", field.placeholder));
                }
                out.push_str(&format!("{desc}\n"));
            }
            out.push('\n');
        }
    }

    // Tables
    if !tables.is_empty() {
        out.push_str(&format!("── Tables ({}) ──\n", tables.len()));
        for table in &tables {
            let id_or_class = if !table.id.is_empty() {
                format!("#{}", table.id)
            } else if !table.class.is_empty() {
                format!(".{}", table.class)
            } else {
                "(unnamed)".to_string()
            };
            if !table.headers.is_empty() {
                out.push_str(&format!("  {}: {}\n", id_or_class, table.headers.join(", ")));
            } else {
                out.push_str(&format!("  {} (no headers)\n", id_or_class));
            }
        }
        out.push('\n');
    }

    // Navigation
    if !navs.is_empty() {
        out.push_str("── Navigation ──\n");
        for nav in &navs {
            let nav_id = if !nav.class.is_empty() {
                format!("<nav class=\"{}\">", nav.class)
            } else if !nav.id.is_empty() {
                format!("<nav id=\"{}\">", nav.id)
            } else {
                "<nav>".to_string()
            };
            out.push_str(&format!("  {nav_id}\n"));
            for (text, href) in &nav.links {
                out.push_str(&format!("    {text} -> {href}\n"));
            }
        }
        out.push('\n');
    }

    // Interactive elements
    let button_count = buttons.len();
    if button_count > 0 || click_count > 0 || modal_count > 0 {
        out.push_str("── Interactive Elements ──\n");
        if button_count > 0 {
            out.push_str(&format!("  Buttons: {button_count}\n"));
        }
        if click_count > 0 {
            out.push_str(&format!("  Click handlers: {click_count}\n"));
        }
        if modal_count > 0 {
            out.push_str(&format!("  Modals/Dialogs: {modal_count}\n"));
        }
        out.push('\n');
    }

    // Scripts
    if !scripts.is_empty() {
        out.push_str("── Scripts ──\n");
        for src in &scripts {
            out.push_str(&format!("  {src}\n"));
        }
        out.push('\n');
    }

    // Iframes
    if !iframes.is_empty() {
        out.push_str(&format!("── Iframes ({}) ──\n", iframes.len()));
        for src in &iframes {
            out.push_str(&format!("  {src}\n"));
        }
        out.push('\n');
    }

    // API references from inline JS
    if !api_refs.is_empty() {
        out.push_str("── API References (from inline JS) ──\n");
        for ref_str in &api_refs {
            out.push_str(&format!("  {ref_str}\n"));
        }
        out.push('\n');
    }

    // Data attributes
    if !data_attrs.is_empty() {
        out.push_str(&format!("── Data Attributes ({}) ──\n", data_attrs.len()));
        for attr in data_attrs.iter().take(50) {
            out.push_str(&format!("  {attr}\n"));
        }
        out.push('\n');
    }

    // Links summary
    if !links.is_empty() {
        let internal: Vec<&(String, String)> = links.iter().filter(|(_, href)| !href.starts_with("http://") && !href.starts_with("https://") && !href.starts_with("//")).collect();
        let external: Vec<&(String, String)> = links.iter().filter(|(_, href)| href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//")).collect();
        out.push_str(&format!("── Links ({} internal, {} external) ──\n", internal.len(), external.len()));
        for (text, href) in internal.iter().take(30) {
            if !text.is_empty() {
                out.push_str(&format!("  {text} -> {href}\n"));
            } else {
                out.push_str(&format!("  {href}\n"));
            }
        }
        if internal.len() > 30 {
            out.push_str(&format!("  ... and {} more\n", internal.len() - 30));
        }
        out.push('\n');
    }

    out
}

struct HtmlForm {
    id: String,
    class: String,
    action: String,
    method: String,
    fields: Vec<HtmlFormField>,
}

struct HtmlFormField {
    name: String,
    field_type: String,
    required: bool,
    placeholder: String,
}

struct HtmlTable {
    id: String,
    class: String,
    headers: Vec<String>,
}

struct HtmlNav {
    id: String,
    class: String,
    links: Vec<(String, String)>, // (text, href)
}

fn count_html_tags(content: &str, tag_counts: &mut HashMap<String, usize>) -> usize {
    let mut total = 0usize;
    let mut i = 0;
    let bytes = content.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() && bytes[i + 1] != b'/' && bytes[i + 1] != b'!' {
            // Find tag name
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b' ' && bytes[end] != b'>' && bytes[end] != b'/' && bytes[end] != b'\n' {
                end += 1;
            }
            if end > start {
                let tag = content[start..end].to_lowercase();
                if tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && tag.len() <= 20 {
                    *tag_counts.entry(tag).or_insert(0) += 1;
                    total += 1;
                }
            }
        }
        i += 1;
    }

    total
}

fn extract_forms(content: &str) -> Vec<HtmlForm> {
    let mut forms = Vec::new();
    let lower = content.to_lowercase();
    let mut search_from = 0;

    while let Some(form_start) = lower[search_from..].find("<form") {
        let abs_start = search_from + form_start;
        let form_tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 5; continue; }
        };

        let form_tag = &content[abs_start..=form_tag_end];

        let id = extract_attr_value(form_tag, "id");
        let class = extract_attr_value(form_tag, "class");
        let action = extract_attr_value(form_tag, "action");
        let method = extract_attr_value(form_tag, "method");
        let method = if method.is_empty() { "GET".to_string() } else { method };

        // Find form end
        let form_end = lower[form_tag_end..].find("</form").map(|e| form_tag_end + e).unwrap_or(content.len());
        let form_body = &content[form_tag_end..form_end];

        let fields = extract_form_fields(form_body);

        forms.push(HtmlForm {
            id,
            class,
            action,
            method,
            fields,
        });

        search_from = form_end + 1;
    }

    forms
}

fn extract_form_fields(body: &str) -> Vec<HtmlFormField> {
    let mut fields = Vec::new();
    let lower = body.to_lowercase();

    // Find <input> elements
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<input") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let field_type = extract_attr_value(tag, "type");
        let field_type = if field_type.is_empty() { "text".to_string() } else { field_type };
        let placeholder = extract_attr_value(tag, "placeholder");
        let required = tag.to_lowercase().contains("required");

        if !name.is_empty() || !field_type.is_empty() {
            fields.push(HtmlFormField {
                name: if name.is_empty() { "(unnamed)".to_string() } else { name },
                field_type,
                required,
                placeholder,
            });
        }
        pos = tag_end + 1;
    }

    // Find <select> elements
    pos = 0;
    while let Some(start) = lower[pos..].find("<select") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let required = tag.to_lowercase().contains("required");

        fields.push(HtmlFormField {
            name: if name.is_empty() { "(unnamed)".to_string() } else { name },
            field_type: "select".to_string(),
            required,
            placeholder: String::new(),
        });
        pos = tag_end + 1;
    }

    // Find <textarea> elements
    pos = 0;
    while let Some(start) = lower[pos..].find("<textarea") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &body[abs_start..=tag_end];
        let name = extract_attr_value(tag, "name");
        let placeholder = extract_attr_value(tag, "placeholder");
        let required = tag.to_lowercase().contains("required");

        fields.push(HtmlFormField {
            name: if name.is_empty() { "(unnamed)".to_string() } else { name },
            field_type: "textarea".to_string(),
            required,
            placeholder,
        });
        pos = tag_end + 1;
    }

    fields
}

fn extract_attr_value(tag: &str, attr: &str) -> String {
    let lower = tag.to_lowercase();
    // Try: attr="value" or attr='value'
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        if let Some(start) = lower.find(&pattern) {
            let val_start = start + pattern.len();
            if val_start < tag.len() {
                if let Some(end) = tag[val_start..].find(quote) {
                    return tag[val_start..val_start + end].to_string();
                }
            }
        }
    }
    // Try: attr=value (no quotes, up to space or >)
    let pattern = format!("{attr}=");
    if let Some(start) = lower.find(&pattern) {
        let val_start = start + pattern.len();
        if val_start < tag.len() {
            let rest = &tag[val_start..];
            let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
            let val = &rest[..end];
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    String::new()
}

fn extract_tables(content: &str) -> Vec<HtmlTable> {
    let mut tables = Vec::new();
    let lower = content.to_lowercase();
    let mut search_from = 0;

    while let Some(table_start) = lower[search_from..].find("<table") {
        let abs_start = search_from + table_start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 6; continue; }
        };

        let table_tag = &content[abs_start..=tag_end];
        let id = extract_attr_value(table_tag, "id");
        let class = extract_attr_value(table_tag, "class");

        // Find table end
        let table_end = lower[tag_end..].find("</table").map(|e| tag_end + e).unwrap_or(content.len());
        let table_body = &content[tag_end..table_end];

        // Extract <th> headers
        let mut headers = Vec::new();
        let table_lower = table_body.to_lowercase();
        let mut th_pos = 0;
        while let Some(th_start) = table_lower[th_pos..].find("<th") {
            let abs_th = th_pos + th_start;
            let th_tag_end = match table_lower[abs_th..].find('>') {
                Some(e) => abs_th + e + 1,
                None => break,
            };
            let th_close = table_lower[th_tag_end..].find("</th").map(|e| th_tag_end + e).unwrap_or(table_body.len());
            let header_text = strip_html_tags(&table_body[th_tag_end..th_close]).trim().to_string();
            if !header_text.is_empty() {
                headers.push(header_text);
            }
            th_pos = th_close + 1;
        }

        tables.push(HtmlTable { id, class, headers });

        search_from = table_end + 1;
    }

    tables
}

fn strip_html_tags(s: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(c);
        }
    }
    result
}

fn extract_navs(content: &str) -> Vec<HtmlNav> {
    let mut navs = Vec::new();
    let lower = content.to_lowercase();
    let mut search_from = 0;

    while let Some(nav_start) = lower[search_from..].find("<nav") {
        let abs_start = search_from + nav_start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => { search_from = abs_start + 4; continue; }
        };

        let nav_tag = &content[abs_start..=tag_end];
        let id = extract_attr_value(nav_tag, "id");
        let class = extract_attr_value(nav_tag, "class");

        let nav_end = lower[tag_end..].find("</nav").map(|e| tag_end + e).unwrap_or(content.len());
        let nav_body = &content[tag_end..nav_end];

        let links = extract_links(nav_body);

        navs.push(HtmlNav { id, class, links });

        search_from = nav_end + 1;
    }

    navs
}

fn extract_buttons(content: &str) -> Vec<String> {
    let mut buttons = Vec::new();
    let lower = content.to_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<button") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e + 1,
            None => break,
        };
        let close = lower[tag_end..].find("</button").map(|e| tag_end + e).unwrap_or(content.len());
        let text = strip_html_tags(&content[tag_end..close]).trim().to_string();
        if !text.is_empty() {
            buttons.push(text);
        }
        pos = close + 1;
    }

    buttons
}

fn count_click_handlers(content: &str) -> usize {
    let lower = content.to_lowercase();
    let patterns = ["onclick=", "@click=", "v-on:click=", "(click)="];
    patterns.iter().map(|p| lower.matches(p).count()).sum()
}

fn count_component_patterns(content: &str, patterns: &[&str]) -> usize {
    let lower = content.to_lowercase();
    let mut count = 0usize;
    for pat in patterns {
        // Look for class="...modal..." or id="...modal..." etc.
        let class_pat = format!("class=\"");
        let mut pos = 0;
        while let Some(start) = lower[pos..].find(&class_pat) {
            let abs_start = pos + start + class_pat.len();
            if let Some(end) = lower[abs_start..].find('"') {
                let class_val = &lower[abs_start..abs_start + end];
                if class_val.contains(pat) {
                    count += 1;
                }
            }
            pos = abs_start + 1;
        }
    }
    count
}

fn extract_script_srcs(content: &str) -> Vec<String> {
    let mut srcs = Vec::new();
    let lower = content.to_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<script") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &content[abs_start..=tag_end];
        let src = extract_attr_value(tag, "src");
        if !src.is_empty() {
            srcs.push(src);
        }
        pos = tag_end + 1;
    }

    srcs
}

fn extract_iframes(content: &str) -> Vec<String> {
    let mut iframes = Vec::new();
    let lower = content.to_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<iframe") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e,
            None => break,
        };
        let tag = &content[abs_start..=tag_end];
        let src = extract_attr_value(tag, "src");
        if !src.is_empty() {
            iframes.push(src);
        } else {
            iframes.push("(no src)".to_string());
        }
        pos = tag_end + 1;
    }

    iframes
}

fn extract_inline_api_refs(content: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();

    // Look for fetch('...'), fetch("..."), axios.get('...'), axios.post('...'), etc.
    let patterns = [
        "fetch(", "fetch (", "axios.get(", "axios.post(", "axios.put(",
        "axios.delete(", "axios.patch(", "axios(",
        "XMLHttpRequest", ".open(",
    ];

    for line in content.lines() {
        let trimmed = line.trim();
        for pat in &patterns {
            if let Some(pos) = trimmed.find(pat) {
                // Try to extract the URL argument
                let after = &trimmed[pos + pat.len()..];
                if let Some(url) = extract_string_arg(after) {
                    if url.starts_with('/') || url.starts_with("http") {
                        refs.insert(format!("{}{}", &pat[..pat.len().saturating_sub(1)].trim_end_matches('.'), format!("('{url}')")));
                    }
                }
            }
        }
    }

    refs
}

fn extract_string_arg(s: &str) -> Option<String> {
    let trimmed = s.trim();
    for quote in ['"', '\'', '`'] {
        if trimmed.starts_with(quote) {
            let rest = &trimmed[1..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn extract_data_attributes(content: &str) -> BTreeSet<String> {
    let mut attrs = BTreeSet::new();
    // Simple regex-like scan for data-xxx= patterns
    let bytes = content.as_bytes();
    let prefix = b"data-";

    let mut i = 0;
    while i + prefix.len() < bytes.len() {
        if bytes[i..].starts_with(prefix) {
            // Check it's preceded by space (part of an HTML attribute)
            if i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\n' || bytes[i - 1] == b'\t') {
                let start = i;
                let mut end = i + prefix.len();
                while end < bytes.len() && bytes[end] != b'=' && bytes[end] != b' ' && bytes[end] != b'>' && bytes[end] != b'\n' {
                    end += 1;
                }
                let attr = &content[start..end];
                if attr.len() > 5 && attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    attrs.insert(attr.to_string());
                }
            }
        }
        i += 1;
    }

    attrs
}

fn extract_links(content: &str) -> Vec<(String, String)> {
    let mut links = Vec::new();
    let lower = content.to_lowercase();
    let mut pos = 0;

    while let Some(start) = lower[pos..].find("<a ") {
        let abs_start = pos + start;
        let tag_end = match lower[abs_start..].find('>') {
            Some(e) => abs_start + e + 1,
            None => break,
        };
        let tag = &content[abs_start..tag_end];
        let href = extract_attr_value(tag, "href");

        // Get link text (up to </a>)
        let close = lower[tag_end..].find("</a").map(|e| tag_end + e).unwrap_or(content.len().min(tag_end + 200));
        let text = strip_html_tags(&content[tag_end..close]).trim().to_string();
        let text = if text.len() > 60 { format!("{}...", &text[..57]) } else { text };

        if !href.is_empty() && href != "#" {
            links.push((text, href));
        }
        pos = tag_end;
    }

    links
}

// ── 14. web_sitemap ────────────────────────────────────────────────

pub fn web_sitemap(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("Path not found: {target}");
    }

    // Collect HTML files
    let html_files = if path.is_dir() {
        collect_html_files(path)
    } else {
        vec![path.to_path_buf()]
    };

    if html_files.is_empty() {
        return "No HTML files found.".to_string();
    }

    // Parse each file
    let mut pages: HashMap<String, SitemapPage> = HashMap::new();

    for file in &html_files {
        let content = match fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Derive a page path from the file path relative to root
        let page_path = if path.is_dir() {
            file.strip_prefix(path)
                .map(|p| {
                    let s = p.to_string_lossy().to_string();
                    let s = s.replace('\\', "/");
                    // index.html -> /
                    if s == "index.html" || s == "index.htm" {
                        "/".to_string()
                    } else {
                        let s = s.trim_end_matches("/index.html").trim_end_matches("/index.htm");
                        format!("/{s}")
                    }
                })
                .unwrap_or_else(|_| file.to_string_lossy().to_string())
        } else {
            file.file_name().map(|f| format!("/{}", f.to_string_lossy())).unwrap_or_else(|| "/".to_string())
        };

        // Extract title
        let title = extract_title(&content);

        // Extract all links
        let links = extract_links(&content);

        // Extract form actions
        let forms = extract_forms(&content);
        let form_urls: Vec<String> = forms.iter()
            .filter(|f| !f.action.is_empty())
            .map(|f| f.action.clone())
            .collect();

        // Separate internal vs external links
        let mut internal_links: Vec<String> = Vec::new();
        let mut external_links: Vec<String> = Vec::new();

        for (_, href) in &links {
            let href = href.split('#').next().unwrap_or(href).to_string();
            let href = href.split('?').next().unwrap_or(&href).to_string();
            if href.is_empty() || href == "/" && page_path == "/" {
                continue;
            }
            if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
                external_links.push(href);
            } else if href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("javascript:") {
                continue;
            } else {
                internal_links.push(href);
            }
        }

        for url in &form_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                internal_links.push(url.clone());
            }
        }

        internal_links.sort();
        internal_links.dedup();
        external_links.sort();
        external_links.dedup();

        pages.insert(page_path, SitemapPage {
            title,
            internal_links,
            external_links,
        });
    }

    if pages.is_empty() {
        return "No pages parsed.".to_string();
    }

    // Count incoming links for each page
    let mut incoming_count: HashMap<String, usize> = HashMap::new();
    for page in pages.values() {
        for link in &page.internal_links {
            *incoming_count.entry(link.clone()).or_insert(0) += 1;
        }
    }

    let total_internal: usize = pages.values().map(|p| p.internal_links.len()).sum();
    let total_external: usize = pages.values().map(|p| p.external_links.len()).sum();

    // Build output
    let mut out = String::new();
    out.push_str("=== Web Sitemap ===\n\n");
    out.push_str(&format!("Pages: {}\n", pages.len()));
    out.push_str(&format!("Internal links: {total_internal}\n"));
    out.push_str(&format!("External links: {total_external}\n\n"));

    // Site structure: build tree from paths
    out.push_str("── Site Structure ──\n");
    let mut sorted_pages: Vec<(&String, &SitemapPage)> = pages.iter().collect();
    sorted_pages.sort_by_key(|(path, _)| path.to_lowercase());

    for (page_path, page) in &sorted_pages {
        let depth = page_path.matches('/').count().saturating_sub(1);
        let indent = "  ".repeat(depth + 1);
        let title_str = if !page.title.is_empty() {
            format!(" ({})", page.title)
        } else {
            String::new()
        };
        out.push_str(&format!("{indent}{page_path}{title_str} -> {} links\n", page.internal_links.len()));
    }
    out.push('\n');

    // Hub pages (most outgoing links)
    let mut hubs: Vec<(&String, usize)> = pages.iter()
        .map(|(path, page)| (path, page.internal_links.len()))
        .filter(|(_, count)| *count > 0)
        .collect();
    hubs.sort_by(|a, b| b.1.cmp(&a.1));

    if !hubs.is_empty() {
        out.push_str("── Hub Pages (most links) ──\n");
        for (path, count) in hubs.iter().take(10) {
            out.push_str(&format!("  {path}: {count} outgoing links\n"));
        }
        out.push('\n');
    }

    // Entry points (no incoming internal links)
    let entry_points: Vec<&String> = pages.keys()
        .filter(|path| incoming_count.get(*path).copied().unwrap_or(0) == 0)
        .collect();

    if !entry_points.is_empty() {
        out.push_str("── Entry Points (no incoming links) ──\n");
        for path in &entry_points {
            out.push_str(&format!("  {path}\n"));
        }
        out.push('\n');
    }

    // Dead ends (no outgoing internal links)
    let dead_ends: Vec<&String> = pages.iter()
        .filter(|(_, page)| page.internal_links.is_empty())
        .map(|(path, _)| path)
        .collect();

    if !dead_ends.is_empty() {
        out.push_str("── Dead Ends (no outgoing internal links) ──\n");
        for path in &dead_ends {
            out.push_str(&format!("  {path}\n"));
        }
        out.push('\n');
    }

    // External links summary
    let mut ext_domains: HashMap<String, usize> = HashMap::new();
    for page in pages.values() {
        for link in &page.external_links {
            let domain = extract_domain_from_url(link);
            if !domain.is_empty() {
                *ext_domains.entry(domain).or_insert(0) += 1;
            }
        }
    }

    if !ext_domains.is_empty() {
        out.push_str("── External Links ──\n");
        let mut ext_sorted: Vec<(&String, &usize)> = ext_domains.iter().collect();
        ext_sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (domain, count) in ext_sorted.iter().take(20) {
            out.push_str(&format!("  {domain}: {count} references\n"));
        }
        out.push('\n');
    }

    out
}

struct SitemapPage {
    title: String,
    internal_links: Vec<String>,
    external_links: Vec<String>,
}

fn collect_html_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_html_files(&path));
            } else if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "html" || ext == "htm" {
                    files.push(path);
                }
            }
        }
    }
    files
}

fn extract_title(content: &str) -> String {
    let lower = content.to_lowercase();
    if let Some(start) = lower.find("<title") {
        if let Some(tag_end) = lower[start..].find('>') {
            let after = start + tag_end + 1;
            if let Some(close) = lower[after..].find("</title") {
                let title = content[after..after + close].trim().to_string();
                return strip_html_tags(&title);
            }
        }
    }
    String::new()
}

fn extract_domain_from_url(url: &str) -> String {
    let url = url.trim_start_matches("//");
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    after_scheme.split('/').next().unwrap_or("").to_string()
}
