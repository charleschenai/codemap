use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use crate::types::Graph;

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

pub fn clarion_schema(_graph: &mut Graph, target: &str) -> String {
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

pub fn pe_strings(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
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
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
            }
            current.clear();
        }
    }

    // Don't forget the last string
    if current.len() >= min_len {
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
        s
    } else {
        &s[..max]
    }
}

// ── 3. pe_exports ───────────────────────────────────────────────────

pub fn pe_exports(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
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

pub fn pe_imports(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("Error reading file: {e}"),
    };

    match parse_pe_imports(&data) {
        Ok(result) => result,
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

fn parse_pe_imports(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("File too small for PE".to_string());
    }

    // Check DOS header magic "MZ"
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ magic)".to_string());
    }

    // e_lfanew at offset 0x3C
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

    // COFF header at e_lfanew + 4
    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return Err("Truncated COFF header".to_string());
    }

    let num_sections = read_u16(data, coff_start + 2)? as usize;
    let optional_header_size = read_u16(data, coff_start + 16)? as usize;

    // Optional header
    let opt_start = coff_start + 20;
    if opt_start + optional_header_size > data.len() {
        return Err("Truncated optional header".to_string());
    }

    // Determine PE32 vs PE32+
    let opt_magic = read_u16(data, opt_start)?;
    let is_pe64 = match opt_magic {
        0x10B => false, // PE32
        0x20B => true,  // PE32+ (PE64)
        _ => return Err(format!("Unknown optional header magic: 0x{:X}", opt_magic)),
    };

    // Import table is data directory entry 1 (second entry)
    // PE32: data directories start at optional_header + 96, import = entry 1 => +104
    // PE64: data directories start at optional_header + 112, import = entry 1 => +120
    let import_dir_offset = if is_pe64 {
        opt_start + 120
    } else {
        opt_start + 104
    };

    if import_dir_offset + 8 > data.len() {
        return Err("No import data directory entry".to_string());
    }

    let import_rva = read_u32(data, import_dir_offset)? as usize;
    let import_size = read_u32(data, import_dir_offset + 4)? as usize;

    if import_rva == 0 || import_size == 0 {
        return Err("No import directory".to_string());
    }

    // Parse section headers
    let sections_start = opt_start + optional_header_size;
    let sections = parse_sections(data, sections_start, num_sections)?;

    let import_offset = rva_to_offset(import_rva, &sections)
        .ok_or_else(|| "Cannot resolve import table RVA to file offset".to_string())?;

    // Read Import Directory Table: array of 20-byte entries until all-zero
    let mut dlls: Vec<ImportedDll> = Vec::new();
    let mut entry_offset = import_offset;

    loop {
        if entry_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = read_u32(data, entry_offset)? as usize;
        let name_rva = read_u32(data, entry_offset + 12)? as usize;
        let first_thunk = read_u32(data, entry_offset + 16)? as usize;

        // All-zero entry marks the end
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        // Read DLL name
        let dll_name = if name_rva != 0 {
            match rva_to_offset(name_rva, &sections) {
                Some(off) => read_cstring(data, off),
                None => String::from("<unknown>"),
            }
        } else {
            String::from("<unknown>")
        };

        // Read imported functions from ILT (OriginalFirstThunk) or IAT (FirstThunk) as fallback
        let ilt_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut functions: Vec<String> = Vec::new();

        if ilt_rva != 0 {
            if let Some(ilt_offset) = rva_to_offset(ilt_rva, &sections) {
                let entry_size = if is_pe64 { 8usize } else { 4usize };
                let mut i = 0usize;

                loop {
                    let pos = ilt_offset + i * entry_size;
                    if pos + entry_size > data.len() {
                        break;
                    }

                    if is_pe64 {
                        let val = read_u64(data, pos)?;
                        if val == 0 {
                            break;
                        }
                        if val & (1u64 << 63) != 0 {
                            // Import by ordinal
                            let ordinal = val & 0xFFFF;
                            functions.push(format!("Ordinal({})", ordinal));
                        } else {
                            // Import by name: bits 0-30 = Hint/Name RVA
                            let hint_name_rva = (val & 0x7FFFFFFF) as usize;
                            if let Some(hn_offset) = rva_to_offset(hint_name_rva, &sections) {
                                // Skip 2-byte hint, read null-terminated name
                                if hn_offset + 2 < data.len() {
                                    let name = read_cstring(data, hn_offset + 2);
                                    if !name.is_empty() {
                                        functions.push(name);
                                    }
                                }
                            }
                        }
                    } else {
                        let val = read_u32(data, pos)? as u32;
                        if val == 0 {
                            break;
                        }
                        if val & (1u32 << 31) != 0 {
                            // Import by ordinal
                            let ordinal = val & 0xFFFF;
                            functions.push(format!("Ordinal({})", ordinal));
                        } else {
                            // Import by name
                            let hint_name_rva = (val & 0x7FFFFFFF) as usize;
                            if let Some(hn_offset) = rva_to_offset(hint_name_rva, &sections) {
                                if hn_offset + 2 < data.len() {
                                    let name = read_cstring(data, hn_offset + 2);
                                    if !name.is_empty() {
                                        functions.push(name);
                                    }
                                }
                            }
                        }
                    }

                    i += 1;
                    // Safety: cap at 10000 imports per DLL
                    if i > 10_000 {
                        break;
                    }
                }
            }
        }

        dlls.push(ImportedDll {
            name: dll_name,
            functions,
        });

        entry_offset += 20;

        // Safety: cap at 500 DLLs
        if dlls.len() > 500 {
            break;
        }
    }

    if dlls.is_empty() {
        return Ok("No imports found in PE binary.".to_string());
    }

    // Format output
    let total_functions: usize = dlls.iter().map(|d| d.functions.len()).sum();

    let mut out = String::new();
    out.push_str("=== PE Import Analysis ===\n\n");
    out.push_str(&format!("DLLs: {}\n", dlls.len()));
    out.push_str(&format!("Total imported functions: {total_functions}\n\n"));

    for dll in &dlls {
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

    for dll in &dlls {
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

    Ok(out)
}

// ── 5. pe_resources ────────────────────────────────────────────────

pub fn pe_resources(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
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
            collect_rsrc_data_entries(data, subdir_offset, rsrc_base, sections, &mut entries);
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
) {
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
                collect_rsrc_data_entries(data, sub_offset, rsrc_base, sections, out);
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
    let string_values = parse_version_children(data, pos, end);
    for (k, v) in &string_values {
        out.push_str(&format!("  {}: {}\n", k, v));
    }

    out
}

/// Parse StringFileInfo children to extract key-value pairs
fn parse_version_children(data: &[u8], start: usize, end: usize) -> Vec<(String, String)> {
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
            let sub_results = parse_version_children(data, val_pos, child_end);
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
            let sub_results = parse_version_children(data, val_pos, child_end);
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

pub fn pe_debug(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
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

pub fn dbf_schema(_graph: &mut Graph, target: &str) -> String {
    let path = Path::new(target);
    if !path.exists() {
        return format!("File not found: {target}");
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
