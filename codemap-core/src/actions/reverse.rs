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
