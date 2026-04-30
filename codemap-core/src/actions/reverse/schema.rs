use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use crate::types::Graph;

use super::common::*;

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
    let lower = line.to_ascii_lowercase();
    let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
    if parts.len() < 2 {
        return None;
    }

    let rest = parts[1].trim();
    if !rest.to_ascii_lowercase().starts_with("file,") && !rest.to_ascii_lowercase().starts_with("file ") {
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
    let lower = line.to_ascii_lowercase();
    if let Some(start) = lower.find(&prefix.to_ascii_lowercase()) {
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

    let rest = parts[1].trim().to_ascii_lowercase();
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
    parts[1].trim().to_ascii_lowercase().starts_with("record")
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
    let type_str = parts[1].trim().to_ascii_lowercase();

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
    let table_names: Vec<String> = tables.iter().map(|t| t.name.to_ascii_lowercase()).collect();

    for table in tables {
        let key_fields: Vec<String> = table.keys.iter()
            .flat_map(|k| k.fields.clone())
            .collect();
        table_keys.insert(table.name.to_ascii_lowercase(), key_fields);
    }

    // For each table, look at fields that might reference another table
    for table in tables {
        for field in &table.fields {
            let fname = field.name.to_ascii_lowercase();

            // Pattern: field ends with _id or _key or _code
            let suffixes = ["_id", "_key", "_code", "_no", "_num"];
            for suffix in &suffixes {
                if fname.ends_with(suffix) {
                    let potential_table = &fname[..fname.len() - suffix.len()];
                    // Check if a table with this name or similar exists
                    for tname in &table_names {
                        if tname == &table.name.to_ascii_lowercase() {
                            continue;
                        }
                        // Match: vendor_id -> vendor table, cust_id -> customer table
                        if tname.starts_with(potential_table) || potential_table.starts_with(&tname[..tname.len().min(4)]) {
                            // Verify the target table has a key on this field
                            if let Some(keys) = table_keys.get(tname) {
                                let has_matching_key = keys.iter().any(|k| {
                                    let kl = k.to_ascii_lowercase();
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

// ── 2. dbf_schema ─────────────────────────────────────────────────

pub fn dbf_schema(_graph: &Graph, target: &str) -> String {
    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
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

// ── 3. sql_extract ─────────────────────────────────────────────────

pub fn sql_extract(_graph: &Graph, target: &str) -> String {
    let path = Path::new(target);

    if path.is_dir() {
        // Directory mode: scan all EXE/DLL files
        return sql_extract_directory(path);
    }

    let data = match read_binary_file(target) {
        Ok(d) => d,
        Err(e) => return e,
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
                    tables.insert(clean.to_ascii_lowercase());
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
                        let clean_t = t.trim_matches(|c: char| c == '[' || c == ']').to_ascii_lowercase();
                        let clean_join = if let Some(dot) = join_table.rfind('.') {
                            join_table[dot + 1..].to_ascii_lowercase()
                        } else {
                            join_table.to_ascii_lowercase()
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
            .to_ascii_lowercase();

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
