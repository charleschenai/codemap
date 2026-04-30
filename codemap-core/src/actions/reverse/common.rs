use std::fs;
use std::path::Path;

pub const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024; // 256 MB

pub struct Section {
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_offset: usize,
    pub raw_size: usize,
}

pub fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset {offset}"));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

pub fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
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

pub fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
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

pub fn read_cstring(data: &[u8], offset: usize) -> String {
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

pub fn parse_sections(data: &[u8], start: usize, count: usize) -> Result<Vec<Section>, String> {
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

pub fn rva_to_offset(rva: usize, sections: &[Section]) -> Option<usize> {
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

pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    const MAX_STRINGS: usize = 50_000;
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (0x20..=0x7E).contains(&byte) {
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

pub fn is_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

pub fn format_file_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

pub fn read_utf16le(data: &[u8], start: usize, end: usize) -> String {
    let mut chars: Vec<u16> = Vec::new();
    let mut i = start;
    while i + 1 < end {
        chars.push(u16::from_le_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&chars)
}

pub fn align4(pos: usize) -> usize {
    (pos + 3) & !3
}

/// Read binary file with size check, returning data or error string.
pub fn read_binary_file(target: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(target);
    if !path.exists() {
        return Err(format!("File not found: {target}"));
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Err(format!("Error: {e}")),
    };
    if meta.len() > MAX_BINARY_SIZE {
        return Err(format!("File too large ({} bytes, max 256 MB)", meta.len()));
    }

    fs::read(path).map_err(|e| format!("Error reading file: {e}"))
}

/// Promote a list of binary-extracted strings to StringLiteral nodes.
/// Each string becomes a node with id `str:<binary>:<short-hash>`,
/// classified via crate::strings::classify, and linked back to the
/// binary via a `binary→string` edge. URL-classified strings are
/// additionally promoted to HttpEndpoint nodes (matches the existing
/// source-code URL-promotion pipeline) so meta-path queries like
/// "pe->string->endpoint" work uniformly.
///
/// `bin_kind` is "pe" / "elf" / "macho" — used to construct the
/// binary node id and the string node id prefix.
///
/// Caps the number of nodes registered at 5000 per binary to keep
/// graphs sane on huge stripped binaries with millions of strings.
/// Skips strings shorter than 6 chars and longer than 4 KB.
pub fn promote_strings_to_graph(
    graph: &mut crate::types::Graph,
    target: &str,
    bin_kind: &str,
    strings: &[String],
) {
    use crate::types::EntityKind;
    let bin_id = format!("{bin_kind}:{target}");
    let mut registered = 0usize;
    const MAX_STRINGS_PER_BINARY: usize = 5000;
    for s in strings {
        if registered >= MAX_STRINGS_PER_BINARY { break; }
        if s.len() < 6 || s.len() > 4096 { continue; }
        let st = crate::strings::classify(s);
        let hash = short_hash(s);
        let str_id = format!("str:{bin_kind}:{}:{}", target_basename(target), hash);
        let display = if s.len() > 200 { &s[..200] } else { s.as_str() };
        graph.ensure_typed_node(&str_id, EntityKind::StringLiteral, &[
            ("value", display),
            ("string_type", st.as_str()),
            ("source_binary", target),
            ("length", &s.len().to_string()),
        ]);
        graph.add_edge(&bin_id, &str_id);

        // URL strings: promote to HttpEndpoint and add string→endpoint edge.
        if matches!(st, crate::strings::StringType::Url) {
            let ep_id = format!("ep:{}", normalize_url(s));
            graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
                ("url", display),
                ("source_kind", bin_kind),
                ("discovered_via", "binary_string"),
            ]);
            graph.add_edge(&str_id, &ep_id);
        }
        registered += 1;
    }
}

fn short_hash(s: &str) -> String {
    // FNV-1a 64-bit, hex-encoded; deterministic and stable.
    let mut h = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn target_basename(target: &str) -> String {
    Path::new(target)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| target.to_string())
}

fn normalize_url(url: &str) -> String {
    // Strip whitespace, query strings, and fragment for endpoint id.
    let clean = url.trim();
    let head = clean.split_whitespace().next().unwrap_or(clean);
    let no_frag = head.split('#').next().unwrap_or(head);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    no_query.to_string()
}
