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
