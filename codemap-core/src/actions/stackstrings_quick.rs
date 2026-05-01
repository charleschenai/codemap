// ── Stackstrings Quick Regex Scan — FLOSS port ──────────────────────
//
// Pure-static byte-pattern scan over .text for the classic
// stack-string compiler-emitted shapes:
//
//   amd64:  48 BA <8 byte imm>      ; mov rdx, imm64
//           48 B8 <8 byte imm>      ; mov rax, imm64
//           81 78 ?? <4 byte imm>   ; cmp dword [rax+disp8], imm32
//           81 79 ?? <4 byte imm>   ; cmp dword [rcx+disp8], imm32
//           81 7B ?? <4 byte imm>   ; cmp dword [rbx+disp8], imm32
//           81 7C ?? <4 byte imm>   ; cmp dword [rsp+...]  (often 5-byte SIB)
//           81 7D ?? <4 byte imm>   ; cmp dword [rbp+disp8], imm32
//
//   i386:   81 F9 <4 byte imm>      ; cmp ecx, imm32
//           81 38 <4 byte imm>      ; cmp dword [eax], imm32
//           81 7D ?? <4 byte imm>   ; cmp dword [ebp+disp8], imm32
//           C7 45 ?? <4 byte imm>   ; mov dword [ebp+disp8], imm32
//           C7 04 24 <4 byte imm>   ; mov dword [esp], imm32
//
// Source: FLOSS `floss/language/go/extract.py:69-137`. License: Apache-
// 2.0. This is a clean reimplementation, not a source copy.
//
// Recall: lower than FLOSS's emulation path (which actually executes
// the function and snapshots the stack) — gets the easy wins for free.
// Useful as a triage signal even on non-Go binaries.

use crate::types::{EntityKind, Graph};

/// Min printable run length to call a hit. FLOSS uses 4 bytes per
/// `cmp imm32`; we require all 4 to be printable (or all 4 of an 8-byte
/// imm64 — printable bytes need only show up in the low half).
const MIN_PRINTABLE_BYTES: usize = 4;

/// Cap nodes per binary to keep noisy strippable corpora tractable.
const MAX_HITS_PER_BINARY: usize = 5_000;

pub fn stackstrings_quick(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap stackstrings-quick <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let (format, text_bytes, text_va) = match locate_text(&data) {
        Some(t) => t,
        None => return format!("Failed to locate .text section in {target}"),
    };

    let hits = scan_text(text_bytes, text_va);
    register_into_graph(graph, target, format, &hits);
    format_report(target, format, text_bytes.len(), &hits)
}

#[derive(Debug, Clone)]
struct Hit {
    /// VA of the matched cmp / mov instruction.
    va: u64,
    /// Decoded printable bytes from the immediate.
    text: String,
    /// "amd64" / "i386".
    arch: &'static str,
    /// Pattern shape — "cmp_reg_imm" / "cmp_mem_imm" / "mov_imm64" /
    /// "mov_mem_imm" — for downstream filtering.
    pattern: &'static str,
}

// ── Header walks (PE + ELF) ────────────────────────────────────────

fn locate_text(data: &[u8]) -> Option<(&'static str, &[u8], u64)> {
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        return locate_text_elf(data).map(|(b, v)| ("elf", b, v));
    }
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        return locate_text_pe(data).map(|(b, v)| ("pe", b, v));
    }
    None
}

fn locate_text_pe(data: &[u8]) -> Option<(&[u8], u64)> {
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return None;
    }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = coff + 20;
    if opt_off + 32 > data.len() {
        return None;
    }
    let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_pe32_plus = opt_magic == 0x20b;
    let image_base: u64 = if is_pe32_plus {
        u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0u8; 8]))
    } else {
        u32::from_le_bytes([data[opt_off + 28], data[opt_off + 29], data[opt_off + 30], data[opt_off + 31]]) as u64
    };
    let sec_table = coff + 20 + opt_size;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() {
            return None;
        }
        let name_bytes = &data[off..off + 8];
        if !name_bytes.starts_with(b".text") {
            continue;
        }
        let virt_addr =
            u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_size =
            u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as usize;
        let raw_off =
            u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
        let end = (raw_off + raw_size).min(data.len());
        return Some((&data[raw_off..end], image_base + virt_addr));
    }
    None
}

fn locate_text_elf(data: &[u8]) -> Option<(&[u8], u64)> {
    if data.len() < 64 {
        return None;
    }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let read_u32 = |off: usize| -> u32 {
        if off + 4 > data.len() {
            return 0;
        }
        if little_endian {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        } else {
            u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        }
    };
    let read_u64 = |off: usize| -> u64 {
        if off + 8 > data.len() {
            return 0;
        }
        if little_endian {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
        } else {
            u64::from_be_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
        }
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() {
            return 0;
        }
        if little_endian {
            u16::from_le_bytes([data[off], data[off + 1]])
        } else {
            u16::from_be_bytes([data[off], data[off + 1]])
        }
    };
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        (
            read_u64(0x28) as usize,
            read_u16(0x3a) as usize,
            read_u16(0x3c) as usize,
            read_u16(0x3e) as usize,
        )
    } else {
        (
            read_u32(0x20) as usize,
            read_u16(0x2e) as usize,
            read_u16(0x30) as usize,
            read_u16(0x32) as usize,
        )
    };
    if e_shoff == 0 || e_shentsize == 0 {
        return None;
    }
    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = if is_64 {
        read_u64(shstr_hdr + 0x18) as usize
    } else {
        read_u32(shstr_hdr + 0x10) as usize
    };
    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() {
            break;
        }
        let name_idx = read_u32(hdr) as usize;
        let (offset, size, addr) = if is_64 {
            (read_u64(hdr + 0x18), read_u64(hdr + 0x20), read_u64(hdr + 0x10))
        } else {
            (
                read_u32(hdr + 0x10) as u64,
                read_u32(hdr + 0x14) as u64,
                read_u32(hdr + 0x0c) as u64,
            )
        };
        let mut name = String::new();
        if shstrtab_off + name_idx < data.len() {
            let mut end = shstrtab_off + name_idx;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
        }
        if name == ".text" {
            let off = offset as usize;
            let end = (off + size as usize).min(data.len());
            if off >= data.len() {
                return None;
            }
            return Some((&data[off..end], addr));
        }
    }
    None
}

// ── Pattern scanner ────────────────────────────────────────────────

fn scan_text(text: &[u8], text_va: u64) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    let n = text.len();
    let mut i = 0usize;
    while i < n {
        if out.len() >= MAX_HITS_PER_BINARY {
            break;
        }
        // ── amd64: mov reg64, imm64 (10-byte forms) ──
        if i + 10 <= n && text[i] == 0x48 && (text[i + 1] == 0xBA || text[i + 1] == 0xB8 || text[i + 1] == 0xB9 || text[i + 1] == 0xBB || text[i + 1] == 0xBE || text[i + 1] == 0xBF) {
            let imm = &text[i + 2..i + 10];
            if let Some(s) = decode_printable(imm) {
                out.push(Hit {
                    va: text_va + i as u64,
                    text: s,
                    arch: "amd64",
                    pattern: "mov_imm64",
                });
                i += 10;
                continue;
            }
        }
        // ── amd64: cmp dword [reg+disp8], imm32 (7-byte form: 81 7? ?? imm32) ──
        if i + 7 <= n && text[i] == 0x81 && matches!(text[i + 1], 0x78 | 0x79 | 0x7A | 0x7B | 0x7D | 0x7E | 0x7F) {
            let imm = &text[i + 3..i + 7];
            if let Some(s) = decode_printable(imm) {
                out.push(Hit {
                    va: text_va + i as u64,
                    text: s,
                    arch: "amd64",
                    pattern: "cmp_mem_imm",
                });
                i += 7;
                continue;
            }
        }
        // ── i386 / amd64-shared: cmp r/m32, imm32 reg-direct
        //                       (81 F9 imm32 = cmp ecx, imm32; 81 F8...) ──
        if i + 6 <= n && text[i] == 0x81 && matches!(text[i + 1], 0xF8 | 0xF9 | 0xFA | 0xFB | 0xFD | 0xFE | 0xFF) {
            let imm = &text[i + 2..i + 6];
            if let Some(s) = decode_printable(imm) {
                out.push(Hit {
                    va: text_va + i as u64,
                    text: s,
                    arch: "i386",
                    pattern: "cmp_reg_imm",
                });
                i += 6;
                continue;
            }
        }
        // ── i386: cmp dword [eax], imm32 (81 38 imm32, 6 bytes) ──
        if i + 6 <= n && text[i] == 0x81 && (text[i + 1] == 0x38 || text[i + 1] == 0x39 || text[i + 1] == 0x3A || text[i + 1] == 0x3B || text[i + 1] == 0x3E || text[i + 1] == 0x3F) {
            let imm = &text[i + 2..i + 6];
            if let Some(s) = decode_printable(imm) {
                out.push(Hit {
                    va: text_va + i as u64,
                    text: s,
                    arch: "i386",
                    pattern: "cmp_mem_imm",
                });
                i += 6;
                continue;
            }
        }
        // ── i386: mov dword [ebp+disp8], imm32 (C7 45 disp8 imm32, 7 bytes) ──
        if i + 7 <= n && text[i] == 0xC7 && (text[i + 1] == 0x45 || text[i + 1] == 0x44 || text[i + 1] == 0x42 || text[i + 1] == 0x41 || text[i + 1] == 0x40 || text[i + 1] == 0x46 || text[i + 1] == 0x47 || text[i + 1] == 0x43) {
            let imm = &text[i + 3..i + 7];
            if let Some(s) = decode_printable(imm) {
                out.push(Hit {
                    va: text_va + i as u64,
                    text: s,
                    arch: "i386",
                    pattern: "mov_mem_imm",
                });
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Return the bytes as a UTF-8 string if all are printable ASCII or
/// runs of zero (allow trailing nulls — common for short stack strings
/// padded to 4/8 bytes). Reject if fewer than `MIN_PRINTABLE_BYTES`
/// printable characters present.
fn decode_printable(bytes: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(bytes.len());
    let mut printable_run = 0usize;
    let mut last_was_zero = false;
    for &b in bytes {
        if b == 0 {
            last_was_zero = true;
            continue;
        }
        if last_was_zero && printable_run > 0 {
            // Embedded null after printable run — not a clean string.
            return None;
        }
        if !is_printable_ascii(b) {
            return None;
        }
        out.push(b as char);
        printable_run += 1;
    }
    if printable_run < MIN_PRINTABLE_BYTES {
        return None;
    }
    Some(out)
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

// ── Graph emission + report ─────────────────────────────────────────

fn register_into_graph(graph: &mut Graph, target: &str, format: &'static str, hits: &[Hit]) {
    if hits.is_empty() {
        return;
    }
    let bin_id = if format == "pe" {
        format!("pe:{target}")
    } else {
        format!("elf:{target}")
    };
    let kind = if format == "pe" {
        EntityKind::PeBinary
    } else {
        EntityKind::ElfBinary
    };
    graph.ensure_typed_node(&bin_id, kind, &[("path", target)]);

    for h in hits {
        let s_id = format!("string:{target}::stackstring::{:#x}", h.va);
        let va_s = format!("{:#x}", h.va);
        graph.ensure_typed_node(
            &s_id,
            EntityKind::StringLiteral,
            &[
                ("string_type", "stackstring"),
                ("value", h.text.as_str()),
                ("offset", va_s.as_str()),
                ("arch", h.arch),
                ("pattern", h.pattern),
            ],
        );
        graph.add_edge(&bin_id, &s_id);
    }
}

fn format_report(target: &str, format: &'static str, text_size: usize, hits: &[Hit]) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== Stackstrings Quick: {target} ===\n\n"));
    out.push_str(&format!("Format:           {format}\n"));
    out.push_str(&format!(".text bytes:      {text_size}\n"));
    out.push_str(&format!("Stackstrings:     {} (capped at {MAX_HITS_PER_BINARY})\n", hits.len()));
    out.push('\n');
    if hits.is_empty() {
        out.push_str("No stack-string compiler patterns matched.\n");
        out.push_str("(Pure-regex pre-pass — emulation-based recall lives in FLOSS proper.)\n");
        return out;
    }
    let n_show = 50.min(hits.len());
    for h in hits.iter().take(n_show) {
        out.push_str(&format!(
            "  {:#012x}  [{:<5}] [{:<13}] {:?}\n",
            h.va, h.arch, h.pattern, h.text
        ));
    }
    if hits.len() > n_show {
        out.push_str(&format!("  ... and {} more\n", hits.len() - n_show));
    }
    out.push('\n');
    out.push_str("Try: codemap pagerank --type string         (rank stackstrings cross-binary)\n");
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_amd64_mov_imm64() {
        // mov rax, 0x6f6c6c6548 ('Hello' little-endian, with 3 trailing nulls)
        // 48 B8 48 65 6C 6C 6F 00 00 00
        let bytes = vec![0x48, 0xB8, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00];
        let hits = scan_text(&bytes, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "Hello");
        assert_eq!(hits[0].pattern, "mov_imm64");
    }

    #[test]
    fn detects_i386_cmp_reg_imm() {
        // cmp ecx, 0x44434241 ('ABCD' little-endian)
        // 81 F9 41 42 43 44
        let bytes = vec![0x81, 0xF9, 0x41, 0x42, 0x43, 0x44];
        let hits = scan_text(&bytes, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "ABCD");
        assert_eq!(hits[0].arch, "i386");
        assert_eq!(hits[0].pattern, "cmp_reg_imm");
    }

    #[test]
    fn detects_i386_mov_to_ebp_local() {
        // mov dword [ebp-4], 0x46434241 ('ABCF') —
        // C7 45 FC 41 42 43 46
        let bytes = vec![0xC7, 0x45, 0xFC, 0x41, 0x42, 0x43, 0x46];
        let hits = scan_text(&bytes, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "ABCF");
        assert_eq!(hits[0].pattern, "mov_mem_imm");
    }

    #[test]
    fn rejects_garbage_immediates() {
        // 81 F9 00 00 00 00 — all-zero immediate, no printable bytes
        let bytes = vec![0x81, 0xF9, 0x00, 0x00, 0x00, 0x00];
        let hits = scan_text(&bytes, 0x1000);
        assert!(hits.is_empty(), "all-zero immediate must not match");

        // 81 F9 41 00 42 00 — interleaved nulls between printable bytes
        let bytes = vec![0x81, 0xF9, 0x41, 0x00, 0x42, 0x00];
        let hits = scan_text(&bytes, 0x1000);
        assert!(hits.is_empty(), "nulls between printable bytes must not match");
    }

    #[test]
    fn requires_minimum_printable_bytes() {
        // 81 F9 41 42 00 00 — only 2 printable bytes, below MIN
        let bytes = vec![0x81, 0xF9, 0x41, 0x42, 0x00, 0x00];
        let hits = scan_text(&bytes, 0x1000);
        assert!(hits.is_empty(), "<{MIN_PRINTABLE_BYTES} printable bytes must not match");
    }

    #[test]
    fn sliding_scan_finds_multiple_hits() {
        // Two cmp ecx, imm32 patterns back-to-back
        let bytes = vec![
            0x81, 0xF9, 0x41, 0x42, 0x43, 0x44, // cmp ecx, "ABCD"
            0x90, 0x90,                         // nop nop (filler)
            0x81, 0xF9, 0x57, 0x58, 0x59, 0x5A, // cmp ecx, "WXYZ"
        ];
        let hits = scan_text(&bytes, 0x1000);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].text, "ABCD");
        assert_eq!(hits[1].text, "WXYZ");
    }
}
