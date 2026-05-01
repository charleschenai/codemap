// ── Binary Disassembly ─────────────────────────────────────────────
//
// x86 / x86-64 disassembly via iced-x86 (pure Rust, no system libs).
// ARM / MIPS / RISC-V deferred — would need yaxpeax-arch family or a
// rolled implementation; for v1 we cover the 95% of binaries that
// matter for typical Windows/Linux RE work.
//
// Function boundary detection: symbol-table-driven. Read the binary's
// symbol table (.symtab/.dynsym for ELF, export table for PE), use
// each symbol's address as a function start, and infer end from the
// next symbol's start. Stripped binaries get a small, less-useful
// result (the entry point + any imports). Linear-sweep fallback can
// come later if needed.
//
// Output: a Vec<DisasmFunction> per binary that the bin-disasm
// action turns into BinaryFunction nodes in the graph.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use crate::disasm_jt::{RegFile, RegState, SectionMap, SectionView, record_instr, resolve_indirect_jmp};

#[derive(Debug, Clone)]
pub struct DisasmFunction {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub instruction_count: usize,
    /// Internal call targets (absolute virtual addresses) that this
    /// function calls within the same binary. Imports go to a
    /// separate field.
    pub calls: Vec<u64>,
    /// Indirect/import calls — stored as raw target addresses or
    /// import-table RVAs depending on what the binary type lets us
    /// resolve cheaply. For now we just count them.
    pub indirect_calls: usize,
    /// Indirect-jump targets recovered by the jump-table resolver
    /// (Ship 1 #7). Each entry is an absolute VA the function may
    /// branch to via a switch table. Empty for stripped binaries
    /// or ARM/AArch64 (resolver is x86/x64 only for v1).
    pub jump_targets: Vec<u64>,
    /// Crypto-loop signal (Ship 3 #9b): number of XOR instructions
    /// whose key is a known constant (immediate or const-tracked
    /// register from the propagator) AND which lie inside a back-edge
    /// range — i.e., the XOR runs in a loop. ≥ 1 → likely
    /// XOR-decryption routine. Captured by the same RegFile pass as
    /// jump-table resolution; ~zero added cost per instruction.
    pub crypto_xor_in_loop: usize,
    /// Total back-edges (Jcc / Jmp targeting an earlier address
    /// inside the same function). Useful as a "complexity of
    /// looping" indicator and as a denominator for the
    /// crypto-XOR-in-loop ratio.
    pub back_edge_count: usize,
    pub is_entry: bool,
}

#[derive(Debug)]
pub struct DisasmResult {
    pub format: &'static str,
    pub bitness: u32,
    pub image_base: u64,
    pub entry_va: u64,
    pub functions: Vec<DisasmFunction>,
    pub text_start_va: u64,
    pub text_size: u64,
    /// Symbol-table-driven (true) vs linear-sweep fallback (false).
    pub from_symbols: bool,
    /// Architecture string for graph annotation: "x86", "x64", "arm",
    /// "aarch64". Used by `bin_disasm` to set `binary_format` attr.
    pub arch: &'static str,
}

const MAX_FUNCTIONS: usize = 50_000;

/// Format-agnostic entry: detects PE / ELF and dispatches.
pub fn disasm_binary(data: &[u8]) -> Result<DisasmResult, String> {
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        return disasm_elf(data);
    }
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if e_lfanew + 4 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            return disasm_pe(data);
        }
    }
    Err("Unsupported format. v1 covers PE (x86/x64) + ELF (x86/x64/ARM/AArch64).".to_string())
}

// ── PE ─────────────────────────────────────────────────────────────

fn disasm_pe(data: &[u8]) -> Result<DisasmResult, String> {
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() { return Err("Truncated PE COFF".to_string()); }
    let machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = coff + 20;
    if opt_off + 28 > data.len() { return Err("Truncated PE optional header".to_string()); }
    let opt_magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_pe32_plus = opt_magic == 0x20b;
    let bitness: u32 = if is_pe32_plus { 64 } else { 32 };

    if machine != 0x14c && machine != 0x8664 {
        return Err(format!("PE machine {machine:#x} not supported by v1 disasm (need 0x14c x86 or 0x8664 x64)"));
    }

    let entry_rva = u32::from_le_bytes([data[opt_off + 16], data[opt_off + 17], data[opt_off + 18], data[opt_off + 19]]) as u64;
    let image_base: u64 = if is_pe32_plus {
        u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0u8; 8]))
    } else {
        u32::from_le_bytes([data[opt_off + 28], data[opt_off + 29], data[opt_off + 30], data[opt_off + 31]]) as u64
    };

    // Walk section table — capture both .text bounds AND every
    // section's VA→file mapping for the jump-table resolver, which
    // needs to read jump-table bytes from .rdata / .data.rel.ro / etc.
    let sec_table = coff + 20 + opt_size;
    let mut text_va = 0u64;
    let mut text_size = 0u64;
    let mut text_off = 0usize;
    let mut text_raw_size = 0u64;
    let mut sec_map = SectionMap::new();
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { break; }
        let name = &data[off..off + 8];
        let virt_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as u64;
        let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as u64;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64 as usize;
        // Use the smaller of virt_size / raw_size — virt_size can be
        // larger than what's actually on disk (e.g. .bss-style padding).
        let mapped = virt_size.min(raw_size);
        sec_map.push(image_base + virt_addr, mapped, raw_off, mapped as usize);
        if name.starts_with(b".text") && text_size == 0 {
            text_va = image_base + virt_addr;
            text_size = virt_size;
            text_off = raw_off;
            text_raw_size = raw_size;
        }
    }
    if text_size == 0 {
        return Err("No .text section found in PE".to_string());
    }
    let text_end = (text_off + text_raw_size as usize).min(data.len());
    let text_bytes = &data[text_off..text_end];

    // Symbol table from PE export directory (data dir #0)
    let exp_dd_off = if is_pe32_plus { opt_off + 112 } else { opt_off + 96 };
    let mut starts: Vec<(String, u64)> = Vec::new();
    if exp_dd_off + 8 <= data.len() {
        let exp_rva = u32::from_le_bytes([data[exp_dd_off], data[exp_dd_off + 1], data[exp_dd_off + 2], data[exp_dd_off + 3]]) as u64;
        let exp_size = u32::from_le_bytes([data[exp_dd_off + 4], data[exp_dd_off + 5], data[exp_dd_off + 6], data[exp_dd_off + 7]]) as u64;
        if exp_rva > 0 && exp_size > 0 {
            if let Some(off) = pe_rva_to_offset(data, sec_table, n_sections, exp_rva) {
                if off + 40 <= data.len() {
                    let n_funcs = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
                    let n_names = u32::from_le_bytes([data[off + 24], data[off + 25], data[off + 26], data[off + 27]]) as usize;
                    let funcs_rva = u32::from_le_bytes([data[off + 28], data[off + 29], data[off + 30], data[off + 31]]) as u64;
                    let names_rva = u32::from_le_bytes([data[off + 32], data[off + 33], data[off + 34], data[off + 35]]) as u64;
                    let ords_rva = u32::from_le_bytes([data[off + 36], data[off + 37], data[off + 38], data[off + 39]]) as u64;
                    if let (Some(funcs_off), Some(names_off), Some(ords_off)) = (
                        pe_rva_to_offset(data, sec_table, n_sections, funcs_rva),
                        pe_rva_to_offset(data, sec_table, n_sections, names_rva),
                        pe_rva_to_offset(data, sec_table, n_sections, ords_rva),
                    ) {
                        for i in 0..n_names.min(n_funcs).min(8192) {
                            if names_off + i * 4 + 4 > data.len() { break; }
                            let name_rva = u32::from_le_bytes([data[names_off + i * 4], data[names_off + i * 4 + 1], data[names_off + i * 4 + 2], data[names_off + i * 4 + 3]]) as u64;
                            let name_off = match pe_rva_to_offset(data, sec_table, n_sections, name_rva) {
                                Some(o) => o,
                                None => continue,
                            };
                            let mut end = name_off;
                            while end < data.len() && data[end] != 0 { end += 1; }
                            let name = String::from_utf8_lossy(&data[name_off..end]).to_string();
                            if name.is_empty() { continue; }
                            // Get the ordinal then function RVA
                            if ords_off + i * 2 + 2 > data.len() { continue; }
                            let ord = u16::from_le_bytes([data[ords_off + i * 2], data[ords_off + i * 2 + 1]]) as usize;
                            if funcs_off + ord * 4 + 4 > data.len() { continue; }
                            let func_rva = u32::from_le_bytes([data[funcs_off + ord * 4], data[funcs_off + ord * 4 + 1], data[funcs_off + ord * 4 + 2], data[funcs_off + ord * 4 + 3]]) as u64;
                            if func_rva == 0 { continue; }
                            // Skip forwards (RVA falls within export dir)
                            if func_rva >= exp_rva && func_rva < exp_rva + exp_size { continue; }
                            starts.push((name, image_base + func_rva));
                        }
                    }
                }
            }
        }
    }
    let from_symbols = !starts.is_empty();
    if !from_symbols {
        // Stripped: fall back to entry point only
        if entry_rva > 0 {
            starts.push((format!("_start"), image_base + entry_rva));
        }
    }

    let entry_va = image_base + entry_rva;
    let sv = SectionView::new(data, &sec_map);
    let funcs = decode_functions(text_bytes, text_va, bitness, &starts, entry_va, &sv);
    let arch = if bitness == 64 { "x64" } else { "x86" };
    Ok(DisasmResult {
        format: "pe",
        bitness,
        image_base,
        entry_va,
        functions: funcs,
        text_start_va: text_va,
        text_size,
        from_symbols,
        arch,
    })
}

fn pe_rva_to_offset(data: &[u8], sec_table: usize, n_sections: usize, rva: u64) -> Option<usize> {
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 24 > data.len() { return None; }
        let virt_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as u64;
        let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as u64;
        if rva >= virt_addr && rva < virt_addr + virt_size {
            return Some((raw_off + (rva - virt_addr)) as usize);
        }
    }
    None
}

// ── ELF ────────────────────────────────────────────────────────────

fn disasm_elf(data: &[u8]) -> Result<DisasmResult, String> {
    if data.len() < 64 { return Err("Truncated ELF".to_string()); }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let machine = if little_endian {
        u16::from_le_bytes([data[0x12], data[0x13]])
    } else {
        u16::from_be_bytes([data[0x12], data[0x13]])
    };
    // Supported ELF machines: 3=EM_386 (x86), 0x3E=EM_X86_64 (x64),
    // 0x28=EM_ARM (32-bit ARM), 0xb7=EM_AARCH64 (64-bit ARM). 5.24.0
    // adds ARM/AArch64 via symbol-table-only function discovery
    // (no instruction decoding — would need yaxpeax-arm). Function
    // sizes come from STT_FUNC st_size; intra-binary call edges
    // unavailable without disasm.
    let arch: &'static str = match (machine, is_64) {
        (3, _)         => "x86",
        (0x3E, _)      => "x64",
        (0x28, _)      => "arm",
        (0xb7, _)      => "aarch64",
        _ => return Err(format!(
            "ELF machine {machine:#x} not supported by v1 disasm (need 3=x86, 0x3E=x86_64, 0x28=ARM, 0xb7=AArch64)"
        )),
    };
    let bitness: u32 = if is_64 { 64 } else { 32 };

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

    let entry_va = if is_64 { read_u64(0x18) } else { read_u32(0x18) as u64 };
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        (read_u64(0x28) as usize, read_u16(0x3a) as usize, read_u16(0x3c) as usize, read_u16(0x3e) as usize)
    } else {
        (read_u32(0x20) as usize, read_u16(0x2e) as usize, read_u16(0x30) as usize, read_u16(0x32) as usize)
    };
    if e_shoff == 0 || e_shentsize == 0 { return Err("ELF has no section header table".to_string()); }

    // Read section headers + names
    #[allow(dead_code)]
    struct Sec { name: String, sh_type: u32, offset: u64, size: u64, addr: u64, entsize: u64, link: u32 }
    let mut sections: Vec<Sec> = Vec::with_capacity(e_shnum);
    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = if is_64 { read_u64(shstr_hdr + 0x18) as usize } else { read_u32(shstr_hdr + 0x10) as usize };
    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
        let name_idx = read_u32(hdr) as usize;
        let sh_type = read_u32(hdr + 4);
        let (offset, size, addr, entsize, link) = if is_64 {
            (read_u64(hdr + 0x18), read_u64(hdr + 0x20), read_u64(hdr + 0x10), read_u64(hdr + 0x38), read_u32(hdr + 0x28))
        } else {
            (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64, read_u32(hdr + 0x0c) as u64, read_u32(hdr + 0x24) as u64, read_u32(hdr + 0x18))
        };
        let mut name = String::new();
        if shstrtab_off + name_idx < data.len() {
            let mut end = shstrtab_off + name_idx;
            while end < data.len() && data[end] != 0 { end += 1; }
            name = String::from_utf8_lossy(&data[shstrtab_off + name_idx..end]).to_string();
        }
        sections.push(Sec { name, sh_type, offset, size, addr, entsize, link });
    }

    // Find .text
    let text = sections.iter().find(|s| s.name == ".text")
        .ok_or_else(|| "No .text section found in ELF".to_string())?;
    let text_va = text.addr;
    let text_size = text.size;
    let text_off = text.offset as usize;
    let text_end = (text_off + text_size as usize).min(data.len());
    let text_bytes = &data[text_off..text_end];

    // Build a SectionMap covering every loaded section so the
    // jump-table resolver can read .rodata / .data.rel.ro entries.
    // SHT_NOBITS sections (.bss) skipped — no bytes on disk.
    let mut sec_map = SectionMap::new();
    for s in &sections {
        if s.sh_type == 8 { continue; } // SHT_NOBITS
        if s.size == 0 || s.addr == 0 { continue; }
        sec_map.push(s.addr, s.size, s.offset as usize, s.size as usize);
    }

    // Read .symtab + .strtab if present, else .dynsym + .dynstr.
    // Each entry: (name, va, st_size). st_size is used by the ARM/AArch64
    // path (no disasm) to set function size; the x86/x64 path ignores it
    // and lets decode_functions compute size from instruction bytes.
    let mut starts: Vec<(String, u64, u64)> = Vec::new();
    let symtab = sections.iter().find(|s| s.name == ".symtab")
        .or_else(|| sections.iter().find(|s| s.name == ".dynsym"));
    if let Some(sym) = symtab {
        let strtab_idx = sym.link as usize;
        if strtab_idx < sections.len() {
            let strtab = &sections[strtab_idx];
            let strtab_off = strtab.offset as usize;
            let strtab_end = (strtab_off + strtab.size as usize).min(data.len());
            let strtab_data = &data[strtab_off..strtab_end];
            let entsize = if sym.entsize > 0 { sym.entsize as usize } else { if is_64 { 24 } else { 16 } };
            let count = sym.size as usize / entsize;
            for i in 1..count {
                let base = sym.offset as usize + i * entsize;
                if base + entsize > data.len() { break; }
                let (st_name, st_info, st_value, st_size) = if is_64 {
                    let n = read_u32(base) as usize;
                    let info = data[base + 4];
                    let v = read_u64(base + 8);
                    let s = read_u64(base + 16);
                    (n, info, v, s)
                } else {
                    let n = read_u32(base) as usize;
                    let v = read_u32(base + 4) as u64;
                    let s = read_u32(base + 8) as u64;
                    let info = data[base + 12];
                    (n, info, v, s)
                };
                let sym_type = st_info & 0xF;
                if sym_type != 2 || st_value == 0 { continue; } // STT_FUNC=2
                if st_value < text_va || st_value >= text_va + text_size { continue; }
                // Read name
                if st_name >= strtab_data.len() { continue; }
                let mut end = st_name;
                while end < strtab_data.len() && strtab_data[end] != 0 { end += 1; }
                let name = String::from_utf8_lossy(&strtab_data[st_name..end]).to_string();
                if name.is_empty() { continue; }
                starts.push((name, st_value, st_size));
            }
        }
    }
    let from_symbols = !starts.is_empty();
    if !from_symbols && entry_va != 0 {
        starts.push(("_start".to_string(), entry_va, 0));
    }

    // Branch on arch. x86/x64 use the existing iced-x86 path which
    // computes size + call edges from real instruction decoding. ARM
    // and AArch64 v1 use a symbol-table-only path: function size from
    // STT_FUNC st_size, instruction_count estimated as size/4 (most ARM
    // instructions are 4 bytes; AArch64 always 4 bytes), no call edges.
    let funcs = if arch == "x86" || arch == "x64" {
        // decode_functions still expects (name, va) tuples — strip size.
        let starts_xy: Vec<(String, u64)> = starts.iter()
            .map(|(n, v, _)| (n.clone(), *v))
            .collect();
        let sv = SectionView::new(data, &sec_map);
        decode_functions(text_bytes, text_va, bitness, &starts_xy, entry_va, &sv)
    } else {
        functions_from_symbols(&starts, text_va, text_size, entry_va, arch)
    };
    Ok(DisasmResult {
        format: "elf",
        bitness,
        image_base: 0,
        entry_va,
        functions: funcs,
        text_start_va: text_va,
        text_size,
        from_symbols,
        arch,
    })
}

/// ARM/AArch64 function discovery — no instruction decoding (would need
/// yaxpeax-arm). Builds a `DisasmFunction` per STT_FUNC symbol using the
/// symbol's st_size for function length, and estimates instruction_count
/// as size/4 (AArch64 instructions are always 4 bytes; ARM Thumb mixes
/// 2/4 byte but most code is 4-byte ARM). Calls list is empty —
/// intra-binary call edges require real disasm. Sufficient for `pagerank
/// --type bin_func` filtering on `binary_format=arm/aarch64` and for
/// "what's in this .so file" inventory queries on Android native libs.
fn functions_from_symbols(
    starts: &[(String, u64, u64)],
    text_va: u64,
    text_size: u64,
    entry_va: u64,
    _arch: &'static str,
) -> Vec<DisasmFunction> {
    let mut out: Vec<DisasmFunction> = Vec::with_capacity(starts.len());
    for (name, va, st_size) in starts {
        if *va < text_va || *va >= text_va + text_size { continue; }
        if out.len() >= MAX_FUNCTIONS { break; }
        // Some ELF producers emit st_size=0 for symbols at known boundaries
        // (rare on ARM but possible). Default to 4 bytes (one ARM/AArch64
        // instruction) so the node still registers and isn't culled by the
        // size==0 check below.
        let size = if *st_size == 0 { 4 } else { *st_size };
        let instr_count = (size / 4) as usize;
        out.push(DisasmFunction {
            name: name.clone(),
            address: *va,
            size,
            instruction_count: instr_count,
            calls: Vec::new(),
            indirect_calls: 0,
            jump_targets: Vec::new(),
            crypto_xor_in_loop: 0,
            back_edge_count: 0,
            is_entry: *va == entry_va,
        });
    }
    out
}

// ── Decoder / boundary detection ───────────────────────────────────

fn decode_functions(text: &[u8], text_va: u64, bitness: u32, starts: &[(String, u64)], entry_va: u64, sv: &SectionView<'_>) -> Vec<DisasmFunction> {
    let mut sorted: Vec<(String, u64)> = starts.iter()
        .filter(|(_, va)| *va >= text_va && *va < text_va + text.len() as u64)
        .cloned()
        .collect();
    sorted.sort_by_key(|(_, va)| *va);
    sorted.dedup_by_key(|(_, va)| *va);

    let mut out = Vec::with_capacity(sorted.len());
    for i in 0..sorted.len().min(MAX_FUNCTIONS) {
        let (name, start_va) = &sorted[i];
        let next_start = if i + 1 < sorted.len() { sorted[i + 1].1 } else { text_va + text.len() as u64 };
        let max_size = (next_start - start_va).min(0x100000); // cap at 1 MB

        let off_in_text = (start_va - text_va) as usize;
        if off_in_text >= text.len() { continue; }
        let end_in_text = (off_in_text + max_size as usize).min(text.len());
        let func_bytes = &text[off_in_text..end_in_text];

        let mut decoder = Decoder::with_ip(bitness, func_bytes, *start_va, DecoderOptions::NONE);
        let mut instr_count = 0usize;
        let mut calls = Vec::new();
        let mut indirect_calls = 0usize;
        let mut jump_targets: Vec<u64> = Vec::new();
        // Crypto-loop tracking (Ship 3 #9b)
        let mut back_edges: Vec<(u64, u64)> = Vec::new(); // (target_va, source_va) with target < source
        let mut xor_const_sites: Vec<u64> = Vec::new();   // VAs of XOR instructions with a known-constant key
        let mut size = 0u64;
        let mut last_ip = *start_va;
        let mut instr = Instruction::default();
        let mut rf = RegFile::new();
        // Text bounds for the jump-table resolver. Targets outside
        // [text_start, text_end) terminate table walks.
        let text_end_va = text_va + text.len() as u64;
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() { break; }
            instr_count += 1;
            let _ip = instr.ip();
            let next_ip = instr.next_ip();
            size = next_ip - start_va;
            last_ip = next_ip;

            // Track call / jump targets BEFORE updating the propagator
            // — the JMP itself is the resolution point, not its result.
            match instr.mnemonic() {
                Mnemonic::Call => {
                    if instr.op_count() == 1 && matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                        let target = instr.near_branch_target();
                        if target != 0 { calls.push(target); }
                    } else {
                        indirect_calls += 1;
                    }
                }
                Mnemonic::Jmp => {
                    if instr.op_count() == 1 && matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                        // Direct unconditional jump; falls into the
                        // function-end logic below.
                    } else {
                        // Indirect JMP — try to resolve as a jump table.
                        let resolved = resolve_indirect_jmp(&instr, &rf, sv, bitness, text_va, text_end_va);
                        if !resolved.is_empty() {
                            jump_targets.extend_from_slice(&resolved);
                        }
                    }
                }
                Mnemonic::Ret | Mnemonic::Retf => {
                    break;
                }
                // Conditional branches contribute to back-edge detection
                // (back-edge = branch whose target is an earlier address
                // inside this function). Used by crypto-loop detection
                // to know whether a given XOR site lies inside a loop.
                Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jl | Mnemonic::Jle
                | Mnemonic::Jg | Mnemonic::Jge | Mnemonic::Ja | Mnemonic::Jae
                | Mnemonic::Jb | Mnemonic::Jbe | Mnemonic::Js | Mnemonic::Jns
                | Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jo | Mnemonic::Jno
                | Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
                | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz => {
                    if instr.op_count() == 1 && matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                        let target = instr.near_branch_target();
                        if target >= *start_va && target < next_start && target < instr.ip() {
                            back_edges.push((target, instr.ip()));
                        }
                    }
                }
                // XOR instruction: candidate for crypto-loop detection.
                // We count XORs whose source operand is either an
                // immediate or a register the propagator tracks as
                // a non-zero constant (rules out `xor reg, reg` self-zero).
                Mnemonic::Xor => {
                    if instr.op_count() == 2 {
                        let key_is_const = match instr.op1_kind() {
                            OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32
                            | OpKind::Immediate64 | OpKind::Immediate8to32
                            | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
                                let v = instr.immediate(1);
                                v != 0
                            }
                            OpKind::Register => {
                                let r = instr.op1_register();
                                // Skip xor reg, reg (the zeroing idiom)
                                if instr.op0_kind() == OpKind::Register
                                    && instr.op0_register() == r
                                {
                                    false
                                } else {
                                    matches!(rf.get(r), RegState::Const(v) if v != 0)
                                }
                            }
                            _ => false,
                        };
                        if key_is_const {
                            xor_const_sites.push(instr.ip());
                        }
                    }
                }
                _ => {}
            }

            // Update register state AFTER call/jmp inspection so the
            // propagator reflects the post-instruction view available
            // to subsequent instructions.
            record_instr(&mut rf, &instr);

            // Stop if we hit the next function boundary
            if next_ip >= next_start { break; }
        }
        let _ = last_ip;
        // Skip empty functions
        if size == 0 { continue; }

        // Dedup jump-table targets (resolver may produce duplicates if
        // the same JMP is decoded twice through some shape we don't
        // model, or if a switch table has overlapping default cases).
        jump_targets.sort_unstable();
        jump_targets.dedup();

        // Compute crypto_xor_in_loop: count of XOR-with-const sites
        // whose VA falls inside any back-edge range [target, source].
        let crypto_xor_in_loop = xor_const_sites.iter()
            .filter(|&&xor_va| {
                back_edges.iter().any(|&(t, s)| xor_va >= t && xor_va <= s)
            })
            .count();

        out.push(DisasmFunction {
            name: name.clone(),
            address: *start_va,
            size,
            instruction_count: instr_count,
            calls,
            indirect_calls,
            jump_targets,
            crypto_xor_in_loop,
            back_edge_count: back_edges.len(),
            is_entry: *start_va == entry_va,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 5.24.0: ARM/AArch64 functions_from_symbols builds DisasmFunction
    /// nodes from STT_FUNC entries without instruction decoding. Default
    /// st_size=0 still produces a valid 4-byte node so the function is
    /// not silently dropped by downstream callers.
    #[test]
    fn functions_from_symbols_handles_zero_size_and_default_4_bytes() {
        let starts = vec![
            ("normal_func".to_string(),  0x1000, 64),  // 16 instructions
            ("zero_size".to_string(),    0x1100, 0),   // becomes 1 instruction
            ("out_of_text".to_string(),  0x9999, 32),  // dropped (outside .text)
            ("entry".to_string(),        0x1200, 100),
        ];
        let funcs = functions_from_symbols(&starts, 0x1000, 0x500, 0x1200, "aarch64");
        assert_eq!(funcs.len(), 3, "out-of-text symbol should be filtered: {funcs:?}");

        let normal = funcs.iter().find(|f| f.name == "normal_func").unwrap();
        assert_eq!(normal.size, 64);
        assert_eq!(normal.instruction_count, 16);
        assert!(!normal.is_entry);

        let zero = funcs.iter().find(|f| f.name == "zero_size").unwrap();
        assert_eq!(zero.size, 4, "zero st_size must default to 4");
        assert_eq!(zero.instruction_count, 1);

        let entry = funcs.iter().find(|f| f.name == "entry").unwrap();
        assert!(entry.is_entry, "function at entry_va should set is_entry=true");

        for f in &funcs {
            assert!(f.calls.is_empty(), "ARM v1 should not produce call edges");
            assert_eq!(f.indirect_calls, 0);
        }
    }

    #[test]
    fn disasm_binary_rejects_unknown_elf_machine() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[0x12] = 0x99;
        elf[0x13] = 0x00;
        let result = disasm_binary(&elf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("ARM") && err.contains("AArch64"),
            "error should list newly-supported archs: {err}");
    }

    // ── Ship 1 #7: end-to-end jump-table resolution through decode_functions ──
    //
    // These tests exercise the SectionView/RegFile wiring that links
    // the disasm decoder to the disasm_jt resolver. Pure-resolver
    // unit tests live in disasm_jt::tests; these confirm the integration
    // is correct by feeding crafted x64 bytes through the real
    // decode_functions entry point that PE/ELF callers go through.

    /// Pattern A — GCC/Clang PIC-style switch (relative offset table).
    ///   lea    rdx, [rip+TABLE]         ; rdx = 0x2000
    ///   movsxd rax, dword [rdx + rcx*4] ; rax = sign_extend(table[idx])
    ///   add    rax, rdx                 ; rax = TABLE_BASE + offset
    ///   jmp    rax
    #[test]
    fn decode_functions_resolves_pattern_a_switch() {
        use crate::disasm_jt::{SectionMap, SectionView};

        // 0x3000 byte image: text at va 0x1000..0x2000, table at 0x2000..0x3000
        let mut data = vec![0u8; 0x3000];

        // Function bytes at va 0x1000
        // LEA rdx, [rip+0xff9]  → rip after instr is 0x1007, target = 0x2000
        let code: [u8; 17] = [
            0x48, 0x8d, 0x15, 0xf9, 0x0f, 0x00, 0x00, // lea rdx, [rip+0xff9]
            0x48, 0x63, 0x04, 0x8a,                   // movsxd rax, dword ptr [rdx+rcx*4]
            0x48, 0x01, 0xd0,                         // add rax, rdx
            0xff, 0xe0,                               // jmp rax
            0xc3,                                     // ret
        ];
        data[0x1000..0x1011].copy_from_slice(&code);

        // Three valid case targets (offsets from TABLE_BASE=0x2000):
        //   0x1100 = 0x2000 + (-0x0F00)
        //   0x1200 = 0x2000 + (-0x0E00)
        //   0x1300 = 0x2000 + (-0x0D00)
        data[0x2000..0x2004].copy_from_slice(&(-0x0F00i32).to_le_bytes());
        data[0x2004..0x2008].copy_from_slice(&(-0x0E00i32).to_le_bytes());
        data[0x2008..0x200C].copy_from_slice(&(-0x0D00i32).to_le_bytes());
        // Sentinel (out-of-text target → terminates walk):
        data[0x200C..0x2010].copy_from_slice(&0x10_0000i32.to_le_bytes());

        let mut map = SectionMap::new();
        map.push(0x1000, 0x1000, 0x1000, 0x1000); // text
        map.push(0x2000, 0x1000, 0x2000, 0x1000); // rdata
        let sv = SectionView::new(&data, &map);

        let text_bytes = &data[0x1000..0x2000];
        let starts = vec![("dispatch".to_string(), 0x1000u64)];
        let funcs = decode_functions(text_bytes, 0x1000, 64, &starts, 0x1000, &sv);

        assert_eq!(funcs.len(), 1, "exactly one function decoded");
        assert_eq!(funcs[0].name, "dispatch");
        assert_eq!(funcs[0].jump_targets, vec![0x1100, 0x1200, 0x1300],
            "Pattern A switch should resolve to three case targets");
    }

    /// Pattern B — Windows MSVC x64 absolute-pointer table.
    ///   jmp    qword ptr [rcx*8 + 0x2000]
    /// All target VAs come straight from the table — no register
    /// state needed. Table holds 4 absolute u64 targets.
    #[test]
    fn decode_functions_resolves_pattern_b_absolute_table() {
        use crate::disasm_jt::{SectionMap, SectionView};

        let mut data = vec![0u8; 0x3000];

        // jmp qword ptr [rcx*8 + 0x2000]
        // Encoding: FF 24 CD 00 20 00 00
        let code: [u8; 8] = [
            0xff, 0x24, 0xcd, 0x00, 0x20, 0x00, 0x00, 0xc3,
        ];
        data[0x1000..0x1008].copy_from_slice(&code);

        // Four absolute u64 targets within text [0x1000, 0x2000)
        for (i, t) in [0x1100u64, 0x1200, 0x1300, 0x1400].iter().enumerate() {
            data[0x2000 + i * 8..0x2000 + i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        // Sentinel
        data[0x2020..0x2028].copy_from_slice(&0x9999u64.to_le_bytes());

        let mut map = SectionMap::new();
        map.push(0x1000, 0x1000, 0x1000, 0x1000);
        map.push(0x2000, 0x1000, 0x2000, 0x1000);
        let sv = SectionView::new(&data, &map);

        let text_bytes = &data[0x1000..0x2000];
        let starts = vec![("dispatch".to_string(), 0x1000u64)];
        let funcs = decode_functions(text_bytes, 0x1000, 64, &starts, 0x1000, &sv);

        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].jump_targets, vec![0x1100, 0x1200, 0x1300, 0x1400]);
    }

    /// Stripped-binary case: indirect JMP with no recoverable history
    /// (no LEA before it). Resolver must return empty without crashing.
    #[test]
    fn decode_functions_unresolvable_jmp_yields_no_targets() {
        use crate::disasm_jt::{SectionMap, SectionView};

        let mut data = vec![0u8; 0x2000];

        // mov rax, rcx ; jmp rax ; ret  — rax untracked, JMP REG should not resolve
        let code: [u8; 6] = [
            0x48, 0x89, 0xc8,   // mov rax, rcx
            0xff, 0xe0,         // jmp rax
            0xc3,               // ret
        ];
        data[0x1000..0x1006].copy_from_slice(&code);

        let mut map = SectionMap::new();
        map.push(0x1000, 0x1000, 0x1000, 0x1000);
        let sv = SectionView::new(&data, &map);

        let text_bytes = &data[0x1000..0x2000];
        let starts = vec![("opaque".to_string(), 0x1000u64)];
        let funcs = decode_functions(text_bytes, 0x1000, 64, &starts, 0x1000, &sv);
        assert_eq!(funcs.len(), 1);
        assert!(funcs[0].jump_targets.is_empty(),
            "no resolvable history → no jump targets, got {:?}", funcs[0].jump_targets);
    }

    /// Ensure the existing DisasmFunction Debug derive is enough — used
    /// by the assertion message in functions_from_symbols_handles_*.
    #[test]
    fn disasm_function_debug_round_trip() {
        let f = DisasmFunction {
            name: "x".to_string(), address: 0, size: 0, instruction_count: 0,
            calls: vec![], indirect_calls: 0, jump_targets: vec![],
            crypto_xor_in_loop: 0, back_edge_count: 0, is_entry: false,
        };
        let _ = format!("{f:?}");
    }
}

