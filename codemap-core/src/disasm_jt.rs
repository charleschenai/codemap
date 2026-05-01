// ── Jump-Table Resolver (Ship 1 #7) ────────────────────────────────
//
// Recovers indirect-jump targets in compiler-emitted switch tables
// across the three patterns that cover ~95% of real-world cases:
//
//   Pattern A — PIC, GCC/Clang style (relative-to-base table):
//     lea    rdx, [rip+TABLE]
//     movsxd rax, dword ptr [rdx + idx*4]
//     add    rax, rdx
//     jmp    rax                       ; rax = TABLE + sign_extend(table[idx])
//
//   Pattern B — Windows MSVC, x64 (absolute pointer table):
//     jmp    qword ptr [rip+TABLE + idx*8]
//
//   Pattern C — x86 32-bit (absolute pointer table):
//     jmp    dword ptr [TABLE + idx*4]
//
// Pattern B/C are resolved from the JMP instruction alone — the table
// base, scale, and index register are all present in the memory
// operand. No backward walk required.
//
// Pattern A requires a bounded backward constant-propagator: walk back
// ≤ MAX_HISTORY instructions tracking which register holds what, until
// we find the LEA that established the table base. The propagator
// state is intentionally minimal (Const, Sum, TableLoad, Unknown) and
// is the same primitive Ship 3 #5 / #6 / Ship 1 #8 will reuse — when
// #8 lands, we extract this into `dataflow_local.rs` and let both
// share it. Until then it lives here.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

// As of 5.34.0 the bounded backward constant-propagator (RegFile,
// RegState, ElemKind, MAX_HISTORY, record_instr) lives in
// `dataflow_local.rs` so other consumers can use it without depending
// on the jump-table resolver. We re-export through this module for
// backwards compatibility — existing callers can keep their
// `use crate::disasm_jt::{...}` imports.
pub use crate::dataflow_local::{ElemKind, MAX_HISTORY, RegFile, RegState, record_instr};

/// Maximum entries we'll read from a single jump table.
/// Real switches rarely exceed 32; cap at 64 to handle edge cases
/// without runaway on malformed binaries.
pub const MAX_TABLE_ENTRIES: usize = 64;

// ── SectionView ────────────────────────────────────────────────────
// VA → byte slice. Built once per binary by the PE/ELF parser and
// passed into the decoder so the jump-table resolver can read table
// entries from .rdata / .data.rel.ro / wherever they actually live.

#[derive(Debug, Clone)]
pub struct SectionMap {
    pub regions: Vec<Region>,
}

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub va_start: u64,
    pub va_end: u64,
    pub file_start: usize,
    pub file_size: usize,
}

impl SectionMap {
    pub fn new() -> Self { Self { regions: Vec::new() } }

    pub fn push(&mut self, va: u64, va_size: u64, file_off: usize, file_size: usize) {
        if va_size == 0 || file_size == 0 { return; }
        self.regions.push(Region {
            va_start: va,
            va_end: va + va_size,
            file_start: file_off,
            file_size,
        });
    }

    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        for r in &self.regions {
            if va >= r.va_start && va < r.va_end {
                let delta = (va - r.va_start) as usize;
                if delta < r.file_size {
                    return Some(r.file_start + delta);
                }
            }
        }
        None
    }
}

impl Default for SectionMap {
    fn default() -> Self { Self::new() }
}

pub struct SectionView<'a> {
    pub data: &'a [u8],
    pub map: &'a SectionMap,
}

impl<'a> SectionView<'a> {
    pub fn new(data: &'a [u8], map: &'a SectionMap) -> Self { Self { data, map } }

    pub fn read_bytes(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        let off = self.map.va_to_offset(va)?;
        if off + len > self.data.len() { return None; }
        Some(&self.data[off..off + len])
    }

    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let b = self.read_bytes(va, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&self, va: u64) -> Option<u64> {
        let b = self.read_bytes(va, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }

    pub fn read_i32(&self, va: u64) -> Option<i32> {
        self.read_u32(va).map(|v| v as i32)
    }
}


// ── Resolver ───────────────────────────────────────────────────────

/// Try to resolve an indirect JMP into a list of concrete target VAs.
/// Returns an empty Vec if the JMP doesn't match any recognized
/// pattern or the table can't be safely read.
///
/// Bounds applied:
///   - Each entry must land within [text_start, text_end)
///   - First entry that falls outside the text range terminates the table
///   - Hard cap of MAX_TABLE_ENTRIES regardless
pub fn resolve_indirect_jmp(
    jmp: &Instruction,
    rf: &RegFile,
    sv: &SectionView<'_>,
    bitness: u32,
    text_start: u64,
    text_end: u64,
) -> Vec<u64> {
    if jmp.mnemonic() != Mnemonic::Jmp { return Vec::new(); }
    if jmp.op_count() != 1 { return Vec::new(); }

    match jmp.op0_kind() {
        // Pattern B/C: JMP [base + idx*scale + disp]
        OpKind::Memory => resolve_memory_jmp(jmp, rf, sv, bitness, text_start, text_end),
        // Pattern A: JMP REG (state must be BasePlusTable)
        OpKind::Register => resolve_register_jmp(jmp, rf, sv, text_start, text_end),
        _ => Vec::new(),
    }
}

fn resolve_memory_jmp(
    jmp: &Instruction,
    rf: &RegFile,
    sv: &SectionView<'_>,
    bitness: u32,
    text_start: u64,
    text_end: u64,
) -> Vec<u64> {
    let base = jmp.memory_base();
    let idx = jmp.memory_index();
    let scale = jmp.memory_index_scale() as u8;
    let disp = jmp.memory_displacement64();

    // Single-indirection (no index register): function pointer call,
    // not a jump table. v1 doesn't try to resolve these.
    if idx == Register::None { return Vec::new(); }

    // Resolve table base VA
    let table_va: Option<u64> = if base == Register::None {
        // Pattern C: 32-bit absolute  jmp [TABLE + idx*4]
        Some(disp)
    } else if jmp.is_ip_rel_memory_operand() {
        // Pattern B in some encodings — RIP base + idx*scale is rare
        // but iced resolves the absolute disp for us.
        Some(disp)
    } else {
        match rf.get(base) {
            RegState::Const(c) => Some(c.wrapping_add(disp)),
            _ => None,
        }
    };
    let Some(table_va) = table_va else { return Vec::new(); };

    let entry_size = if bitness == 64 { 8 } else { 4 };
    let _ = idx;  // index register doesn't influence resolution; only the table layout does
    let _ = scale;

    let mut out = Vec::new();
    for i in 0..MAX_TABLE_ENTRIES {
        let entry_va = table_va.wrapping_add((i * entry_size) as u64);
        let target = if entry_size == 8 {
            sv.read_u64(entry_va)
        } else {
            sv.read_u32(entry_va).map(|v| v as u64)
        };
        let Some(t) = target else { break; };
        if t < text_start || t >= text_end { break; }
        out.push(t);
    }
    out
}

fn resolve_register_jmp(
    jmp: &Instruction,
    rf: &RegFile,
    sv: &SectionView<'_>,
    text_start: u64,
    text_end: u64,
) -> Vec<u64> {
    let r = jmp.op0_register();
    let RegState::BasePlusTable { base_va, table_va, scale, index_reg: _, elem } = rf.get(r) else {
        return Vec::new();
    };
    let entry_size = elem.size() as u64;
    let mut out = Vec::new();
    for i in 0..MAX_TABLE_ENTRIES {
        let entry_va = table_va.wrapping_add(i as u64 * scale.max(1) as u64);
        let off = match elem {
            ElemKind::I8 => sv.read_bytes(entry_va, 1).map(|b| b[0] as i8 as i64),
            ElemKind::I16 => sv.read_bytes(entry_va, 2).map(|b| i16::from_le_bytes([b[0], b[1]]) as i64),
            ElemKind::I32 => sv.read_i32(entry_va).map(|v| v as i64),
            ElemKind::U32 => sv.read_u32(entry_va).map(|v| v as i64),
            ElemKind::U64 => sv.read_u64(entry_va).map(|v| v as i64),
        };
        let Some(off) = off else { break; };
        let _ = entry_size;
        let target = base_va.wrapping_add_signed(off);
        if target < text_start || target >= text_end { break; }
        out.push(target);
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_one(bytes: &[u8], ip: u64, bitness: u32) -> Instruction {
        let mut d = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
        d.decode()
    }

    #[test]
    fn section_map_va_to_offset() {
        let mut m = SectionMap::new();
        m.push(0x1000, 0x100, 0x400, 0x100);
        m.push(0x2000, 0x80, 0x600, 0x80);
        assert_eq!(m.va_to_offset(0x1000), Some(0x400));
        assert_eq!(m.va_to_offset(0x10ff), Some(0x4ff));
        assert_eq!(m.va_to_offset(0x1100), None);
        assert_eq!(m.va_to_offset(0x2010), Some(0x610));
        assert_eq!(m.va_to_offset(0x9999), None);
    }

    #[test]
    fn pattern_a_resolves_three_relative_offsets() {
        // Build: text region 0x1000..0x2000, table at 0x3000 with 3 i32 entries
        // table[0] = 0x100   → target = 0x3000 + 0x100 = 0x3100  (out of text, terminates)
        // We want targets in text. Use base 0x1500 (within text).
        let mut data = vec![0u8; 0x4000];
        // Place the table at file offset 0x3000, with VA = 0x3000.
        // Entries are *signed offsets from base_va* (Pattern A uses base+table[i]).
        // base_va = 0x1500, target = 0x1500 + offset. We want targets at 0x1600, 0x1700, 0x1800.
        // So entries are 0x100, 0x200, 0x300.
        for (i, off) in [0x100i32, 0x200, 0x300].iter().enumerate() {
            data[0x3000 + i * 4..0x3000 + i * 4 + 4].copy_from_slice(&off.to_le_bytes());
        }
        // 4th entry sentinel (index 3, offset 0x300C): large offset
        // puts target outside text and terminates the table walk.
        data[0x300C..0x3010].copy_from_slice(&0x10_0000i32.to_le_bytes());

        let mut map = SectionMap::new();
        map.push(0x3000, 0x1000, 0x3000, 0x1000);  // table region
        let sv = SectionView::new(&data, &map);

        // Build a fake JMP RAX instruction; state = BasePlusTable with base=0x1500, table=0x3000, scale=4.
        let mut rf = RegFile::new();
        rf.set(Register::RAX, RegState::BasePlusTable {
            base_va: 0x1500,
            table_va: 0x3000,
            scale: 4,
            index_reg: Register::RCX,
            elem: ElemKind::I32,
        });
        // Encoding: FF E0 = JMP RAX
        let jmp_bytes = [0xFF, 0xE0];
        let jmp = decode_one(&jmp_bytes, 0x1100, 64);
        let targets = resolve_indirect_jmp(&jmp, &rf, &sv, 64, 0x1000, 0x2000);
        assert_eq!(targets, vec![0x1600, 0x1700, 0x1800]);
    }

    #[test]
    fn pattern_b_resolves_absolute_pointer_table_x64() {
        // x64 Windows: jmp qword ptr [TABLE + RCX*8] — table at 0x4000 with 4 absolute u64 targets
        let mut data = vec![0u8; 0x5000];
        for (i, t) in [0x1100u64, 0x1200, 0x1300, 0x1400].iter().enumerate() {
            data[0x4000 + i * 8..0x4000 + i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        // Sentinel: out-of-text
        data[0x4020..0x4028].copy_from_slice(&0x9999u64.to_le_bytes());

        let mut map = SectionMap::new();
        map.push(0x4000, 0x1000, 0x4000, 0x1000);
        let sv = SectionView::new(&data, &map);

        // Encoding: FF 24 CD 00 40 00 00 = JMP qword ptr [RCX*8 + 0x4000]
        let bytes = [0xFF, 0x24, 0xCD, 0x00, 0x40, 0x00, 0x00];
        let jmp = decode_one(&bytes, 0x1100, 64);
        assert_eq!(jmp.mnemonic(), Mnemonic::Jmp);

        let rf = RegFile::new();
        let targets = resolve_indirect_jmp(&jmp, &rf, &sv, 64, 0x1000, 0x2000);
        assert_eq!(targets, vec![0x1100, 0x1200, 0x1300, 0x1400]);
    }

    #[test]
    fn pattern_c_resolves_absolute_pointer_table_x86() {
        // x86: jmp dword ptr [TABLE + ECX*4]  — table at 0x4000 with 3 absolute u32 targets
        let mut data = vec![0u8; 0x5000];
        for (i, t) in [0x1100u32, 0x1200, 0x1300].iter().enumerate() {
            data[0x4000 + i * 4..0x4000 + i * 4 + 4].copy_from_slice(&t.to_le_bytes());
        }
        data[0x400c..0x4010].copy_from_slice(&0x9999u32.to_le_bytes());

        let mut map = SectionMap::new();
        map.push(0x4000, 0x1000, 0x4000, 0x1000);
        let sv = SectionView::new(&data, &map);

        // Encoding: FF 24 8D 00 40 00 00 = JMP dword ptr [ECX*4 + 0x4000]
        let bytes = [0xFF, 0x24, 0x8D, 0x00, 0x40, 0x00, 0x00];
        let jmp = decode_one(&bytes, 0x1100, 32);
        assert_eq!(jmp.mnemonic(), Mnemonic::Jmp);

        let rf = RegFile::new();
        let targets = resolve_indirect_jmp(&jmp, &rf, &sv, 32, 0x1000, 0x2000);
        assert_eq!(targets, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn negative_jmp_reg_with_unknown_state_returns_empty() {
        // JMP RAX, but RAX is Unknown — no resolution should be attempted
        let map = SectionMap::new();
        let data = [];
        let sv = SectionView::new(&data, &map);
        let rf = RegFile::new();  // all Unknown
        let bytes = [0xFF, 0xE0];
        let jmp = decode_one(&bytes, 0x1000, 64);
        let targets = resolve_indirect_jmp(&jmp, &rf, &sv, 64, 0x1000, 0x2000);
        assert!(targets.is_empty());
    }

    #[test]
    fn negative_jmp_single_indirection_ignored() {
        // JMP qword ptr [RIP + 0x100]  — single-indirection (function pointer call), not a table
        // Encoding: FF 25 00 01 00 00 = JMP qword ptr [rip+0x100]
        let map = SectionMap::new();
        let data = [];
        let sv = SectionView::new(&data, &map);
        let rf = RegFile::new();
        let bytes = [0xFF, 0x25, 0x00, 0x01, 0x00, 0x00];
        let jmp = decode_one(&bytes, 0x1000, 64);
        let targets = resolve_indirect_jmp(&jmp, &rf, &sv, 64, 0x1000, 0x2000);
        assert!(targets.is_empty());
    }
}
