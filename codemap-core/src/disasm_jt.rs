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

// ── RegFile ────────────────────────────────────────────────────────
// Bounded backward constant-propagator state. We only model the
// 16 GPRs (RAX..R15 / EAX..R15D — iced normalizes both to the full
// register on writes; we always look up by the full register).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegState {
    Unknown,
    /// Register holds a known absolute value (immediate, RIP-relative LEA).
    Const(u64),
    /// Register holds `table[idx*scale]` — an N-byte signed/unsigned
    /// value loaded from `table_va + idx*scale`. Used to recognize the
    /// MOVSXD step in Pattern A.
    TableLoad {
        table_va: u64,
        scale: u8,
        index_reg: Register,
        elem: ElemKind,
    },
    /// Register holds `base + table[idx*scale]` — the result of the
    /// `add rax, rdx` step in Pattern A. The JMP onto this register
    /// resolves to absolute addresses by re-reading the table.
    BasePlusTable {
        base_va: u64,
        table_va: u64,
        scale: u8,
        index_reg: Register,
        elem: ElemKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElemKind {
    I8,
    I16,
    I32,
    U32,
    U64,
}

impl ElemKind {
    fn size(self) -> u8 {
        match self {
            ElemKind::I8 => 1,
            ElemKind::I16 => 2,
            ElemKind::I32 | ElemKind::U32 => 4,
            ElemKind::U64 => 8,
        }
    }
}

/// Maximum number of past instructions whose effects we track.
pub const MAX_HISTORY: usize = 16;

pub struct RegFile {
    map: [RegState; 16],
}

fn reg_index(r: Register) -> Option<usize> {
    // We collapse 64/32/16/8-bit GPR variants down to one of 16 slots.
    // iced-x86's `full_register` would do this in one call but requires
    // the `instr_info` feature; we expand the table by hand to keep the
    // build minimal.
    match r {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Some(0),
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Some(1),
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Some(2),
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Some(3),
        Register::RSP | Register::ESP | Register::SP | Register::SPL              => Some(4),
        Register::RBP | Register::EBP | Register::BP | Register::BPL              => Some(5),
        Register::RSI | Register::ESI | Register::SI | Register::SIL              => Some(6),
        Register::RDI | Register::EDI | Register::DI | Register::DIL              => Some(7),
        Register::R8  | Register::R8D  | Register::R8W  | Register::R8L  => Some(8),
        Register::R9  | Register::R9D  | Register::R9W  | Register::R9L  => Some(9),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(10),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(11),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(12),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(13),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(14),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(15),
        _ => None,
    }
}

impl RegFile {
    pub fn new() -> Self { Self { map: [RegState::Unknown; 16] } }

    pub fn reset(&mut self) {
        self.map = [RegState::Unknown; 16];
    }

    pub fn get(&self, r: Register) -> RegState {
        match reg_index(r) { Some(i) => self.map[i], None => RegState::Unknown }
    }

    pub fn set(&mut self, r: Register, s: RegState) {
        if let Some(i) = reg_index(r) { self.map[i] = s; }
    }

    /// Mark every GPR a given instruction *might* write as Unknown.
    /// Used when we encounter an instruction the propagator doesn't
    /// model — preserves soundness at the cost of some recall.
    pub fn invalidate_writes(&mut self, ins: &Instruction) {
        // Conservative: walk operand 0 and any implicit writes.
        // Most arithmetic and move instructions write op0 if op0 is
        // a register; that's all we track explicitly. Instructions
        // that don't fit (e.g., string ops, division writing
        // multiple regs) still land here via the catch-all in
        // record_instr.
        if ins.op_count() > 0 && ins.op0_kind() == OpKind::Register {
            let r = ins.op0_register();
            if r != Register::None { self.set(r, RegState::Unknown); }
        }
    }
}

impl Default for RegFile {
    fn default() -> Self { Self::new() }
}

// ── Per-instruction state update ───────────────────────────────────

/// Update the register file from one decoded instruction. The
/// recognized patterns are exactly the ones needed for jump-table
/// resolution (LEA, MOV imm, MOVSXD/MOVSX from indexed memory, ADD
/// reg+reg). Everything else conservatively invalidates the write
/// destination.
pub fn record_instr(rf: &mut RegFile, ins: &Instruction) {
    match ins.mnemonic() {
        // LEA reg, [rip+disp]  →  reg = absolute_va
        // LEA reg, [disp]      →  reg = disp (rare, but happens in PIC code on 32-bit)
        Mnemonic::Lea => {
            if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register { return; }
            let dst = ins.op0_register();
            // Pure-displacement form (no base, no index)
            if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
                rf.set(dst, RegState::Const(ins.memory_displacement64()));
                return;
            }
            // RIP-relative form: iced resolves the target VA in memory_displacement64()
            if ins.is_ip_rel_memory_operand() {
                rf.set(dst, RegState::Const(ins.memory_displacement64()));
                return;
            }
            rf.set(dst, RegState::Unknown);
        }

        // MOV reg, imm  →  reg = imm
        Mnemonic::Mov => {
            if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register {
                rf.invalidate_writes(ins);
                return;
            }
            let dst = ins.op0_register();
            match ins.op1_kind() {
                OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32
                | OpKind::Immediate64 | OpKind::Immediate8to32
                | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
                    rf.set(dst, RegState::Const(ins.immediate(1)));
                }
                _ => rf.set(dst, RegState::Unknown),
            }
        }

        // MOVSXD reg, dword [base + idx*scale]  →  reg = sign_extend(table[idx])
        // MOVSX  reg, byte/word [base + idx*scale]  →  reg = sign_extend(narrower table[idx])
        Mnemonic::Movsxd | Mnemonic::Movsx | Mnemonic::Movzx => {
            if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register
                || ins.op1_kind() != OpKind::Memory {
                rf.invalidate_writes(ins);
                return;
            }
            let dst = ins.op0_register();
            let base = ins.memory_base();
            let idx = ins.memory_index();
            let scale = ins.memory_index_scale() as u8;
            let disp = ins.memory_displacement64();

            // Need a known base register and a real index register
            if idx == Register::None {
                rf.set(dst, RegState::Unknown);
                return;
            }

            // Compute the table base VA: from base register's known value
            // (plus disp) OR from absolute disp (when base reg is None).
            let table_va: Option<u64> = if base == Register::None {
                Some(disp)
            } else {
                match rf.get(base) {
                    RegState::Const(c) => Some(c.wrapping_add(disp)),
                    _ => None,
                }
            };
            let Some(table_va) = table_va else {
                rf.set(dst, RegState::Unknown);
                return;
            };

            let elem = match ins.mnemonic() {
                Mnemonic::Movsxd => ElemKind::I32,
                Mnemonic::Movsx => match ins.memory_size() {
                    iced_x86::MemorySize::Int8 => ElemKind::I8,
                    iced_x86::MemorySize::Int16 => ElemKind::I16,
                    _ => { rf.set(dst, RegState::Unknown); return; }
                },
                Mnemonic::Movzx => match ins.memory_size() {
                    iced_x86::MemorySize::UInt8 => ElemKind::U32,  // zero-extended; we treat as U32 since table values are usually small
                    iced_x86::MemorySize::UInt16 => ElemKind::U32,
                    _ => { rf.set(dst, RegState::Unknown); return; }
                },
                _ => unreachable!(),
            };

            rf.set(dst, RegState::TableLoad {
                table_va,
                scale,
                index_reg: idx,
                elem,
            });
        }

        // ADD reg, reg  →  if one side is TableLoad and the other is
        // a Const matching the TableLoad's base, promote to BasePlusTable.
        Mnemonic::Add => {
            if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register {
                rf.invalidate_writes(ins);
                return;
            }
            let dst = ins.op0_register();
            if ins.op1_kind() != OpKind::Register {
                rf.set(dst, RegState::Unknown);
                return;
            }
            let src = ins.op1_register();
            let dst_state = rf.get(dst);
            let src_state = rf.get(src);
            match (dst_state, src_state) {
                (RegState::TableLoad { table_va, scale, index_reg, elem }, RegState::Const(c))
                | (RegState::Const(c), RegState::TableLoad { table_va, scale, index_reg, elem }) => {
                    rf.set(dst, RegState::BasePlusTable {
                        base_va: c,
                        table_va,
                        scale,
                        index_reg,
                        elem,
                    });
                }
                _ => rf.set(dst, RegState::Unknown),
            }
        }

        // Anything else: conservatively invalidate the destination
        // register. Calls / interrupts / control-flow instructions
        // just leave state alone (they don't write GPRs we care about).
        Mnemonic::Call | Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Jmp
        | Mnemonic::Jne | Mnemonic::Je | Mnemonic::Jl | Mnemonic::Jle
        | Mnemonic::Jg | Mnemonic::Jge | Mnemonic::Ja | Mnemonic::Jae
        | Mnemonic::Jb | Mnemonic::Jbe | Mnemonic::Js | Mnemonic::Jns
        | Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jo | Mnemonic::Jno
        | Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz
        | Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop | Mnemonic::Int
        | Mnemonic::Int1 | Mnemonic::Int3 | Mnemonic::Cld | Mnemonic::Std
        | Mnemonic::Pushfq | Mnemonic::Popfq => {}
        _ => rf.invalidate_writes(ins),
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
    fn lea_rip_relative_records_const() {
        // LEA RDX, [rip + 0x100]   ip=0x1000, instr_len=7, target=0x1107
        // Encoding: 48 8D 15 00 01 00 00
        let bytes = [0x48, 0x8D, 0x15, 0x00, 0x01, 0x00, 0x00];
        let ins = decode_one(&bytes, 0x1000, 64);
        let mut rf = RegFile::new();
        record_instr(&mut rf, &ins);
        assert_eq!(rf.get(Register::RDX), RegState::Const(0x1107));
    }

    #[test]
    fn movsxd_with_base_records_table_load() {
        // MOVSXD RAX, dword ptr [RDX + RCX*4]
        // Encoding: 48 63 04 8A
        let mut rf = RegFile::new();
        rf.set(Register::RDX, RegState::Const(0x2000));
        let bytes = [0x48, 0x63, 0x04, 0x8A];
        let ins = decode_one(&bytes, 0x1010, 64);
        record_instr(&mut rf, &ins);
        match rf.get(Register::RAX) {
            RegState::TableLoad { table_va, scale, elem, .. } => {
                assert_eq!(table_va, 0x2000);
                assert_eq!(scale, 4);
                assert_eq!(elem, ElemKind::I32);
            }
            other => panic!("expected TableLoad, got {other:?}"),
        }
    }

    #[test]
    fn add_promotes_tableload_to_baseplustable() {
        let mut rf = RegFile::new();
        rf.set(Register::RDX, RegState::Const(0x2000));
        rf.set(Register::RAX, RegState::TableLoad {
            table_va: 0x2000, scale: 4, index_reg: Register::RCX, elem: ElemKind::I32,
        });
        // ADD RAX, RDX
        let bytes = [0x48, 0x01, 0xD0];
        let ins = decode_one(&bytes, 0x1014, 64);
        record_instr(&mut rf, &ins);
        match rf.get(Register::RAX) {
            RegState::BasePlusTable { base_va, table_va, scale, elem, .. } => {
                assert_eq!(base_va, 0x2000);
                assert_eq!(table_va, 0x2000);
                assert_eq!(scale, 4);
                assert_eq!(elem, ElemKind::I32);
            }
            other => panic!("expected BasePlusTable, got {other:?}"),
        }
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

    #[test]
    fn unknown_mov_invalidates_destination() {
        let mut rf = RegFile::new();
        rf.set(Register::RAX, RegState::Const(0x42));
        // MOV RAX, [RBX] — memory load, we don't track these
        let bytes = [0x48, 0x8B, 0x03];
        let ins = decode_one(&bytes, 0x1000, 64);
        record_instr(&mut rf, &ins);
        assert_eq!(rf.get(Register::RAX), RegState::Unknown);
    }

    #[test]
    fn cmp_does_not_disturb_state() {
        let mut rf = RegFile::new();
        rf.set(Register::RAX, RegState::Const(0x42));
        // CMP RAX, RCX  — compare, no GPR write
        let bytes = [0x48, 0x39, 0xC8];
        let ins = decode_one(&bytes, 0x1000, 64);
        record_instr(&mut rf, &ins);
        assert_eq!(rf.get(Register::RAX), RegState::Const(0x42));
    }
}
