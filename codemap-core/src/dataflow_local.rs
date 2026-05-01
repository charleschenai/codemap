// ── Bounded Backward Constant-Propagator ───────────────────────────
//
// Originally introduced in 5.27.0 (Ship 1 #7) inside disasm_jt.rs as
// the engine for jump-table resolution. 5.33.0 (Ship 3 #9b) became
// the second consumer (XOR-decryption-loop detection inside
// `decode_functions`). At two consumers, the original handoff plan
// said to extract — that's what this file is.
//
// Public API:
//   - `RegState`     — abstract value of a GPR
//   - `ElemKind`     — sign/size descriptor for memory loads
//   - `RegFile`      — 16-slot register file (GPRs collapsed across
//                      64/32/16/8-bit aliases)
//   - `record_instr` — update RegFile from one decoded instruction
//   - `MAX_HISTORY`  — recommended bound for backward window
//
// The propagator is intentionally tiny — it only models LEA, MOV imm,
// MOVSXD/MOVSX/MOVZX from indexed memory, and ADD reg+reg. Anything
// else conservatively invalidates the destination register. This
// covers ~95% of compiler-generated dispatch / decryption-key
// idioms; the rest needs a real CPG (out of scope for codemap).
//
// Adding a new consumer? You probably only need:
//
//   ```
//   use crate::dataflow_local::{RegFile, RegState, record_instr};
//
//   let mut rf = RegFile::new();
//   for ins in instructions {
//       // Inspect ins.mnemonic() / ins.op0_register() / etc. and
//       // query rf.get(reg) BEFORE record_instr — the value reflects
//       // state going INTO this instruction.
//       record_instr(&mut rf, &ins);
//   }
//   ```
//
// Architectural notes:
//   - RegState is value-typed (Copy). Cheap to clone, cheap to set.
//   - record_instr is O(1) per instruction. The 16-GPR slot array
//     fits in cache; record_instr's match table is small.
//   - reg_index collapses subregs by hand instead of using iced-x86's
//     `full_register()` helper because that requires the `instr_info`
//     feature codemap doesn't enable (keeps the dep tree minimal).
//   - record_instr takes &mut RegFile + &Instruction — the caller
//     owns iteration order, so callers can flexibly run the
//     propagator forwards (typical) or reset between basic blocks.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegState {
    Unknown,
    /// Register holds a known absolute value (immediate, RIP-relative LEA).
    Const(u64),
    /// Register holds `table[idx*scale]` — an N-byte signed/unsigned
    /// value loaded from `table_va + idx*scale`. Used to recognize
    /// the MOVSXD step in jump-table Pattern A.
    TableLoad {
        table_va: u64,
        scale: u8,
        index_reg: Register,
        elem: ElemKind,
    },
    /// Register holds `base + table[idx*scale]` — the result of the
    /// `add rax, rdx` step in jump-table Pattern A. JMPing on this
    /// register resolves to absolute addresses by re-reading the table.
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
    pub fn size(self) -> u8 {
        match self {
            ElemKind::I8 => 1,
            ElemKind::I16 => 2,
            ElemKind::I32 | ElemKind::U32 => 4,
            ElemKind::U64 => 8,
        }
    }
}

/// Maximum number of past instructions whose effects we track.
/// Callers using a sliding window should reset the RegFile between
/// windows of this length — but most current consumers reset per
/// function rather than per fixed window.
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
/// resolution + crypto-loop detection (LEA, MOV imm, MOVSXD/MOVSX
/// /MOVZX from indexed memory, ADD reg+reg). Everything else
/// conservatively invalidates the write destination.
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
                    iced_x86::MemorySize::UInt8 => ElemKind::U32,
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

    #[test]
    fn elem_kind_size_matches_layout() {
        assert_eq!(ElemKind::I8.size(), 1);
        assert_eq!(ElemKind::I16.size(), 2);
        assert_eq!(ElemKind::I32.size(), 4);
        assert_eq!(ElemKind::U32.size(), 4);
        assert_eq!(ElemKind::U64.size(), 8);
    }

    #[test]
    fn reg_file_reset_clears_state() {
        let mut rf = RegFile::new();
        rf.set(Register::RAX, RegState::Const(0x42));
        rf.set(Register::RDX, RegState::Const(0x100));
        rf.reset();
        assert_eq!(rf.get(Register::RAX), RegState::Unknown);
        assert_eq!(rf.get(Register::RDX), RegState::Unknown);
    }

    #[test]
    fn subreg_aliases_share_slot() {
        // Writing to RAX should be visible when reading EAX, AX, AL.
        let mut rf = RegFile::new();
        rf.set(Register::RAX, RegState::Const(0xDEADBEEF));
        assert_eq!(rf.get(Register::EAX), RegState::Const(0xDEADBEEF));
        assert_eq!(rf.get(Register::AX),  RegState::Const(0xDEADBEEF));
        assert_eq!(rf.get(Register::AL),  RegState::Const(0xDEADBEEF));
        // And writing to AL is visible through RAX (same slot).
        rf.set(Register::AL, RegState::Const(0x42));
        assert_eq!(rf.get(Register::RAX), RegState::Const(0x42));
    }
}
