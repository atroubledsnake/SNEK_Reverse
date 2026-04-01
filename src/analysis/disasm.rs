use std::fmt;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind, Register};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm32,
    Arm64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub operands_semantic: Vec<Operand>,
    pub is_jump: bool,
    pub is_call: bool,
    pub target_address: Option<u64>,
    pub ref_address: Option<u64>,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}: {:<8} {}", self.address, self.mnemonic, self.operands.join(", "))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Register(String),
    Immediate(i64),
    Memory {
        segment: Option<String>,
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        displacement: i64,
        absolute: Option<u64>,
        ip_relative: bool,
    },
    Unknown(String),
}

#[allow(dead_code)]
pub trait Disassembler {
    fn new(arch: Architecture) -> Self where Self: Sized;
    fn disassemble_block(&self, data: &[u8], start_address: u64) -> Vec<Instruction>;
    fn identify_functions(&self, data: &[u8], start_address: u64) -> Vec<u64>;
}

#[allow(dead_code)]
pub struct X86Decoder {
    pub is_64_bit: bool,
}

impl Disassembler for X86Decoder {
    fn new(arch: Architecture) -> Self {
        X86Decoder {
            is_64_bit: arch == Architecture::X86_64,
        }
    }

    fn disassemble_block(&self, data: &[u8], start_address: u64) -> Vec<Instruction> {
        let bitness = if self.is_64_bit { 64 } else { 32 };
        let mut decoder = Decoder::with_ip(bitness, data, start_address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();

        let mut out = Vec::new();
        while decoder.can_decode() {
            let pos_before = decoder.position();
            let inst = decoder.decode();
            let pos_after = decoder.position();
            if pos_after <= pos_before || pos_after > data.len() {
                break;
            }

            let mut formatted = String::new();
            formatter.format(&inst, &mut formatted);
            let formatted = formatted.trim().to_string();

            let mut mnemonic = format!("{:?}", inst.mnemonic()).to_lowercase();
            if inst.has_lock_prefix() {
                mnemonic = format!("lock {}", mnemonic);
            }
            if inst.has_repne_prefix() {
                mnemonic = format!("repne {}", mnemonic);
            } else if inst.has_rep_prefix() {
                mnemonic = format!("rep {}", mnemonic);
            } else if inst.has_repe_prefix() {
                mnemonic = format!("repe {}", mnemonic);
            }

            let operands = if inst.op_count() == 0 {
                Vec::new()
            } else {
                let rest = if formatted.starts_with(&mnemonic) {
                    formatted[mnemonic.len()..].trim()
                } else {
                    formatted.splitn(2, ' ').nth(1).unwrap_or("").trim()
                };
                if rest.is_empty() {
                    Vec::new()
                } else {
                    rest.split(", ").map(|s| s.trim().to_string()).collect()
                }
            };

            let reg_to_string = |r: Register| -> Option<String> {
                if r == Register::None {
                    None
                } else {
                    Some(format!("{:?}", r).to_lowercase())
                }
            };

            let mut operands_semantic: Vec<Operand> = Vec::new();
            for i in 0..inst.op_count() {
                let k = inst.op_kind(i);
                let op = match k {
                    OpKind::Register => Operand::Register(format!("{:?}", inst.op_register(i)).to_lowercase()),
                    OpKind::Immediate8 => Operand::Immediate(inst.immediate8() as i8 as i64),
                    OpKind::Immediate16 => Operand::Immediate(inst.immediate16() as i16 as i64),
                    OpKind::Immediate32 => Operand::Immediate(inst.immediate32() as i32 as i64),
                    OpKind::Immediate64 => Operand::Immediate(inst.immediate64() as i64),
                    OpKind::Immediate8to16 => Operand::Immediate(inst.immediate8to16() as i16 as i64),
                    OpKind::Immediate8to32 => Operand::Immediate(inst.immediate8to32() as i32 as i64),
                    OpKind::Immediate8to64 => Operand::Immediate(inst.immediate8to64() as i64),
                    OpKind::Immediate32to64 => Operand::Immediate(inst.immediate32to64() as i64),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 | OpKind::FarBranch16 | OpKind::FarBranch32 => {
                        Operand::Immediate(inst.near_branch_target() as i64)
                    }
                    OpKind::Memory => {
                        let base = inst.memory_base();
                        let index = inst.memory_index();
                        let scale = inst.memory_index_scale();
                        let disp = inst.memory_displacement64() as i64;
                        let seg = inst.memory_segment();
                        let ip_rel = inst.is_ip_rel_memory_operand();
                        let abs = if base == Register::None && index == Register::None {
                            let a = inst.memory_displacement64();
                            if a == 0 { None } else { Some(a) }
                        } else {
                            None
                        };
                        Operand::Memory {
                            segment: reg_to_string(seg),
                            base: reg_to_string(base),
                            index: reg_to_string(index),
                            scale,
                            displacement: disp,
                            absolute: abs,
                            ip_relative: ip_rel,
                        }
                    }
                    _ => Operand::Unknown(format!("{:?}", k)),
                };
                operands_semantic.push(op);
            }

            let mut is_jump = false;
            let mut is_call = false;
            let mut target_address = None;
            let mut ref_address = None;

            match inst.flow_control() {
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::IndirectBranch => {
                    is_jump = true;
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    is_call = true;
                }
                _ => {}
            }

            if is_jump || is_call {
                if matches!(
                    inst.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 | OpKind::FarBranch16 | OpKind::FarBranch32
                ) {
                    target_address = Some(inst.near_branch_target());
                }
            }

            let mut has_mem = false;
            for i in 0..inst.op_count() {
                if inst.op_kind(i) == OpKind::Memory {
                    has_mem = true;
                    break;
                }
            }

            if has_mem {
                if inst.is_ip_rel_memory_operand() {
                    ref_address = Some(inst.ip_rel_memory_address());
                } else if inst.memory_base() == Register::None && inst.memory_index() == Register::None {
                    let a = inst.memory_displacement64();
                    if a != 0 {
                        ref_address = Some(a);
                    }
                }
            }

            out.push(Instruction {
                address: start_address + pos_before as u64,
                bytes: data[pos_before..pos_after].to_vec(),
                mnemonic,
                operands,
                operands_semantic,
                is_jump,
                is_call,
                target_address,
                ref_address,
            });

            if out.len() % 4000 == 0 {
                std::thread::yield_now();
            }
        }

        out
    }

    fn identify_functions(&self, data: &[u8], start_address: u64) -> Vec<u64> {
        let bitness = if self.is_64_bit { 64 } else { 32 };
        let mut decoder = Decoder::with_ip(bitness, data, start_address, DecoderOptions::NONE);
        let start = start_address;
        let end = start_address.saturating_add(data.len() as u64);

        let mut funcs = std::collections::BTreeSet::new();
        while decoder.can_decode() {
            let pos_before = decoder.position();
            let inst = decoder.decode();
            let pos_after = decoder.position();
            if pos_after <= pos_before {
                break;
            }

            if matches!(inst.flow_control(), FlowControl::Call) {
                if matches!(
                    inst.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    let t = inst.near_branch_target();
                    if t >= start && t < end {
                        funcs.insert(t);
                    }
                }
            }
        }

        funcs.into_iter().collect()
    }
}
