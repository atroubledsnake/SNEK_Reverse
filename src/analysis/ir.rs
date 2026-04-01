use std::collections::HashMap;
use crate::analysis::decomp::ControlFlowGraph;
use crate::analysis::disasm::{Instruction, Operand};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Var(String),
    Imm(i64),
    Unknown(String),
    BinOp {
        op: BinOp,
        a: Box<Expr>,
        b: Box<Expr>,
    },
    Load {
        addr: Box<Expr>,
        size: u32,
    },
    Stack(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Cmp {
        op: CmpOp,
        lhs: Expr,
        rhs: Expr,
    },
    NonZero(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Phi {
        var: String,
        dst: String,
        sources: Vec<(u64, String)>,
    },
    Assign {
        dst: String,
        expr: Expr,
    },
    Store {
        addr: Expr,
        value: Expr,
        size: u32,
    },
    Call {
        target: Expr,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Jump(u64),
    Branch {
        cond: Cond,
        then_t: u64,
        else_t: u64,
    },
    Return,
    Unreachable,
}

#[derive(Debug, Clone)]
pub struct IrBlock {
    pub addr: u64,
    pub preds: Vec<u64>,
    pub succs: Vec<u64>,
    pub stmts: Vec<Stmt>,
    pub term: Term,
}

#[derive(Debug, Clone)]
pub struct IrFunction {
    pub entry: u64,
    pub blocks: HashMap<u64, IrBlock>,
}

fn reg_expr(name: &str) -> Expr {
    Expr::Var(name.to_lowercase())
}

fn imm_expr(v: i64) -> Expr {
    Expr::Imm(v)
}

fn addr_from_mem(inst: &Instruction, m: &Operand) -> Expr {
    let Operand::Memory { base, index, scale, displacement, absolute, .. } = m else {
        return imm_expr(0);
    };

    if let Some(a) = inst.ref_address.or(*absolute) {
        return imm_expr(a as i64);
    }

    let mut is_stack = false;
    if let Some(b) = base {
        let bl = b.to_lowercase();
        if bl == "rsp" || bl == "rbp" || bl == "esp" || bl == "ebp" {
            is_stack = true;
        }
    }

    if is_stack && index.is_none() {
        return Expr::Stack(*displacement);
    }

    let mut e: Option<Expr> = None;
    if let Some(b) = base {
        e = Some(reg_expr(b));
    }
    if let Some(ix) = index {
        let ix_e = reg_expr(ix);
        let mul = match *scale {
            0 | 1 => ix_e,
            2 => Expr::BinOp { op: BinOp::Shl, a: Box::new(ix_e), b: Box::new(imm_expr(1)) },
            4 => Expr::BinOp { op: BinOp::Shl, a: Box::new(ix_e), b: Box::new(imm_expr(2)) },
            8 => Expr::BinOp { op: BinOp::Shl, a: Box::new(ix_e), b: Box::new(imm_expr(3)) },
            _ => Expr::Unknown(format!("mem_scale_{}", scale)),
        };
        e = Some(match e {
            Some(prev) => Expr::BinOp { op: BinOp::Add, a: Box::new(prev), b: Box::new(mul) },
            None => mul,
        });
    }
    if *displacement != 0 {
        e = Some(match e {
            Some(prev) => Expr::BinOp { op: BinOp::Add, a: Box::new(prev), b: Box::new(imm_expr(*displacement)) },
            None => imm_expr(*displacement),
        });
    }
    e.unwrap_or_else(|| imm_expr(0))
}

impl BinOp {
    fn to_str(&self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Xor => "^",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
        }
    }
}

fn mem_size_from_str(s: &str) -> u32 {
    let low = s.to_lowercase();
    if low.contains("byte ptr") {
        1
    } else if low.contains("word ptr") {
        2
    } else if low.contains("dword ptr") {
        4
    } else if low.contains("qword ptr") {
        8
    } else if low.contains("xmmword ptr") {
        16
    } else if low.contains("ymmword ptr") {
        32
    } else if low.contains("zmmword ptr") {
        64
    } else {
        8
    }
}

fn expr_from_operand(inst: &Instruction, op: &Operand, op_str: Option<&str>) -> Expr {
    match op {
        Operand::Register(r) => reg_expr(r),
        Operand::Immediate(v) => imm_expr(*v),
        Operand::Memory { .. } => {
            let size = op_str.map(mem_size_from_str).unwrap_or(8);
            Expr::Load { addr: Box::new(addr_from_mem(inst, op)), size }
        }
        Operand::Unknown(k) => Expr::Unknown(k.clone()),
    }
}

fn store_size_from_operand(op_str: Option<&str>) -> u32 {
    op_str.map(mem_size_from_str).unwrap_or(8)
}

fn cond_from_jcc(mn: &str, last: Option<(Expr, Expr, bool)>) -> Option<Cond> {
    let (lhs, rhs, is_test) = last?;
    let m = mn.to_lowercase();
    let c = match m.as_str() {
        "je" | "jz" => {
            if is_test {
                Cond::Cmp { op: CmpOp::Eq, lhs: Expr::BinOp { op: BinOp::And, a: Box::new(lhs), b: Box::new(rhs) }, rhs: imm_expr(0) }
            } else {
                Cond::Cmp { op: CmpOp::Eq, lhs, rhs }
            }
        }
        "jne" | "jnz" => {
            if is_test {
                Cond::Cmp { op: CmpOp::Ne, lhs: Expr::BinOp { op: BinOp::And, a: Box::new(lhs), b: Box::new(rhs) }, rhs: imm_expr(0) }
            } else {
                Cond::Cmp { op: CmpOp::Ne, lhs, rhs }
            }
        }
        "jb" | "jc" | "jnae" => Cond::Cmp { op: CmpOp::Ult, lhs, rhs },
        "jbe" | "jna" => Cond::Cmp { op: CmpOp::Ule, lhs, rhs },
        "ja" | "jnbe" => Cond::Cmp { op: CmpOp::Ugt, lhs, rhs },
        "jae" | "jnb" | "jnc" => Cond::Cmp { op: CmpOp::Uge, lhs, rhs },
        "jl" | "jnge" => Cond::Cmp { op: CmpOp::Slt, lhs, rhs },
        "jle" | "jng" => Cond::Cmp { op: CmpOp::Sle, lhs, rhs },
        "jg" | "jnle" => Cond::Cmp { op: CmpOp::Sgt, lhs, rhs },
        "jge" | "jnl" => Cond::Cmp { op: CmpOp::Sge, lhs, rhs },
        _ => Cond::NonZero(lhs),
    };
    Some(c)
}

pub fn lift_cfg(cfg: &ControlFlowGraph) -> IrFunction {
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for (a, b) in &cfg.blocks {
        for &s in &b.successors {
            preds.entry(s).or_default().push(*a);
        }
    }

    let mut blocks: HashMap<u64, IrBlock> = HashMap::new();
    for (a, b) in &cfg.blocks {
        let mut stmts = Vec::new();
        let mut term = Term::Unreachable;
        let mut last_cmp: Option<(Expr, Expr, bool)> = None;

        for inst in &b.instructions {
            let m = inst.mnemonic.to_lowercase();
            match m.as_str() {
                "cmp" => {
                    if inst.operands_semantic.len() >= 2 {
                        let lhs = expr_from_operand(inst, &inst.operands_semantic[0], inst.operands.get(0).map(|s| s.as_str()));
                        let rhs = expr_from_operand(inst, &inst.operands_semantic[1], inst.operands.get(1).map(|s| s.as_str()));
                        last_cmp = Some((lhs, rhs, false));
                    }
                }
                "test" => {
                    if inst.operands_semantic.len() >= 2 {
                        let lhs = expr_from_operand(inst, &inst.operands_semantic[0], inst.operands.get(0).map(|s| s.as_str()));
                        let rhs = expr_from_operand(inst, &inst.operands_semantic[1], inst.operands.get(1).map(|s| s.as_str()));
                        last_cmp = Some((lhs, rhs, true));
                    }
                }
                "mov" => {
                    if inst.operands_semantic.len() >= 2 {
                        let dst = &inst.operands_semantic[0];
                        let src = &inst.operands_semantic[1];
                        match dst {
                            Operand::Register(r) => {
                                let expr = expr_from_operand(inst, src, inst.operands.get(1).map(|s| s.as_str()));
                                stmts.push(Stmt::Assign { dst: r.to_lowercase(), expr });
                            }
                            Operand::Memory { .. } => {
                                let addr = addr_from_mem(inst, dst);
                                let value = expr_from_operand(inst, src, inst.operands.get(1).map(|s| s.as_str()));
                                stmts.push(Stmt::Store { addr, value, size: store_size_from_operand(inst.operands.get(0).map(|s| s.as_str())) });
                            }
                            _ => {}
                        }
                    }
                }
                "lea" => {
                    if inst.operands_semantic.len() >= 2 {
                        let dst = &inst.operands_semantic[0];
                        let src = &inst.operands_semantic[1];
                        if let Operand::Register(r) = dst {
                            let expr = match src {
                                Operand::Memory { .. } => addr_from_mem(inst, src),
                                _ => expr_from_operand(inst, src, inst.operands.get(1).map(|s| s.as_str())),
                            };
                            stmts.push(Stmt::Assign { dst: r.to_lowercase(), expr });
                        }
                    }
                }
                "add" | "sub" | "xor" | "and" | "or" => {
                    if inst.operands_semantic.len() >= 2 {
                        let dst = &inst.operands_semantic[0];
                        let src = &inst.operands_semantic[1];
                        if let Operand::Register(r) = dst {
                            let op = match m.as_str() {
                                "add" => BinOp::Add,
                                "sub" => BinOp::Sub,
                                "xor" => BinOp::Xor,
                                "and" => BinOp::And,
                                _ => BinOp::Or,
                            };
                            let a = reg_expr(r);
                            let b = expr_from_operand(inst, src, inst.operands.get(1).map(|s| s.as_str()));
                            let expr = Expr::BinOp { op, a: Box::new(a), b: Box::new(b) };
                            stmts.push(Stmt::Assign { dst: r.to_lowercase(), expr });
                        }
                    }
                }
                "call" => {
                    let target = if let Some(t) = inst.target_address {
                        imm_expr(t as i64)
                    } else if let Some(r) = inst.ref_address {
                        imm_expr(r as i64)
                    } else {
                        imm_expr(0)
                    };
                    stmts.push(Stmt::Call { target, args: vec![] });
                }
                "ret" => {
                    term = Term::Return;
                }
                _ => {}
            }
        }

        if term == Term::Unreachable {
            let last = b.instructions.last();
            if let Some(inst) = last {
                if inst.is_jump {
                    if inst.mnemonic.to_lowercase() == "jmp" {
                        if let Some(t) = inst.target_address {
                            term = Term::Jump(t);
                        }
                    } else {
                        let then_t = inst.target_address.unwrap_or(0);
                        let else_t = b.successors.iter().copied().find(|&x| x != then_t).unwrap_or(0);
                        if let Some(cond) = cond_from_jcc(&inst.mnemonic, last_cmp) {
                            term = Term::Branch { cond, then_t, else_t };
                        } else {
                            term = Term::Branch { cond: Cond::NonZero(imm_expr(1)), then_t, else_t };
                        }
                    }
                } else {
                    if let Some(&ft) = b.successors.first() {
                        term = Term::Jump(ft);
                    } else {
                        term = Term::Return;
                    }
                }
            } else {
                term = Term::Return;
            }
        }

        blocks.insert(
            *a,
            IrBlock {
                addr: *a,
                preds: preds.get(a).cloned().unwrap_or_default(),
                succs: b.successors.clone(),
                stmts,
                term,
            },
        );
    }

    IrFunction { entry: cfg.entry_block, blocks }
}

pub fn render_ir(func: &IrFunction) -> String {
    let mut addrs: Vec<u64> = func.blocks.keys().copied().collect();
    addrs.sort();
    let mut out = String::new();
    out.push_str(&format!("entry {:#010x}\n", func.entry));
    for a in addrs {
        let b = &func.blocks[&a];
        out.push_str(&format!("\nblock {:#010x}\n", b.addr));
        if !b.preds.is_empty() {
            out.push_str("  preds: ");
            for (i, p) in b.preds.iter().enumerate() {
                if i != 0 { out.push_str(", "); }
                out.push_str(&format!("{:#010x}", p));
            }
            out.push('\n');
        }
        if !b.succs.is_empty() {
            out.push_str("  succs: ");
            for (i, s) in b.succs.iter().enumerate() {
                if i != 0 { out.push_str(", "); }
                out.push_str(&format!("{:#010x}", s));
            }
            out.push('\n');
        }
        for s in &b.stmts {
            out.push_str("  ");
            out.push_str(&render_stmt(s));
            out.push('\n');
        }
        out.push_str("  ");
        out.push_str(&render_term(&b.term));
        out.push('\n');
    }
    out
}

fn render_stmt(s: &Stmt) -> String {
    match s {
        Stmt::Phi { var, dst, sources } => {
            let mut t = format!("{} = phi {}(", dst, var);
            for (i, (p, v)) in sources.iter().enumerate() {
                if i != 0 { t.push_str(", "); }
                t.push_str(&format!("[{:#x}: {}]", p, v));
            }
            t.push(')');
            t
        }
        Stmt::Assign { dst, expr } => format!("{} = {}", dst, render_expr(expr)),
        Stmt::Store { addr, value, size } => format!("store{} {} <- {}", size * 8, render_expr(addr), render_expr(value)),
        Stmt::Call { target, args } => {
            let mut t = format!("call {}", render_expr(target));
            t.push('(');
            for (i, a) in args.iter().enumerate() {
                if i != 0 { t.push_str(", "); }
                t.push_str(&render_expr(a));
            }
            t.push(')');
            t
        }
    }
}

fn render_term(t: &Term) -> String {
    match t {
        Term::Jump(a) => format!("jmp {:#010x}", a),
        Term::Branch { cond, then_t, else_t } => format!("br {} ? {:#010x} : {:#010x}", render_cond(cond), then_t, else_t),
        Term::Return => "ret".to_string(),
        Term::Unreachable => "unreachable".to_string(),
    }
}

fn render_cond(c: &Cond) -> String {
    match c {
        Cond::Cmp { op, lhs, rhs } => {
            let o = match op {
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
                CmpOp::Ult => "u<",
                CmpOp::Ule => "u<=",
                CmpOp::Ugt => "u>",
                CmpOp::Uge => "u>=",
                CmpOp::Slt => "s<",
                CmpOp::Sle => "s<=",
                CmpOp::Sgt => "s>",
                CmpOp::Sge => "s>=",
            };
            format!("({} {} {})", render_expr(lhs), o, render_expr(rhs))
        }
        Cond::NonZero(e) => format!("({} != 0)", render_expr(e)),
    }
}

fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Imm(v) => format!("{:#x}", v),
        Expr::Unknown(k) => format!("unknown({})", k),
        Expr::BinOp { op, a, b } => format!("({} {} {})", render_expr(a), op.to_str(), render_expr(b)),
        Expr::Load { addr, size } => format!("load{} {}", size * 8, render_expr(addr)),
        Expr::Stack(offset) => {
            if *offset < 0 {
                format!("stack[{:#x}]", -offset)
            } else {
                format!("stack[+{:#x}]", offset)
            }
        }
    }
}
