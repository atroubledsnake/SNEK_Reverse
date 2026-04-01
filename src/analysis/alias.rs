use std::collections::{BTreeMap, HashMap};

use crate::analysis::ir::{Expr, IrFunction, Stmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemLoc {
    Stack(i64),
    Abs(i64),
    Unknown,
}

pub fn classify_addr(addr: &Expr) -> MemLoc {
    match addr {
        Expr::Stack(off) => MemLoc::Stack(*off),
        Expr::Imm(v) => MemLoc::Abs(*v),
        _ => MemLoc::Unknown,
    }
}

pub fn render_alias_summary(func: &IrFunction) -> Vec<String> {
    let mut counts: BTreeMap<MemLoc, (u64, u64)> = BTreeMap::new();
    for b in func.blocks.values() {
        for s in &b.stmts {
            match s {
                Stmt::Assign { expr, .. } => {
                    if let Expr::Load { addr, .. } = expr {
                        let loc = classify_addr(addr);
                        let e = counts.entry(loc).or_insert((0, 0));
                        e.0 += 1;
                    }
                }
                Stmt::Store { addr, .. } => {
                    let loc = classify_addr(addr);
                    let e = counts.entry(loc).or_insert((0, 0));
                    e.1 += 1;
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    out.push("Location  loads  stores".to_string());
    for (k, (ld, st)) in counts {
        let name = match k {
            MemLoc::Stack(off) => {
                if off < 0 {
                    format!("stack[{:#x}]", -off)
                } else {
                    format!("stack[+{:#x}]", off)
                }
            }
            MemLoc::Abs(v) => format!("{:#x}", v),
            MemLoc::Unknown => "unknown".to_string(),
        };
        out.push(format!("{:<16} {:>5} {:>6}", name, ld, st));
    }
    out
}

pub fn forward_stores_to_loads(func: &mut IrFunction) -> bool {
    let mut changed = false;
    for b in func.blocks.values_mut() {
        let mut mem: HashMap<MemLoc, Expr> = HashMap::new();
        for s in &mut b.stmts {
            match s {
                Stmt::Assign { expr, .. } => {
                    if let Expr::Load { addr, .. } = expr {
                        let loc = classify_addr(addr);
                        if loc != MemLoc::Unknown {
                            if let Some(v) = mem.get(&loc).cloned() {
                                *expr = v;
                                changed = true;
                            }
                        } else {
                            mem.clear();
                        }
                    }
                }
                Stmt::Store { addr, value, .. } => {
                    let loc = classify_addr(addr);
                    if loc != MemLoc::Unknown {
                        mem.insert(loc, value.clone());
                    } else {
                        mem.clear();
                    }
                }
                Stmt::Call { .. } => {
                    mem.clear();
                }
                Stmt::Phi { .. } => {}
            }
        }
    }
    changed
}

