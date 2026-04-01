use std::collections::{HashMap, HashSet};

use crate::analysis::ir::{Cond, Expr, IrFunction, Stmt, Term};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Unknown,
    U8,
    U16,
    U32,
    U64,
    Usize,
}

fn ty_for_size(size: u32) -> Ty {
    match size {
        1 => Ty::U8,
        2 => Ty::U16,
        4 => Ty::U32,
        8 => Ty::U64,
        _ => Ty::U64,
    }
}

fn join(a: Ty, b: Ty) -> Ty {
    use Ty::*;
    match (a, b) {
        (Unknown, x) | (x, Unknown) => x,
        (Usize, _) | (_, Usize) => Usize,
        (U64, _) | (_, U64) => U64,
        (U32, _) | (_, U32) => U32,
        (U16, _) | (_, U16) => U16,
        (U8, U8) => U8,
    }
}

fn vars_in_expr(e: &Expr, out: &mut HashSet<String>) {
    match e {
        Expr::Var(v) => {
            out.insert(v.clone());
        }
        Expr::Imm(_) => {}
        Expr::Unknown(_) => {}
        Expr::Stack(_) => {}
        Expr::BinOp { a, b, .. } => {
            vars_in_expr(a, out);
            vars_in_expr(b, out);
        }
        Expr::Load { addr, .. } => {
            vars_in_expr(addr, out);
        }
    }
}

fn ty_from_expr(e: &Expr, tys: &HashMap<String, Ty>) -> Ty {
    match e {
        Expr::Var(v) => tys.get(v).copied().unwrap_or(Ty::Unknown),
        Expr::Imm(_) => Ty::Unknown,
        Expr::Unknown(_) => Ty::Unknown,
        Expr::Stack(_) => Ty::Usize,
        Expr::BinOp { a, b, .. } => join(ty_from_expr(a, tys), ty_from_expr(b, tys)),
        Expr::Load { size, .. } => ty_for_size(*size),
    }
}

fn mark_addr_expr(e: &Expr, tys: &mut HashMap<String, Ty>) -> bool {
    let mut changed = false;
    let mut vars = HashSet::new();
    vars_in_expr(e, &mut vars);
    for v in vars {
        let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
        let next = join(cur, Ty::Usize);
        if next != cur {
            tys.insert(v, next);
            changed = true;
        }
    }
    changed
}

pub fn infer_var_types(func: &IrFunction) -> HashMap<String, Ty> {
    let mut tys: HashMap<String, Ty> = HashMap::new();

    for b in func.blocks.values() {
        for s in &b.stmts {
            match s {
                Stmt::Assign { dst, .. } | Stmt::Phi { dst, .. } => {
                    if !dst.is_empty() {
                        tys.entry(dst.clone()).or_insert(Ty::Unknown);
                    }
                }
                _ => {}
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for b in func.blocks.values() {
            for s in &b.stmts {
                match s {
                    Stmt::Assign { dst, expr } => {
                        if dst.is_empty() {
                            continue;
                        }
                        let cur = tys.get(dst).copied().unwrap_or(Ty::Unknown);
                        let mut next = ty_from_expr(expr, &tys);
                        next = join(cur, next);
                        if next != cur {
                            tys.insert(dst.clone(), next);
                            changed = true;
                        }
                    }
                    Stmt::Phi { dst, sources, .. } => {
                        if dst.is_empty() {
                            continue;
                        }
                        let cur = tys.get(dst).copied().unwrap_or(Ty::Unknown);
                        let mut next = Ty::Unknown;
                        for (_, v) in sources {
                            if let Some(t) = tys.get(v).copied() {
                                next = join(next, t);
                            }
                        }
                        next = join(cur, next);
                        if next != cur {
                            tys.insert(dst.clone(), next);
                            changed = true;
                        }
                    }
                    Stmt::Store { addr, value, size } => {
                        changed |= mark_addr_expr(addr, &mut tys);
                        let t = ty_for_size(*size);
                        let mut used = HashSet::new();
                        vars_in_expr(value, &mut used);
                        for v in used {
                            let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
                            let next = join(cur, t);
                            if next != cur {
                                tys.insert(v, next);
                                changed = true;
                            }
                        }
                    }
                    Stmt::Call { target, args } => {
                        changed |= mark_addr_expr(target, &mut tys);
                        for a in args {
                            let mut vars = HashSet::new();
                            vars_in_expr(a, &mut vars);
                            for v in vars {
                                let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
                                let next = join(cur, Ty::U64);
                                if next != cur {
                                    tys.insert(v, next);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
            match &b.term {
                Term::Branch { cond, .. } => match cond {
                    Cond::Cmp { lhs, rhs, .. } => {
                        let tl = ty_from_expr(lhs, &tys);
                        let tr = ty_from_expr(rhs, &tys);
                        let t = join(tl, tr);

                        let mut lvars = HashSet::new();
                        vars_in_expr(lhs, &mut lvars);
                        for v in lvars {
                            let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
                            let next = join(cur, t);
                            if next != cur {
                                tys.insert(v, next);
                                changed = true;
                            }
                        }
                        let mut rvars = HashSet::new();
                        vars_in_expr(rhs, &mut rvars);
                        for v in rvars {
                            let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
                            let next = join(cur, t);
                            if next != cur {
                                tys.insert(v, next);
                                changed = true;
                            }
                        }
                    }
                    Cond::NonZero(e) => {
                        let mut vars = HashSet::new();
                        vars_in_expr(e, &mut vars);
                        for v in vars {
                            let cur = tys.get(&v).copied().unwrap_or(Ty::Unknown);
                            let next = join(cur, Ty::U64);
                            if next != cur {
                                tys.insert(v, next);
                                changed = true;
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }

    tys
}

pub fn render_types(tys: &HashMap<String, Ty>) -> Vec<String> {
    let mut vars: Vec<_> = tys.iter().collect();
    vars.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (v, t) in vars {
        let ts = match t {
            Ty::Unknown => "unknown",
            Ty::U8 => "u8",
            Ty::U16 => "u16",
            Ty::U32 => "u32",
            Ty::U64 => "u64",
            Ty::Usize => "usize",
        };
        out.push(format!("{}: {}", v, ts));
    }
    out
}
