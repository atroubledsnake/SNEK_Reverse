use std::collections::{HashSet, VecDeque};

use crate::analysis::ir::{Cond, CmpOp, Expr, IrFunction, Stmt, Term};

fn ty_for_size_c(size: u32) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        16 => "uint8_t",
        32 => "uint8_t",
        64 => "uint8_t",
        _ => "uint64_t",
    }
}

fn ty_for_size_rust(size: u32) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u8",
        32 => "u8",
        64 => "u8",
        _ => "u64",
    }
}

fn render_expr_c(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Imm(v) => format!("{:#x}", v),
        Expr::Unknown(k) => format!("unknown({})", k),
        Expr::BinOp { op, a, b } => format!("({} {} {})", render_expr_c(a), op_str(op), render_expr_c(b)),
        Expr::Load { addr, size } => {
            let ty = ty_for_size_c(*size);
            format!("*({}*)({})", ty, render_expr_c(addr))
        }
        Expr::Stack(offset) => {
            if *offset < 0 {
                format!("(stack_base - {:#x})", -offset)
            } else {
                format!("(stack_base + {:#x})", offset)
            }
        }
    }
}

fn render_expr_rust(e: &Expr) -> String {
    match e {
        Expr::Var(v) => v.clone(),
        Expr::Imm(v) => format!("0x{:x}", v),
        Expr::Unknown(k) => format!("unknown({})", k),
        Expr::BinOp { op, a, b } => format!("({} {} {})", render_expr_rust(a), op_str(op), render_expr_rust(b)),
        Expr::Load { addr, size } => {
            let ty = ty_for_size_rust(*size);
            format!("unsafe {{ *(({} as usize) as *const {}) }}", render_expr_rust(addr), ty)
        }
        Expr::Stack(offset) => {
            if *offset < 0 {
                format!("(stack_base - 0x{:x})", -offset)
            } else {
                format!("(stack_base + 0x{:x})", offset)
            }
        }
    }
}

fn op_str(op: &crate::analysis::ir::BinOp) -> &'static str {
    match op {
        crate::analysis::ir::BinOp::Add => "+",
        crate::analysis::ir::BinOp::Sub => "-",
        crate::analysis::ir::BinOp::Xor => "^",
        crate::analysis::ir::BinOp::And => "&",
        crate::analysis::ir::BinOp::Or => "|",
        crate::analysis::ir::BinOp::Shl => "<<",
        crate::analysis::ir::BinOp::Shr => ">>",
    }
}

fn render_cond_c(c: &Cond) -> String {
    match c {
        Cond::NonZero(e) => format!("({} != 0)", render_expr_c(e)),
        Cond::Cmp { op, lhs, rhs } => format!("({} {} {})", render_expr_c(lhs), cmp_str(*op), render_expr_c(rhs)),
    }
}

fn render_cond_rust(c: &Cond) -> String {
    match c {
        Cond::NonZero(e) => format!("({} != 0)", render_expr_rust(e)),
        Cond::Cmp { op, lhs, rhs } => format!("({} {} {})", render_expr_rust(lhs), cmp_str(*op), render_expr_rust(rhs)),
    }
}

fn cmp_str(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Ult => "<",
        CmpOp::Ule => "<=",
        CmpOp::Ugt => ">",
        CmpOp::Uge => ">=",
        CmpOp::Slt => "<",
        CmpOp::Sle => "<=",
        CmpOp::Sgt => ">",
        CmpOp::Sge => ">=",
    }
}

fn collect_vars(func: &IrFunction) -> Vec<String> {
    let mut vars: HashSet<String> = HashSet::new();
    for b in func.blocks.values() {
        for s in &b.stmts {
            match s {
                Stmt::Assign { dst, .. } => {
                    vars.insert(dst.clone());
                }
                Stmt::Phi { dst, .. } => {
                    vars.insert(dst.clone());
                }
                _ => {}
            }
        }
    }
    let mut v: Vec<String> = vars.into_iter().filter(|x| !x.is_empty()).collect();
    v.sort();
    v
}

fn topo_from_entry(func: &IrFunction) -> Vec<u64> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    q.push_back(func.entry);
    while let Some(b) = q.pop_front() {
        if !seen.insert(b) {
            continue;
        }
        out.push(b);
        if let Some(blk) = func.blocks.get(&b) {
            for &s in &blk.succs {
                q.push_back(s);
            }
        }
    }
    out
}

fn label_for(a: u64) -> String {
    format!("loc_{:x}", a)
}

fn edge_copies(func: &IrFunction, from: u64, to: u64) -> Vec<(String, String)> {
    let Some(b) = func.blocks.get(&to) else {
        return vec![];
    };
    let mut out = Vec::new();
    for s in &b.stmts {
        let Stmt::Phi { dst, sources, .. } = s else {
            continue;
        };
        let mut src: Option<String> = None;
        for (p, v) in sources {
            if *p == from {
                src = Some(v.clone());
                break;
            }
        }
        if let Some(src) = src {
            if !dst.is_empty() {
                out.push((dst.clone(), src));
            }
        }
    }
    out
}

fn render_copy(lang: &str, dst: &str, src: &str) -> String {
    if lang == "rust" {
        format!("    {} = {};\n", dst, src)
    } else {
        format!("    {} = {};\n", dst, src)
    }
}

pub fn render_function(func: &IrFunction, lang: &str) -> String {
    let order = topo_from_entry(func);
    let mut out = String::new();
    let tys = crate::analysis::types::infer_var_types(func);

    fn uses_stack_base(func: &IrFunction) -> bool {
        fn has_stack(e: &Expr) -> bool {
            match e {
                Expr::Stack(_) => true,
                Expr::Var(_) | Expr::Imm(_) | Expr::Unknown(_) => false,
                Expr::BinOp { a, b, .. } => has_stack(a) || has_stack(b),
                Expr::Load { addr, .. } => has_stack(addr),
            }
        }
        for b in func.blocks.values() {
            for s in &b.stmts {
                match s {
                    Stmt::Assign { expr, .. } => {
                        if has_stack(expr) {
                            return true;
                        }
                    }
                    Stmt::Store { addr, value, .. } => {
                        if has_stack(addr) || has_stack(value) {
                            return true;
                        }
                    }
                    Stmt::Call { target, args } => {
                        if has_stack(target) {
                            return true;
                        }
                        for a in args {
                            if has_stack(a) {
                                return true;
                            }
                        }
                    }
                    Stmt::Phi { .. } => {}
                }
            }
            if let Term::Branch { cond, .. } = &b.term {
                match cond {
                    Cond::Cmp { lhs, rhs, .. } => {
                        if has_stack(lhs) || has_stack(rhs) {
                            return true;
                        }
                    }
                    Cond::NonZero(e) => {
                        if has_stack(e) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    let need_stack_base = uses_stack_base(func);

    if lang == "rust" {
        out.push_str(&format!("pub unsafe fn sub_{:x}() {{\n", func.entry));
    } else {
        out.push_str(&format!("void sub_{:x}() {{\n", func.entry));
    }

    let vars = collect_vars(func);
    if lang == "rust" {
        if need_stack_base {
            out.push_str("    let mut stack_base: usize = 0;\n");
        }
        for v in &vars {
            let ty = tys.get(v).copied().unwrap_or(crate::analysis::types::Ty::Unknown);
            let ts = match ty {
                crate::analysis::types::Ty::U8 => "u8",
                crate::analysis::types::Ty::U16 => "u16",
                crate::analysis::types::Ty::U32 => "u32",
                crate::analysis::types::Ty::U64 | crate::analysis::types::Ty::Unknown => "u64",
                crate::analysis::types::Ty::Usize => "usize",
            };
            out.push_str(&format!("    let mut {}: {} = 0;\n", v, ts));
        }
    } else {
        out.push_str("    typedef unsigned long long uint64_t;\n");
        out.push_str("    typedef unsigned int uint32_t;\n");
        out.push_str("    typedef unsigned short uint16_t;\n");
        out.push_str("    typedef unsigned char uint8_t;\n");
        out.push_str("    typedef unsigned long long uintptr_t;\n");
        if need_stack_base {
            out.push_str("    uintptr_t stack_base = 0;\n");
        }
        for v in &vars {
            let ty = tys.get(v).copied().unwrap_or(crate::analysis::types::Ty::Unknown);
            let ts = match ty {
                crate::analysis::types::Ty::U8 => "uint8_t",
                crate::analysis::types::Ty::U16 => "uint16_t",
                crate::analysis::types::Ty::U32 => "uint32_t",
                crate::analysis::types::Ty::U64 | crate::analysis::types::Ty::Unknown => "uint64_t",
                crate::analysis::types::Ty::Usize => "uintptr_t",
            };
            out.push_str(&format!("    {} {} = 0;\n", ts, v));
        }
    }
    out.push('\n');

    for a in order {
        out.push_str(&format!("{}:\n", label_for(a)));
        let Some(b) = func.blocks.get(&a) else {
            out.push_str("    return;\n\n");
            continue;
        };

        for s in &b.stmts {
            match s {
                Stmt::Phi { .. } => {}
                Stmt::Assign { dst, expr } => {
                    if lang == "rust" {
                        out.push_str(&format!("    {} = {};\n", dst, render_expr_rust(expr)));
                    } else {
                        out.push_str(&format!("    {} = {};\n", dst, render_expr_c(expr)));
                    }
                }
                Stmt::Store { addr, value, size } => {
                    if lang == "rust" {
                        let ty = ty_for_size_rust(*size);
                        out.push_str(&format!(
                            "    unsafe {{ *(({} as usize) as *mut {}) = {}; }}\n",
                            render_expr_rust(addr),
                            ty,
                            render_expr_rust(value)
                        ));
                    } else {
                        let ty = ty_for_size_c(*size);
                        out.push_str(&format!(
                            "    *({}*)({}) = {};\n",
                            ty,
                            render_expr_c(addr),
                            render_expr_c(value)
                        ));
                    }
                }
                Stmt::Call { target, args } => {
                    if lang == "rust" {
                        let t = render_expr_rust(target);
                        let mut call = format!(
                            "    unsafe {{ (core::mem::transmute::<usize, extern \"C\" fn()>(({}) as usize))() }};",
                            t
                        );
                        if let Expr::Imm(v) = target {
                            call = format!("    unsafe {{ sub_{:x}() }};", *v as u64);
                        }
                        let _ = args;
                        out.push_str(&call);
                        out.push('\n');
                    } else {
                        let t = render_expr_c(target);
                        let mut call = format!("    ((void(*)())({}))();", t);
                        if let Expr::Imm(v) = target {
                            call = format!("    sub_{:x}();", *v as u64);
                        }
                        let _ = args;
                        out.push_str(&call);
                        out.push('\n');
                    }
                }
            }
        }

        match &b.term {
            Term::Jump(t) => {
                let copies = edge_copies(func, a, *t);
                for (dst, src) in copies {
                    out.push_str(&render_copy(lang, &dst, &src));
                }
                out.push_str(&format!("    goto {};\n\n", label_for(*t)));
            }
            Term::Branch { cond, then_t, else_t } => {
                let c = if lang == "rust" { render_cond_rust(cond) } else { render_cond_c(cond) };
                out.push_str(&format!("    if {} {{\n", c));
                let then_copies = edge_copies(func, a, *then_t);
                for (dst, src) in then_copies {
                    out.push_str(&render_copy(lang, &dst, &src));
                }
                out.push_str(&format!("        goto {};\n", label_for(*then_t)));
                out.push_str("    } else {\n");
                let else_copies = edge_copies(func, a, *else_t);
                for (dst, src) in else_copies {
                    out.push_str(&render_copy(lang, &dst, &src));
                }
                out.push_str(&format!("        goto {};\n", label_for(*else_t)));
                out.push_str("    }\n\n");
            }
            Term::Return => {
                out.push_str("    return;\n\n");
            }
            Term::Unreachable => {
                out.push_str("    return;\n\n");
            }
        }
    }

    out.push_str("}\n");
    out
}
