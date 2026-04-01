use std::collections::{HashMap, HashSet};
use crate::analysis::ir::{Cond, Expr, IrFunction, Stmt, Term};

fn vars_in_expr(e: &Expr, out: &mut HashSet<String>) {
    match e {
        Expr::Var(v) => {
            out.insert(v.clone());
        }
        Expr::Imm(_) => {}
        Expr::Unknown(_) => {}
        Expr::BinOp { a, b, .. } => {
            vars_in_expr(a, out);
            vars_in_expr(b, out);
        }
        Expr::Load { addr, .. } => {
            vars_in_expr(addr, out);
        }
        Expr::Stack(_) => {}
    }
}

fn replace_vars_expr(e: &Expr, map: &HashMap<String, String>) -> Expr {
    match e {
        Expr::Var(v) => {
            if let Some(n) = map.get(v) {
                Expr::Var(n.clone())
            } else {
                Expr::Var(v.clone())
            }
        }
        Expr::Imm(v) => Expr::Imm(*v),
        Expr::Unknown(k) => Expr::Unknown(k.clone()),
        Expr::BinOp { op, a, b } => Expr::BinOp {
            op: op.clone(),
            a: Box::new(replace_vars_expr(a, map)),
            b: Box::new(replace_vars_expr(b, map)),
        },
        Expr::Load { addr, size } => Expr::Load {
            addr: Box::new(replace_vars_expr(addr, map)),
            size: *size,
        },
        Expr::Stack(offset) => Expr::Stack(*offset),
    }
}

fn replace_vars_cond(c: &Cond, map: &HashMap<String, String>) -> Cond {
    match c {
        Cond::Cmp { op, lhs, rhs } => Cond::Cmp {
            op: op.clone(),
            lhs: replace_vars_expr(lhs, map),
            rhs: replace_vars_expr(rhs, map),
        },
        Cond::NonZero(e) => Cond::NonZero(replace_vars_expr(e, map)),
    }
}

fn vars_defined_in_stmt(s: &Stmt) -> Option<String> {
    match s {
        Stmt::Assign { dst, .. } => Some(dst.clone()),
        Stmt::Phi { var, .. } => Some(var.clone()),
        _ => None,
    }
}

fn base_var(name: &str) -> String {
    name.to_lowercase()
}

pub fn optimize(func: &IrFunction) -> IrFunction {
    let mut f = func.clone();
    let mut changed = true;
    while changed {
        changed = false;
        changed |= simplify_phis(&mut f);
        changed |= copy_propagation(&mut f);
        changed |= constant_propagation(&mut f);
        changed |= crate::analysis::alias::forward_stores_to_loads(&mut f);
        changed |= dead_code_elimination(&mut f);
    }
    f
}

fn simplify_phis(f: &mut IrFunction) -> bool {
    let mut changed = false;
    for b in f.blocks.values_mut() {
        for s in b.stmts.iter_mut() {
            let Stmt::Phi { dst, sources, .. } = s else { continue; };
            if dst.is_empty() || sources.is_empty() {
                continue;
            }
            let first = sources[0].1.clone();
            if sources.iter().all(|(_, v)| *v == first) {
                *s = Stmt::Assign { dst: dst.clone(), expr: Expr::Var(first) };
                changed = true;
            }
        }
    }
    changed
}

fn copy_propagation(f: &mut IrFunction) -> bool {
    let mut map: HashMap<String, String> = HashMap::new();
    for b in f.blocks.values() {
        for s in &b.stmts {
            if let Stmt::Assign { dst, expr } = s {
                if let Expr::Var(src) = expr {
                    if !dst.is_empty() && dst != src {
                        map.insert(dst.clone(), src.clone());
                    }
                }
            }
        }
    }
    if map.is_empty() {
        return false;
    }

    fn resolve(v: &str, map: &HashMap<String, String>) -> String {
        let mut cur = v.to_string();
        let mut seen = HashSet::new();
        while let Some(n) = map.get(&cur) {
            if !seen.insert(cur.clone()) {
                break;
            }
            cur = n.clone();
        }
        cur
    }

    let mut changed = false;
    for b in f.blocks.values_mut() {
        for s in &mut b.stmts {
            match s {
                Stmt::Assign { expr, .. } => {
                    let mut used = HashSet::new();
                    vars_in_expr(expr, &mut used);
                    let mut rmap: HashMap<String, String> = HashMap::new();
                    for u in used {
                        let r = resolve(&u, &map);
                        if r != u {
                            rmap.insert(u, r);
                        }
                    }
                    if !rmap.is_empty() {
                        *expr = replace_vars_expr(expr, &rmap);
                        changed = true;
                    }
                }
                Stmt::Store { addr, value, .. } => {
                    let mut used = HashSet::new();
                    vars_in_expr(addr, &mut used);
                    vars_in_expr(value, &mut used);
                    let mut rmap: HashMap<String, String> = HashMap::new();
                    for u in used {
                        let r = resolve(&u, &map);
                        if r != u {
                            rmap.insert(u, r);
                        }
                    }
                    if !rmap.is_empty() {
                        *addr = replace_vars_expr(addr, &rmap);
                        *value = replace_vars_expr(value, &rmap);
                        changed = true;
                    }
                }
                Stmt::Call { target, args } => {
                    let mut used = HashSet::new();
                    vars_in_expr(target, &mut used);
                    for a in args.iter() {
                        vars_in_expr(a, &mut used);
                    }
                    let mut rmap: HashMap<String, String> = HashMap::new();
                    for u in used {
                        let r = resolve(&u, &map);
                        if r != u {
                            rmap.insert(u, r);
                        }
                    }
                    if !rmap.is_empty() {
                        *target = replace_vars_expr(target, &rmap);
                        for a in args.iter_mut() {
                            *a = replace_vars_expr(a, &rmap);
                        }
                        changed = true;
                    }
                }
                Stmt::Phi { sources, .. } => {
                    for (_, v) in sources.iter_mut() {
                        let r = resolve(v, &map);
                        if r != *v {
                            *v = r;
                            changed = true;
                        }
                    }
                }
            }
        }
        match &mut b.term {
            Term::Branch { cond, .. } => {
                let mut used = HashSet::new();
                match cond {
                    Cond::Cmp { lhs, rhs, .. } => {
                        vars_in_expr(lhs, &mut used);
                        vars_in_expr(rhs, &mut used);
                    }
                    Cond::NonZero(e) => vars_in_expr(e, &mut used),
                }
                let mut rmap: HashMap<String, String> = HashMap::new();
                for u in used {
                    let r = resolve(&u, &map);
                    if r != u {
                        rmap.insert(u, r);
                    }
                }
                if !rmap.is_empty() {
                    *cond = replace_vars_cond(cond, &rmap);
                    changed = true;
                }
            }
            _ => {}
        }
    }

    changed
}

fn constant_propagation(f: &mut IrFunction) -> bool {
    let mut constants: HashMap<String, i64> = HashMap::new();
    let mut changed = false;

    for b in f.blocks.values() {
        for s in &b.stmts {
            if let Stmt::Assign { dst, expr } = s {
                if let Expr::Imm(v) = expr {
                    constants.insert(dst.clone(), *v);
                }
            }
        }
    }

    fn fold_expr(e: &mut Expr, constants: &HashMap<String, i64>) -> bool {
        let mut ch = false;
        match e {
            Expr::Var(v) => {
                if let Some(&val) = constants.get(v) {
                    *e = Expr::Imm(val);
                    ch = true;
                }
            }
            Expr::BinOp { op, a, b } => {
                ch |= fold_expr(a, constants);
                ch |= fold_expr(b, constants);
                if let (Expr::Imm(va), Expr::Imm(vb)) = (&**a, &**b) {
                    let res = match op {
                        crate::analysis::ir::BinOp::Add => va.wrapping_add(*vb),
                        crate::analysis::ir::BinOp::Sub => va.wrapping_sub(*vb),
                        crate::analysis::ir::BinOp::Xor => va ^ vb,
                        crate::analysis::ir::BinOp::And => va & vb,
                        crate::analysis::ir::BinOp::Or => va | vb,
                        crate::analysis::ir::BinOp::Shl => va.wrapping_shl(*vb as u32),
                        crate::analysis::ir::BinOp::Shr => va.wrapping_shr(*vb as u32),
                    };
                    *e = Expr::Imm(res);
                    ch = true;
                }
            }
            Expr::Load { addr, .. } => {
                ch |= fold_expr(addr, constants);
            }
            _ => {}
        }
        ch
    }

    for b in f.blocks.values_mut() {
        for s in &mut b.stmts {
            match s {
                Stmt::Assign { expr, .. } => changed |= fold_expr(expr, &constants),
                Stmt::Store { addr, value, .. } => {
                    changed |= fold_expr(addr, &constants);
                    changed |= fold_expr(value, &constants);
                }
                Stmt::Call { target, args } => {
                    changed |= fold_expr(target, &constants);
                    for a in args {
                        changed |= fold_expr(a, &constants);
                    }
                }
                _ => {}
            }
        }
        match &mut b.term {
            Term::Branch { cond, .. } => {
                match cond {
                    Cond::Cmp { lhs, rhs, .. } => {
                        changed |= fold_expr(lhs, &constants);
                        changed |= fold_expr(rhs, &constants);
                    }
                    Cond::NonZero(e) => {
                        changed |= fold_expr(e, &constants);
                    }
                }
            }
            _ => {}
        }
    }
    changed
}

fn dead_code_elimination(f: &mut IrFunction) -> bool {
    let mut used = HashSet::new();
    for b in f.blocks.values() {
        for s in &b.stmts {
            match s {
                Stmt::Assign { expr, .. } => vars_in_expr(expr, &mut used),
                Stmt::Store { addr, value, .. } => {
                    vars_in_expr(addr, &mut used);
                    vars_in_expr(value, &mut used);
                }
                Stmt::Call { target, args } => {
                    vars_in_expr(target, &mut used);
                    for a in args {
                        vars_in_expr(a, &mut used);
                    }
                }
                Stmt::Phi { sources, .. } => {
                    for (_, v) in sources {
                        used.insert(v.clone());
                    }
                }
            }
        }
        match &b.term {
            Term::Branch { cond, .. } => {
                match cond {
                    Cond::Cmp { lhs, rhs, .. } => {
                        vars_in_expr(lhs, &mut used);
                        vars_in_expr(rhs, &mut used);
                    }
                    Cond::NonZero(e) => {
                        vars_in_expr(e, &mut used);
                    }
                }
            }
            _ => {}
        }
    }

    let mut changed = false;
    for b in f.blocks.values_mut() {
        let orig_len = b.stmts.len();
        b.stmts.retain(|s| {
            match s {
                Stmt::Assign { dst, .. } | Stmt::Phi { dst, .. } => {
                    dst.starts_with("rax") || dst.starts_with("eax") || used.contains(dst)
                }
                _ => true
            }
        });
        if b.stmts.len() != orig_len {
            changed = true;
        }
    }
    changed
}

pub fn to_ssa(func: &IrFunction) -> IrFunction {
    let mut f = func.clone();
    let blocks: Vec<u64> = {
        let mut v: Vec<u64> = f.blocks.keys().copied().collect();
        v.sort();
        v
    };

    let reachable = compute_reachable(&f);
    let (_dom, idom) = compute_dominators(&f, &blocks, &reachable);
    let dom_tree = build_dom_tree(&idom);
    let df = compute_dominance_frontier(&f, &blocks, &idom, &dom_tree);

    let mut vars: HashSet<String> = HashSet::new();
    let mut defsites: HashMap<String, HashSet<u64>> = HashMap::new();
    for &b in &blocks {
        if !reachable.contains(&b) {
            continue;
        }
        let blk = &f.blocks[&b];
        for s in &blk.stmts {
            if let Some(v) = vars_defined_in_stmt(s) {
                let bv = base_var(&v);
                vars.insert(bv.clone());
                defsites.entry(bv).or_default().insert(b);
            }
        }
    }

    for v in vars.iter() {
        let mut has_phi: HashSet<u64> = HashSet::new();
        let mut work: Vec<u64> = defsites.get(v).map(|s| s.iter().copied().collect()).unwrap_or_default();
        while let Some(n) = work.pop() {
            let frontier = df.get(&n).cloned().unwrap_or_default();
            for y in frontier {
                if !has_phi.insert(y) {
                    continue;
                }
                if let Some(b) = f.blocks.get_mut(&y) {
                    let mut existing = false;
                    for s in &b.stmts {
                        if let Stmt::Phi { var, .. } = s {
                            if var == v {
                                existing = true;
                                break;
                            }
                        }
                    }
                    if !existing {
                        b.stmts.insert(0, Stmt::Phi { var: v.clone(), dst: String::new(), sources: vec![] });
                    }
                }
                if defsites.get(v).map(|s| s.contains(&y)).unwrap_or(false) == false {
                    work.push(y);
                }
            }
        }
    }

    let mut counters: HashMap<String, u32> = HashMap::new();
    let mut stacks: HashMap<String, Vec<u32>> = HashMap::new();
    for v in vars.iter() {
        counters.insert(v.clone(), 0);
        stacks.insert(v.clone(), vec![0]);
    }

    rename_block(
        f.entry,
        &mut f,
        &dom_tree,
        &mut counters,
        &mut stacks,
        &reachable,
    );

    f
}

fn compute_reachable(f: &IrFunction) -> HashSet<u64> {
    let mut q = vec![f.entry];
    let mut seen = HashSet::new();
    while let Some(b) = q.pop() {
        if !seen.insert(b) {
            continue;
        }
        let Some(blk) = f.blocks.get(&b) else { continue; };
        for &s in &blk.succs {
            q.push(s);
        }
    }
    seen
}

fn compute_dominators(
    f: &IrFunction,
    blocks: &[u64],
    reachable: &HashSet<u64>,
) -> (HashMap<u64, HashSet<u64>>, HashMap<u64, Option<u64>>) {
    let all: HashSet<u64> = blocks.iter().copied().filter(|b| reachable.contains(b)).collect();
    let mut dom: HashMap<u64, HashSet<u64>> = HashMap::new();
    for &b in blocks {
        if !reachable.contains(&b) {
            continue;
        }
        if b == f.entry {
            dom.insert(b, [b].into_iter().collect());
        } else {
            dom.insert(b, all.clone());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for &b in blocks {
            if !reachable.contains(&b) || b == f.entry {
                continue;
            }
            let preds = f.blocks.get(&b).map(|x| x.preds.clone()).unwrap_or_default();
            let mut new: HashSet<u64> = all.clone();
            if preds.is_empty() {
                new.clear();
            } else {
                for p in preds {
                    if !reachable.contains(&p) {
                        continue;
                    }
                    if let Some(pd) = dom.get(&p) {
                        new = new.intersection(pd).copied().collect();
                    }
                }
            }
            new.insert(b);
            if new != dom[&b] {
                dom.insert(b, new);
                changed = true;
            }
        }
    }

    let mut idom: HashMap<u64, Option<u64>> = HashMap::new();
    idom.insert(f.entry, None);
    for &b in blocks {
        if !reachable.contains(&b) || b == f.entry {
            continue;
        }
        let mut candidates: Vec<u64> = dom[&b].iter().copied().filter(|x| *x != b).collect();
        candidates.sort();
        let mut chosen: Option<u64> = None;
        for c in candidates.iter().copied() {
            let mut ok = true;
            for o in candidates.iter().copied() {
                if o == c {
                    continue;
                }
                if dom[&o].contains(&c) {
                    ok = false;
                    break;
                }
            }
            if ok {
                chosen = Some(c);
                break;
            }
        }
        idom.insert(b, chosen);
    }
    (dom, idom)
}

fn build_dom_tree(idom: &HashMap<u64, Option<u64>>) -> HashMap<u64, Vec<u64>> {
    let mut tree: HashMap<u64, Vec<u64>> = HashMap::new();
    for (&b, &p) in idom {
        if let Some(p) = p {
            tree.entry(p).or_default().push(b);
        }
    }
    for v in tree.values_mut() {
        v.sort();
    }
    tree
}

fn compute_dominance_frontier(
    f: &IrFunction,
    blocks: &[u64],
    idom: &HashMap<u64, Option<u64>>,
    _dom_tree: &HashMap<u64, Vec<u64>>,
) -> HashMap<u64, HashSet<u64>> {
    let mut df: HashMap<u64, HashSet<u64>> = HashMap::new();
    for &b in blocks {
        df.insert(b, HashSet::new());
    }

    for &b in blocks {
        if let Some(blk) = f.blocks.get(&b) {
            let preds = &blk.preds;
            if preds.len() >= 2 {
                for &p in preds {
                    let mut runner = p;
                    let b_idom = idom.get(&b).copied().flatten();
                    while Some(runner) != b_idom {
                        df.entry(runner).or_default().insert(b);
                        if let Some(Some(next_runner)) = idom.get(&runner) {
                            runner = *next_runner;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    df
}

fn cur_name(var: &str, stacks: &HashMap<String, Vec<u32>>) -> String {
    let v = base_var(var);
    let top = stacks.get(&v).and_then(|s| s.last()).copied().unwrap_or(0);
    format!("{}_{}", v, top)
}

fn new_name(var: &str, counters: &mut HashMap<String, u32>, stacks: &mut HashMap<String, Vec<u32>>) -> String {
    let v = base_var(var);
    let n = counters.get(&v).copied().unwrap_or(0) + 1;
    counters.insert(v.clone(), n);
    stacks.entry(v.clone()).or_default().push(n);
    format!("{}_{}", v, n)
}

fn rename_block(
    b: u64,
    f: &mut IrFunction,
    dom_tree: &HashMap<u64, Vec<u64>>,
    counters: &mut HashMap<String, u32>,
    stacks: &mut HashMap<String, Vec<u32>>,
    reachable: &HashSet<u64>,
) {
    if !reachable.contains(&b) {
        return;
    }
    let Some(block) = f.blocks.get_mut(&b) else { return; };

    let mut pushed: Vec<String> = Vec::new();

    for s in block.stmts.iter_mut() {
        if let Stmt::Phi { var, dst, sources } = s {
            let n = new_name(var, counters, stacks);
            *dst = n;
            sources.clear();
            pushed.push(base_var(var));
        }
    }

    for s in block.stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, expr } => {
                let mut map = HashMap::new();
                let mut used = HashSet::new();
                vars_in_expr(expr, &mut used);
                for u in used {
                    map.insert(u.clone(), cur_name(&u, stacks));
                }
                *expr = replace_vars_expr(expr, &map);
                let n = new_name(dst, counters, stacks);
                pushed.push(base_var(dst));
                *dst = n;
            }
            Stmt::Store { addr, value, .. } => {
                let mut used = HashSet::new();
                vars_in_expr(addr, &mut used);
                vars_in_expr(value, &mut used);
                let mut map = HashMap::new();
                for u in used {
                    map.insert(u.clone(), cur_name(&u, stacks));
                }
                *addr = replace_vars_expr(addr, &map);
                *value = replace_vars_expr(value, &map);
            }
            Stmt::Call { target, args } => {
                let mut used = HashSet::new();
                vars_in_expr(target, &mut used);
                for a in args.iter() {
                    vars_in_expr(a, &mut used);
                }
                let mut map = HashMap::new();
                for u in used {
                    map.insert(u.clone(), cur_name(&u, stacks));
                }
                *target = replace_vars_expr(target, &map);
                for a in args.iter_mut() {
                    *a = replace_vars_expr(a, &map);
                }
            }
            Stmt::Phi { .. } => {}
        }
    }

    match &mut block.term {
        Term::Branch { cond, .. } => {
            let mut used = HashSet::new();
            match cond {
                Cond::Cmp { lhs, rhs, .. } => {
                    vars_in_expr(lhs, &mut used);
                    vars_in_expr(rhs, &mut used);
                }
                Cond::NonZero(e) => vars_in_expr(e, &mut used),
            }
            let mut map = HashMap::new();
            for u in used {
                map.insert(u.clone(), cur_name(&u, stacks));
            }
            *cond = replace_vars_cond(cond, &map);
        }
        _ => {}
    }

    let succs = block.succs.clone();
    for s in succs {
        if let Some(sb) = f.blocks.get_mut(&s) {
            for st in sb.stmts.iter_mut() {
                if let Stmt::Phi { var, sources, .. } = st {
                    let v = base_var(var);
                    let name = cur_name(&v, stacks);
                    sources.push((b, name));
                }
            }
        }
    }

    let children = dom_tree.get(&b).cloned().unwrap_or_default();
    for c in children {
        rename_block(c, f, dom_tree, counters, stacks, reachable);
    }

    for v in pushed {
        if let Some(st) = stacks.get_mut(&v) {
            st.pop();
            if st.is_empty() {
                st.push(0);
            }
        }
    }
}
