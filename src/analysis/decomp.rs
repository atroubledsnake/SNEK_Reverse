use super::Instruction;
use std::collections::HashMap;

pub struct BasicBlock {
    pub start_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

pub struct ControlFlowGraph {
    pub entry_block: u64,
    pub blocks: HashMap<u64, BasicBlock>,
}

impl ControlFlowGraph {
    pub fn new(entry: u64) -> Self {
        ControlFlowGraph {
            entry_block: entry,
            blocks: HashMap::new(),
        }
    }
}

#[allow(non_camel_case_types)]
pub enum PCodeOp {
    COPY(Varnode, Varnode),
    LOAD(Varnode, Varnode),
    STORE(Varnode, Varnode),

    BRANCH(u64),
    CBRANCH(u64, Varnode),
    BRANCHIND(Varnode),
    CALL(u64),
    CALLIND(Varnode),
    RETURN(Option<Varnode>),

    // Arithmetic
    INT_ADD(Varnode, Varnode, Varnode),
    INT_SUB(Varnode, Varnode, Varnode),
    INT_MULT(Varnode, Varnode, Varnode),
    INT_DIV(Varnode, Varnode, Varnode),

    // Logical
    INT_AND(Varnode, Varnode, Varnode),
    INT_OR(Varnode, Varnode, Varnode),
    INT_XOR(Varnode, Varnode, Varnode),
    INT_NEGATE(Varnode, Varnode),

    // Comparison
    INT_EQUAL(Varnode, Varnode, Varnode),
    INT_NOTEQUAL(Varnode, Varnode, Varnode),
    INT_LESS(Varnode, Varnode, Varnode),

    // Not yet handled
    UNIMPLEMENTED,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Varnode {
    Register(String, u32), // name, size in bytes
    Constant(u64, u32),    // value, size in bytes
    Memory(u64, u32),      // address, size in bytes
    Unique(u64, u32),      // temp variable
}

pub trait Decompiler {
    fn build_cfg(&self, instrs: &[Instruction]) -> ControlFlowGraph;
    fn lift_pcode(&self, block: &BasicBlock) -> Vec<PCodeOp>;
    fn optimize_pcode(&self, ir: &mut Vec<PCodeOp>);
    fn generate_pseudocode(&self, cfg: &ControlFlowGraph, lang: &str) -> String;
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum AstNode {
    Statement(String),
    If(String, Vec<AstNode>, Vec<AstNode>),
    While(String, Vec<AstNode>),
}

impl AstNode {
    #[allow(dead_code)]
    fn render(&self, indent: usize, lang: &str) -> String {
        let ind = "    ".repeat(indent);
        match self {
            AstNode::Statement(stmt) => format!("{}{}\n", ind, stmt),
            AstNode::If(cond, then_body, else_body) => {
                let mut out = format!("{}if ({}) {{\n", ind, cond);
                for node in then_body {
                    out.push_str(&node.render(indent + 1, lang));
                }
                if !else_body.is_empty() {
                    out.push_str(&format!("{}}} else {{\n", ind));
                    for node in else_body {
                        out.push_str(&node.render(indent + 1, lang));
                    }
                }
                out.push_str(&format!("{}}}\n", ind));
                out
            }
            AstNode::While(cond, body) => {
                let mut out = format!("{}while ({}) {{\n", ind, cond);
                for node in body {
                    out.push_str(&node.render(indent + 1, lang));
                }
                out.push_str(&format!("{}}}\n", ind));
                out
            }
        }
    }
}

pub struct SnekDecompiler;

#[allow(dead_code)]
impl SnekDecompiler {
    pub fn new() -> Self {
        SnekDecompiler
    }

    fn recognize_memmove(&self, cfg: &ControlFlowGraph, lang: &str) -> Option<String> {
        let mut saw_cld = false;
        let mut saw_rep_movs = false;

        for block in cfg.blocks.values() {
            for inst in &block.instructions {
                if inst.mnemonic == "cld" {
                    saw_cld = true;
                }
                if inst.mnemonic.starts_with("rep movs") {
                    saw_rep_movs = true;
                }
            }
        }

        if saw_rep_movs && saw_cld {
            return Some(if lang == "rust" {
                r#"pub unsafe fn memmove_like(dest: *mut u8, src: *const u8, mut count: usize) -> *mut u8 {
    if dest <= src as *mut u8 || dest >= src.add(count) as *mut u8 {
        let mut d = dest;
        let mut s = src;
        while count > 0 {
            *d = *s;
            d = d.add(1);
            s = s.add(1);
            count -= 1;
        }
    } else {
        let mut d = dest.add(count - 1);
        let mut s = src.add(count - 1);
        while count > 0 {
            *d = *s;
            d = d.sub(1);
            s = s.sub(1);
            count -= 1;
        }
    }
    dest
}"#
            } else {
                r#"void* memmove_like(void* dest, const void* src, size_t count) {
    if (dest <= src || (char*)dest >= (char*)src + count) {
        char* d = (char*)dest;
        const char* s = (const char*)src;
        while (count--) *d++ = *s++;
    } else {
        char* d = (char*)dest + count - 1;
        const char* s = (const char*)src + count - 1;
        while (count--) *d-- = *s--;
    }
    return dest;
}"#
            }.to_string());
        }
        None
    }

    fn structurize_cfg(&self, cfg: &ControlFlowGraph, lang: &str) -> Vec<AstNode> {
        let mut ast = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut declared = std::collections::HashSet::new();
        let mut curr = cfg.entry_block;

        while let Some(block) = cfg.blocks.get(&curr) {
            if visited.contains(&curr) {
                ast.push(AstNode::Statement(format!("// loop back-edge to {:#010x}", curr)));
                break;
            }
            visited.insert(curr);

            let mut stmts = Vec::new();
            let last_idx = block.instructions.len().saturating_sub(1);

            for (i, inst) in block.instructions.iter().enumerate() {
                if i == last_idx && inst.is_jump {
                    continue;
                }
                if let Some(stmt) = self.translate_inst(inst, lang, &mut declared) {
                    stmts.push(AstNode::Statement(stmt));
                }
            }
            ast.extend(stmts);

            if let Some(last) = block.instructions.last() {
                if last.is_jump && last.mnemonic != "jmp" {
                    let target = last.target_address.unwrap_or(0);
                    let fallthrough = cfg
                        .blocks
                        .keys()
                        .copied()
                        .filter(|&k| k > curr)
                        .min()
                        .unwrap_or(0);

                    let cond = self.cond_from_block(block, last, lang);
                    if target < curr {
                        let body = self.build_linear_ast(cfg, target, fallthrough, &mut visited, lang, &mut declared);
                        ast.push(AstNode::While(cond, body));
                        curr = fallthrough;
                    } else {
                        let then = self.build_linear_ast(cfg, fallthrough, target, &mut visited, lang, &mut declared);
                        ast.push(AstNode::If(self.invert_cond(&cond), then, vec![]));
                        curr = target;
                    }
                } else if last.mnemonic == "jmp" {
                    let target = last.target_address.unwrap_or(0);
                    if target < curr {
                        ast.push(AstNode::Statement("continue;".to_string()));
                        break;
                    } else {
                        curr = target;
                    }
                } else if last.mnemonic == "ret" {
                    ast.push(AstNode::Statement("return;".to_string()));
                    break;
                } else {
                    curr = cfg.blocks.keys().copied().filter(|&k| k > curr).min().unwrap_or(0);
                }
            } else {
                break;
            }
        }
        ast
    }

    fn build_linear_ast(
        &self,
        cfg: &ControlFlowGraph,
        start: u64,
        end: u64,
        visited: &mut std::collections::HashSet<u64>,
        lang: &str,
        declared: &mut std::collections::HashSet<String>,
    ) -> Vec<AstNode> {
        let mut ast = Vec::new();
        let mut curr = start;

        while curr != 0 && curr < end {
            if visited.contains(&curr) {
                break;
            }
            visited.insert(curr);

            if let Some(block) = cfg.blocks.get(&curr) {
                let last_idx = block.instructions.len().saturating_sub(1);
                for (i, inst) in block.instructions.iter().enumerate() {
                    if i == last_idx && inst.is_jump {
                        continue;
                    }
                    if let Some(stmt) = self.translate_inst(inst, lang, declared) {
                        ast.push(AstNode::Statement(stmt));
                    }
                }

                if let Some(last) = block.instructions.last() {
                    if last.is_jump && last.mnemonic != "jmp" {
                        let target = last.target_address.unwrap_or(0);
                        let fallthrough = cfg.blocks.keys().copied().filter(|&k| k > curr).min().unwrap_or(0);
                        let cond = self.cond_from_block(block, last, lang);
                        if target < curr {
                            let body = self.build_linear_ast(cfg, target, fallthrough, visited, lang, declared);
                            ast.push(AstNode::While(cond, body));
                            curr = fallthrough;
                        } else {
                            let then = self.build_linear_ast(cfg, fallthrough, target, visited, lang, declared);
                            ast.push(AstNode::If(self.invert_cond(&cond), then, vec![]));
                            curr = target;
                        }
                    } else if last.mnemonic == "jmp" {
                        let target = last.target_address.unwrap_or(0);
                        if target < curr {
                            ast.push(AstNode::Statement("continue;".to_string()));
                            break;
                        } else {
                            curr = target;
                        }
                    } else if last.mnemonic == "ret" {
                        ast.push(AstNode::Statement("return;".to_string()));
                        break;
                    } else {
                        curr = cfg.blocks.keys().copied().filter(|&k| k > curr).min().unwrap_or(0);
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        ast
    }

    fn invert_cond(&self, cond: &str) -> String {
        let c = cond.trim();
        if c.starts_with('!') {
            c[1..].trim().to_string()
        } else if c.starts_with('(') && c.ends_with(')') {
            format!("!{}", c)
        } else {
            format!("!({})", c)
        }
    }

    fn cond_from_block(&self, block: &BasicBlock, jcc: &super::Instruction, lang: &str) -> String {
        let mut cmp = None;
        for inst in block.instructions.iter().rev() {
            if inst.address == jcc.address {
                continue;
            }
            if inst.mnemonic == "cmp" && inst.operands.len() == 2 {
                cmp = Some((self.clean_op(&inst.operands[0]), self.clean_op(&inst.operands[1]), false));
                break;
            }
            if inst.mnemonic == "test" && inst.operands.len() == 2 {
                cmp = Some((self.clean_op(&inst.operands[0]), self.clean_op(&inst.operands[1]), true));
                break;
            }
        }
        let Some((lhs, rhs, is_test)) = cmp else {
            return "cond".to_string();
        };
        self.cond_from_cmp(jcc.mnemonic.as_str(), &lhs, &rhs, is_test, lang)
    }

    fn cond_from_cmp(&self, jcc: &str, lhs: &str, rhs: &str, is_test: bool, lang: &str) -> String {
        let ucast = |x: &str| -> String {
            if lang == "rust" {
                format!("({} as u64)", x)
            } else {
                format!("((unsigned){})", x)
            }
        };
        let scast = |x: &str| -> String {
            if lang == "rust" {
                format!("({} as i64)", x)
            } else {
                format!("((int64_t){})", x)
            }
        };
        match jcc {
            "je" | "jz" => {
                if is_test {
                    format!("(({} & {}) == 0)", lhs, rhs)
                } else {
                    format!("({} == {})", lhs, rhs)
                }
            }
            "jne" | "jnz" => {
                if is_test {
                    format!("(({} & {}) != 0)", lhs, rhs)
                } else {
                    format!("({} != {})", lhs, rhs)
                }
            }
            "jb" | "jc" | "jnae" => format!("({} < {})", ucast(lhs), ucast(rhs)),
            "jbe" | "jna" => format!("({} <= {})", ucast(lhs), ucast(rhs)),
            "ja" | "jnbe" => format!("({} > {})", ucast(lhs), ucast(rhs)),
            "jae" | "jnb" | "jnc" => format!("({} >= {})", ucast(lhs), ucast(rhs)),
            "jl" | "jnge" => format!("({} < {})", scast(lhs), scast(rhs)),
            "jle" | "jng" => format!("({} <= {})", scast(lhs), scast(rhs)),
            "jg" | "jnle" => format!("({} > {})", scast(lhs), scast(rhs)),
            "jge" | "jnl" => format!("({} >= {})", scast(lhs), scast(rhs)),
            _ => "cond".to_string(),
        }
    }

    fn clean_op(&self, op: &str) -> String {
        let mut s = op.trim().to_string();
        for p in &[
            "byte ptr ", "word ptr ", "dword ptr ", "qword ptr",
            "tbyte ptr ", "xmmword ptr ", "ymmword ptr",
        ] {
            if s.to_lowercase().starts_with(p) {
                s = s[p.len()..].trim().to_string();
                break;
            }
        }
        s.replace("PTR ", "")
    }

    fn mem_cast(&self, op: &str, lang: &str) -> &'static str {
        let low = op.to_lowercase();
        if low.contains("byte ptr") {
            if lang == "rust" { "u8" } else { "uint8_t" }
        } else if low.contains("word ptr") {
            if lang == "rust" { "u16" } else { "uint16_t" }
        } else if low.contains("dword ptr") {
            if lang == "rust" { "u32" } else { "uint32_t" }
        } else {
            if lang == "rust" { "u64" } else { "uint64_t" }
        }
    }

    fn is_reg(&self, op: &str) -> bool {
        matches!(
            op.trim().to_lowercase().as_str(),
            "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" |
            "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15" |
            "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" |
            "al" | "bl" | "cl" | "dl"
        )
    }

    fn assign_stmt(
        &self,
        dst: &str,
        expr: &str,
        lang: &str,
        declared: &mut std::collections::HashSet<String>,
    ) -> String {
        let v = dst.trim().to_string();
        if lang == "rust" {
            if declared.insert(v.clone()) {
                format!("let mut {}: u64 = {};", v, expr)
            } else {
                format!("{} = {};", v, expr)
            }
        } else {
            if declared.insert(v.clone()) {
                format!("uint64_t {} = {};", v, expr)
            } else {
                format!("{} = {};", v, expr)
            }
        }
    }

    fn render_mem_expr(&self, op: &str, inst: &super::Instruction, lang: &str, for_lea: bool) -> String {
        let addr = if let Some(a) = inst.ref_address {
            format!("{:#x}", a)
        } else {
            self.clean_op(op).trim_matches(['[', ']']).to_string()
        };
        if for_lea {
            return addr;
        }
        let ty = self.mem_cast(op, lang);
        if lang == "rust" {
            format!("unsafe {{ *(({} as usize) as *const {}) }}", addr, ty)
        } else {
            format!("*({}*)({})", ty, addr)
        }
    }

    fn translate_inst(
        &self,
        inst: &super::Instruction,
        lang: &str,
        declared: &mut std::collections::HashSet<String>,
    ) -> Option<String> {
        match inst.mnemonic.as_str() {
            "mov" | "lea" => {
                if inst.operands.len() != 2 {
                    return None;
                }
                let dst = self.clean_op(&inst.operands[0]);
                if !self.is_reg(&dst) {
                    return None;
                }
                let src_raw = &inst.operands[1];
                let expr = if src_raw.contains('[') {
                    self.render_mem_expr(src_raw, inst, lang, inst.mnemonic == "lea")
                } else {
                    self.clean_op(src_raw)
                };
                Some(self.assign_stmt(&dst, &expr, lang, declared))
            }
            "add" => {
                if inst.operands.len() != 2 {
                    return None;
                }
                let dst = self.clean_op(&inst.operands[0]);
                if !self.is_reg(&dst) {
                    return None;
                }
                declared.insert(dst.clone());
                let src = self.clean_op(&inst.operands[1]);
                Some(format!("{} += {};", dst, src))
            }
            "sub" => {
                if inst.operands.len() != 2 {
                    return None;
                }
                let dst = self.clean_op(&inst.operands[0]);
                if !self.is_reg(&dst) {
                    return None;
                }
                declared.insert(dst.clone());
                let src = self.clean_op(&inst.operands[1]);
                Some(format!("{} -= {};", dst, src))
            }
            "inc" => {
                if inst.operands.len() != 1 {
                    return None;
                }
                let dst = self.clean_op(&inst.operands[0]);
                if !self.is_reg(&dst) {
                    return None;
                }
                declared.insert(dst.clone());
                Some(format!("{} += 1;", dst))
            }
            _ => None,
        }
    }
}

impl Decompiler for SnekDecompiler {
    fn build_cfg(&self, instrs: &[Instruction]) -> ControlFlowGraph {
        if instrs.is_empty() {
            return ControlFlowGraph::new(0);
        }

        let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        leaders.insert(instrs[0].address);

        for i in 0..instrs.len() {
            let inst = &instrs[i];
            if inst.is_jump {
                if let Some(t) = inst.target_address {
                    leaders.insert(t);
                }
                if inst.mnemonic.to_lowercase() != "jmp" {
                    if let Some(n) = instrs.get(i + 1) {
                        leaders.insert(n.address);
                    }
                }
            } else if inst.mnemonic.to_lowercase() == "ret" {
                if let Some(n) = instrs.get(i + 1) {
                    leaders.insert(n.address);
                }
            }
        }

        let mut leader_list: Vec<u64> = leaders.into_iter().collect();
        leader_list.sort();

        let mut cfg = ControlFlowGraph::new(leader_list[0]);
        let mut leader_to_idx: HashMap<u64, usize> = HashMap::new();
        for (i, a) in leader_list.iter().enumerate() {
            leader_to_idx.insert(*a, i);
        }

        for li in 0..leader_list.len() {
            let start = leader_list[li];
            let end = leader_list.get(li + 1).copied().unwrap_or(u64::MAX);
            let mut block_instrs = Vec::new();
            for inst in instrs.iter() {
                if inst.address < start {
                    continue;
                }
                if inst.address >= end {
                    break;
                }
                block_instrs.push(inst.clone());
            }
            cfg.blocks.insert(
                start,
                BasicBlock {
                    start_address: start,
                    instructions: block_instrs,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                },
            );
        }

        let keys: Vec<u64> = cfg.blocks.keys().copied().collect();
        for &b in &keys {
            let mut succs = Vec::new();
            let Some(block) = cfg.blocks.get(&b) else { continue; };
            let last = block.instructions.last();
            let fallthrough = {
                let idx = leader_to_idx.get(&b).copied().unwrap_or(0);
                leader_list.get(idx + 1).copied()
            };

            if let Some(last) = last {
                let m = last.mnemonic.to_lowercase();
                if m == "ret" {
                } else if last.is_jump {
                    if let Some(t) = last.target_address {
                        succs.push(t);
                    }
                    if m != "jmp" {
                        if let Some(ft) = fallthrough {
                            succs.push(ft);
                        }
                    }
                } else {
                    if let Some(ft) = fallthrough {
                        succs.push(ft);
                    }
                }
            }

            succs.retain(|s| cfg.blocks.contains_key(s));
            succs.sort();
            succs.dedup();
            if let Some(bb) = cfg.blocks.get_mut(&b) {
                bb.successors = succs;
            }
        }

        let keys: Vec<u64> = cfg.blocks.keys().copied().collect();
        for &b in &keys {
            let succs = cfg.blocks.get(&b).map(|x| x.successors.clone()).unwrap_or_default();
            for s in succs {
                if let Some(sb) = cfg.blocks.get_mut(&s) {
                    sb.predecessors.push(b);
                }
            }
        }
        for b in cfg.blocks.values_mut() {
            b.predecessors.sort();
            b.predecessors.dedup();
        }

        cfg
    }

    fn lift_pcode(&self, _block: &BasicBlock) -> Vec<PCodeOp> {
        Vec::new()
    }

    fn optimize_pcode(&self, ir: &mut Vec<PCodeOp>) {
        let _ = ir;
    }

    fn generate_pseudocode(&self, cfg: &ControlFlowGraph, lang: &str) -> String {
        if let Some(memmove_code) = self.recognize_memmove(cfg, lang) {
            return memmove_code;
        }
        let ir = crate::analysis::ir::lift_cfg(cfg);
        let mut ssa = crate::analysis::ssa::to_ssa(&ir);
        ssa = crate::analysis::ssa::optimize(&ssa);
        crate::analysis::pseudocode::render_function(&ssa, lang)
    }
}
