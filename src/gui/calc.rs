use std::collections::HashMap;

#[derive(Debug, Clone)]
enum Tok {
    Num(f64),
    Ident(String),
    Op(char),
    LParen,
    RParen,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut it = input.chars().peekable();
    while let Some(&ch) = it.peek() {
        if ch.is_whitespace() {
            let _ = it.next();
            continue;
        }
        if ch.is_ascii_digit() || ch == '.' {
            let mut s = String::new();
            while let Some(&c) = it.peek() {
                if c.is_ascii_digit() || c == '.' {
                    s.push(c);
                    let _ = it.next();
                } else {
                    break;
                }
            }
            let v: f64 = s.parse().map_err(|_| "invalid number".to_string())?;
            out.push(Tok::Num(v));
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut s = String::new();
            while let Some(&c) = it.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    s.push(c);
                    let _ = it.next();
                } else {
                    break;
                }
            }
            out.push(Tok::Ident(s));
            continue;
        }
        match ch {
            '+' | '-' | '*' | '/' | '^' => {
                out.push(Tok::Op(ch));
                let _ = it.next();
            }
            '(' => {
                out.push(Tok::LParen);
                let _ = it.next();
            }
            ')' => {
                out.push(Tok::RParen);
                let _ = it.next();
            }
            ',' => {
                out.push(Tok::Comma);
                let _ = it.next();
            }
            _ => return Err(format!("unexpected character: {}", ch)),
        }
    }
    Ok(out)
}

fn prec(op: char) -> (u8, bool) {
    match op {
        '^' => (4, true),
        '*' | '/' => (3, false),
        '+' | '-' => (2, false),
        _ => (0, false),
    }
}

#[derive(Debug, Clone)]
enum Rpn {
    Num(f64),
    Var(String),
    Op(char),
    Neg,
    Call { name: String, argc: usize },
}

fn to_rpn(tokens: &[Tok]) -> Result<Vec<Rpn>, String> {
    let mut out: Vec<Rpn> = Vec::new();
    let mut ops: Vec<Tok> = Vec::new();
    let mut arg_stack: Vec<usize> = Vec::new();
    let mut prev_was_value = false;

    let mut i = 0usize;
    while i < tokens.len() {
        match &tokens[i] {
            Tok::Num(v) => {
                out.push(Rpn::Num(*v));
                prev_was_value = true;
            }
            Tok::Ident(name) => {
                let is_call = matches!(tokens.get(i + 1), Some(Tok::LParen));
                if is_call {
                    ops.push(Tok::Ident(name.clone()));
                    prev_was_value = false;
                } else {
                    out.push(Rpn::Var(name.clone()));
                    prev_was_value = true;
                }
            }
            Tok::LParen => {
                ops.push(Tok::LParen);
                if matches!(ops.get(ops.len().saturating_sub(2)), Some(Tok::Ident(_))) {
                    arg_stack.push(0);
                }
                prev_was_value = false;
            }
            Tok::Comma => {
                while let Some(top) = ops.last() {
                    if matches!(top, Tok::LParen) {
                        break;
                    }
                    let op = ops.pop().unwrap();
                    match op {
                        Tok::Op(c) => out.push(Rpn::Op(c)),
                        _ => return Err("invalid operator stack".to_string()),
                    }
                }
                if let Some(a) = arg_stack.last_mut() {
                    *a += 1;
                } else {
                    return Err("comma outside function call".to_string());
                }
                prev_was_value = false;
            }
            Tok::RParen => {
                while let Some(top) = ops.last() {
                    if matches!(top, Tok::LParen) {
                        break;
                    }
                    let op = ops.pop().unwrap();
                    match op {
                        Tok::Op(c) => out.push(Rpn::Op(c)),
                        _ => return Err("invalid operator stack".to_string()),
                    }
                }
                if !matches!(ops.last(), Some(Tok::LParen)) {
                    return Err("mismatched ')'".to_string());
                }
                let _ = ops.pop();
                if let Some(Tok::Ident(name)) = ops.last() {
                    let name = name.clone();
                    let _ = ops.pop();
                    let argc = if let Some(n) = arg_stack.pop() {
                        if prev_was_value { n + 1 } else { n }
                    } else {
                        0
                    };
                    out.push(Rpn::Call { name, argc });
                    prev_was_value = true;
                } else {
                    prev_was_value = true;
                }
            }
            Tok::Op(op) => {
                let op = *op;
                if op == '-' && !prev_was_value {
                    ops.push(Tok::Op('~'));
                    prev_was_value = false;
                    i += 1;
                    continue;
                }
                while let Some(top) = ops.last() {
                    let Tok::Op(t) = top else { break; };
                    if *t == '~' {
                        out.push(Rpn::Neg);
                        let _ = ops.pop();
                        continue;
                    }
                    let (p1, r1) = prec(op);
                    let (p2, _) = prec(*t);
                    if (r1 && p1 < p2) || (!r1 && p1 <= p2) {
                        out.push(Rpn::Op(*t));
                        let _ = ops.pop();
                    } else {
                        break;
                    }
                }
                ops.push(Tok::Op(op));
                prev_was_value = false;
            }
        }
        i += 1;
    }

    while let Some(op) = ops.pop() {
        match op {
            Tok::Op('~') => out.push(Rpn::Neg),
            Tok::Op(c) => out.push(Rpn::Op(c)),
            Tok::LParen | Tok::RParen => return Err("mismatched parentheses".to_string()),
            Tok::Ident(_) | Tok::Comma | Tok::Num(_) => return Err("invalid operator stack".to_string()),
        }
    }
    Ok(out)
}

fn call_fn(name: &str, args: &[f64]) -> Result<f64, String> {
    let n = name.to_lowercase();
    let res = match (n.as_str(), args.len()) {
        ("sin", 1) => args[0].sin(),
        ("cos", 1) => args[0].cos(),
        ("tan", 1) => args[0].tan(),
        ("asin", 1) => args[0].asin(),
        ("acos", 1) => args[0].acos(),
        ("atan", 1) => args[0].atan(),
        ("sqrt", 1) => args[0].sqrt(),
        ("abs", 1) => args[0].abs(),
        ("ln", 1) => args[0].ln(),
        ("log", 1) => args[0].log10(),
        ("exp", 1) => args[0].exp(),
        ("floor", 1) => args[0].floor(),
        ("ceil", 1) => args[0].ceil(),
        ("round", 1) => args[0].round(),
        ("pow", 2) => args[0].powf(args[1]),
        ("min", 2) => args[0].min(args[1]),
        ("max", 2) => args[0].max(args[1]),
        _ => return Err(format!("unknown function or arity: {}({})", name, args.len())),
    };
    Ok(res)
}

pub fn eval_expr(input: &str, vars: &HashMap<String, f64>) -> Result<f64, String> {
    let toks = tokenize(input)?;
    let rpn = to_rpn(&toks)?;
    let mut st: Vec<f64> = Vec::new();
    for it in rpn {
        match it {
            Rpn::Num(v) => st.push(v),
            Rpn::Var(v) => {
                let key = v.to_lowercase();
                if let Some(x) = vars.get(&key) {
                    st.push(*x);
                } else if key == "pi" {
                    st.push(std::f64::consts::PI);
                } else if key == "e" {
                    st.push(std::f64::consts::E);
                } else {
                    return Err(format!("unknown variable: {}", v));
                }
            }
            Rpn::Neg => {
                let a = st.pop().ok_or_else(|| "stack underflow".to_string())?;
                st.push(-a);
            }
            Rpn::Op(op) => {
                let b = st.pop().ok_or_else(|| "stack underflow".to_string())?;
                let a = st.pop().ok_or_else(|| "stack underflow".to_string())?;
                let v = match op {
                    '+' => a + b,
                    '-' => a - b,
                    '*' => a * b,
                    '/' => a / b,
                    '^' => a.powf(b),
                    _ => return Err("unknown operator".to_string()),
                };
                st.push(v);
            }
            Rpn::Call { name, argc } => {
                if argc == 0 {
                    return Err(format!("{}() requires arguments", name));
                }
                if st.len() < argc {
                    return Err("stack underflow".to_string());
                }
                let start = st.len() - argc;
                let args = st[start..].to_vec();
                st.truncate(start);
                let v = call_fn(&name, &args)?;
                st.push(v);
            }
        }
    }
    if st.len() != 1 {
        return Err("invalid expression".to_string());
    }
    Ok(st[0])
}
