use std::collections::{HashMap, HashSet, VecDeque};

use crate::analysis::ir::IrFunction;

#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub header: u64,
    pub tail: u64,
    pub blocks: HashSet<u64>,
}

fn compute_reachable(f: &IrFunction) -> HashSet<u64> {
    let mut q = VecDeque::new();
    let mut seen = HashSet::new();
    q.push_back(f.entry);
    while let Some(b) = q.pop_front() {
        if !seen.insert(b) {
            continue;
        }
        let Some(blk) = f.blocks.get(&b) else { continue; };
        for &s in &blk.succs {
            q.push_back(s);
        }
    }
    seen
}

fn compute_dominators(
    f: &IrFunction,
    blocks: &[u64],
    reachable: &HashSet<u64>,
) -> HashMap<u64, HashSet<u64>> {
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
    dom
}

pub fn find_loops(func: &IrFunction) -> Vec<LoopInfo> {
    let mut blocks: Vec<u64> = func.blocks.keys().copied().collect();
    blocks.sort();
    let reachable = compute_reachable(func);
    let dom = compute_dominators(func, &blocks, &reachable);

    let mut loops = Vec::new();
    for &tail in &blocks {
        if !reachable.contains(&tail) {
            continue;
        }
        let Some(tblk) = func.blocks.get(&tail) else { continue; };
        for &head in &tblk.succs {
            if !reachable.contains(&head) {
                continue;
            }
            if !dom.get(&tail).map(|d| d.contains(&head)).unwrap_or(false) {
                continue;
            }

            let mut set: HashSet<u64> = HashSet::new();
            set.insert(head);
            set.insert(tail);
            let mut work = vec![tail];
            while let Some(n) = work.pop() {
                let preds = func.blocks.get(&n).map(|b| b.preds.clone()).unwrap_or_default();
                for p in preds {
                    if !set.insert(p) {
                        continue;
                    }
                    if p != head {
                        work.push(p);
                    }
                }
            }

            loops.push(LoopInfo { header: head, tail, blocks: set });
        }
    }

    loops.sort_by(|a, b| (a.header, a.tail).cmp(&(b.header, b.tail)));
    loops
}

pub fn render_loops(func: &IrFunction) -> Vec<String> {
    let loops = find_loops(func);
    if loops.is_empty() {
        return vec!["(no loops detected)".to_string()];
    }
    let mut out = Vec::new();
    out.push(format!("loops: {}", loops.len()));
    for l in loops {
        let mut blocks: Vec<u64> = l.blocks.iter().copied().collect();
        blocks.sort();
        out.push(format!(
            "header {:#010x}  tail {:#010x}  blocks {}",
            l.header,
            l.tail,
            blocks.len()
        ));
        let mut line = String::new();
        for (i, b) in blocks.iter().enumerate() {
            if i != 0 {
                line.push_str(", ");
            }
            line.push_str(&format!("{:#010x}", b));
        }
        out.push(line);
    }
    out
}

