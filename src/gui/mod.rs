use eframe::egui;
use std::collections::HashMap;
use egui_dock::{DockState, NodeIndex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::path::PathBuf;
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};
use std::process::Command;
use regex::Regex;

use crate::formats::{pe::PeParser, ExecutableParser};
use crate::analysis::disasm::{Architecture, Disassembler, X86Decoder};
use crate::analysis::decomp::{SnekDecompiler, Decompiler, ControlFlowGraph};
pub mod db;
pub mod calc;
use db::ProjectDb;

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut h = 0.0f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

const PY_INDICATORS_SCRIPT: &str = r#"import json, os, re
ctx_path = os.environ.get("SNEK_CONTEXT")
if not ctx_path:
    raise SystemExit("SNEK_CONTEXT missing")
ctx = json.load(open(ctx_path, "r", encoding="utf-8"))
strings = [s.get("text","") for s in ctx.get("strings", [])]
url_re = re.compile(r"(?i)\bhttps?://[^\s\"'`<>]+")
guid_re = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
emails = set()
urls = set()
guids = set()
ips = set()
for t in strings:
    for m in url_re.findall(t):
        urls.add(m)
    for m in guid_re.findall(t):
        guids.add(m)
    for m in ip_re.findall(t):
        ips.add(m)
print("Indicators:")
print("URLs:", len(urls))
for u in sorted(list(urls))[:100]:
    print("URL:", u)
print("GUIDs:", len(guids))
for g in sorted(list(guids))[:50]:
    print("GUID:", g)
print("IPs:", len(ips))
for ip in sorted(list(ips))[:50]:
    print("IP:", ip)
"#;

const PY_STRINGS_SEARCH_SCRIPT: &str = r#"import json, os, re
ctx_path = os.environ.get("SNEK_CONTEXT")
ctx = json.load(open(ctx_path, "r", encoding="utf-8"))
q = os.environ.get("SNEK_QUERY", "").strip()
if not q:
    raise SystemExit("Set SNEK_QUERY to search")
q2 = q.lower()
hits = []
for s in ctx.get("strings", []):
    t = s.get("text","")
    if q2 in t.lower():
        hits.append((s.get("va",0), t))
print("hits:", len(hits))
for va, t in hits[:200]:
    print(hex(va), t)
"#;

const PY_XREF_REPORT_SCRIPT: &str = r#"import json, os
ctx_path = os.environ.get("SNEK_CONTEXT")
ctx = json.load(open(ctx_path, "r", encoding="utf-8"))
xrefs = ctx.get("xrefs", [])
kind = os.environ.get("SNEK_KIND", "").strip().lower()
if kind:
    xrefs = [x for x in xrefs if (x.get("kind","").lower()==kind)]
print("xrefs:", len(xrefs))
for x in xrefs[:400]:
    frm = x.get("from",0)
    to = x.get("to",0)
    k = x.get("kind","")
    p = x.get("preview")
    if p:
        print(hex(frm), "->", hex(to), k, p)
    else:
        print(hex(frm), "->", hex(to), k)
"#;

const PY_MARK_URL_STRINGS_SCRIPT: &str = r#"import json, os, re
ctx_path = os.environ.get("SNEK_CONTEXT")
ctx = json.load(open(ctx_path, "r", encoding="utf-8"))
url_re = re.compile(r"(?i)\bhttps?://[^\s\"'`<>]+")
urls = []
for s in ctx.get("strings", []):
    t = s.get("text","")
    va = s.get("va",0)
    m = url_re.search(t)
    if m:
        urls.append((va, m.group(0)))
print("urls:", len(urls))
for va, u in urls[:50]:
    print("SNEK_CMD", json.dumps({"op":"bookmark","va":hex(va)}))
    print("SNEK_CMD", json.dumps({"op":"label","va":hex(va),"name":"url"}))
    print(hex(va), u)
"#;

pub enum GuiMessage {
    DisassemblyUpdate(Vec<String>),
    ListingUpdate(Vec<ListingRow>),
    GraphUpdate(HashMap<u64, GraphNode>),
    AnalysisDataUpdate(Vec<String>),
    DecompilationUpdateC(Vec<String>),
    DecompilationUpdateRust(Vec<String>),
    IrUpdate(Vec<String>),
    SsaUpdate(Vec<String>),
    LoopsUpdate(Vec<String>),
    TypesUpdate(Vec<String>),
    AliasUpdate(Vec<String>),
    StringsUpdate(Vec<StringEntry>),
    ImportsUpdate(Vec<String>),
    ExportsUpdate(Vec<String>),
    FunctionsUpdate(Vec<String>),
    RegistersUpdate(Vec<String>),
    StackUpdate(Vec<String>),
    XrefsUpdate(Vec<Xref>),
    FileInfoUpdate(Vec<String>),
    PythonConsoleResult(PythonConsoleRunResult),
    #[allow(dead_code)]
    ParseError(String),
}

#[derive(Debug, Clone)]
pub enum PythonCommand {
    Goto(u64),
    FocusXrefsTo(u64),
    Rename(u64, String),
    Label(u64, String),
    Comment(u64, String),
    Bookmark(u64),
    PatchFileOffset(usize, Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct PythonConsoleRunResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub status: String,
    pub commands: Vec<PythonCommand>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct LoadedSection {
    pub name: String,
    pub start_va: u64,
    pub bytes: Vec<u8>,
    pub file_offset: u64,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone)]
pub struct StringEntry {
    pub va: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Data,
    String,
    Pointer,
}

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListingTokenKind {
    Mnemonic,
    Register,
    Immediate,
    Address,
    Punct,
    Text,
}

#[derive(Debug, Clone)]
pub struct ListingToken {
    pub kind: ListingTokenKind,
    pub text: String,
    pub target: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ListingRow {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub tokens: Vec<ListingToken>,
}

pub struct SnekReverseApp {
    pub tree: DockState<String>,
    pub file_path: Option<String>,

    pub raw_bytes: Vec<u8>,
    pub disassembled_code: Vec<String>,
    pub disassembly_text: String,
    pub disassembly_export_text: String,
    pub listing_rows: Vec<ListingRow>,
    pub cursor_va: Option<u64>,
    pub hex_cursor_offset: Option<usize>,
    pub hex_patch_input: String,
    pub hex_patch_status: String,
    pub hex_dump_text: String,
    pub hex_dump_len: usize,
    pub extracted_assets: Vec<String>,
    pub analysis_data: Vec<String>,
    pub analysis_data_text: String,
    pub decompiled_c: Vec<String>,
    pub decompiled_c_text: String,
    pub decompiled_rust: Vec<String>,
    pub decompiled_rust_text: String,
    pub ir_view: Vec<String>,
    pub ir_text: String,
    pub ssa_view: Vec<String>,
    pub ssa_text: String,
    pub loops_text: String,
    pub types_text: String,
    pub alias_text: String,
    pub strings_list: Vec<StringEntry>,
    pub strings_text: String,
    pub functions_list: Vec<String>,
    pub functions_text: String,
    pub imports_list: Vec<String>,
    pub imports_text: String,
    pub exports_list: Vec<String>,
    pub exports_text: String,
    pub file_info: Vec<String>,
    pub file_info_text: String,
    pub memory_map: Vec<String>,
    pub xrefs: Vec<Xref>,
    pub xrefs_text: String,
    pub signatures: Vec<String>,
    pub signatures_text: String,
    pub stack_view: Vec<String>,
    pub stack_view_text: String,
    pub registers_state: Vec<String>,
    pub registers_text: String,
    pub logs: Vec<String>,
    pub logs_text: String,
    pub graph_nodes: HashMap<u64, GraphNode>,
    pub code_bytes: Vec<u8>,
    pub code_base_va: u64,
    pub selected_function: Option<u64>,
    pub is_64_bit: bool,
    pub loaded_sections: Vec<LoadedSection>,
    pub workspace_dir: Option<PathBuf>,
    pub project_db: ProjectDb,
    pub goto_open: bool,
    pub goto_input: String,
    pub search_open: bool,
    pub search_query: String,
    pub search_hits: Vec<u64>,
    pub search_index: usize,
    pub global_find_open: bool,
    pub global_find_query: String,
    pub global_find_case_sensitive: bool,
    pub global_find_scope: usize,
    pub global_find_results: Vec<GlobalFindHit>,
    pub global_find_index: usize,
    pub rename_open: bool,
    pub rename_target: Option<u64>,
    pub rename_input: String,
    pub symbol_filter: String,
    pub label_open: bool,
    pub label_target: Option<u64>,
    pub label_input: String,
    pub comment_open: bool,
    pub comment_target: Option<u64>,
    pub comment_input: String,
    pub nav_back: Vec<u64>,
    pub nav_forward: Vec<u64>,
    pub xref_open: bool,
    pub xref_mode: u8,
    pub xref_focus_to: Option<u64>,
    pub xref_query: String,
    pub xref_show_call: bool,
    pub xref_show_jump: bool,
    pub xref_show_data: bool,
    pub xref_show_string: bool,
    pub xref_show_pointer: bool,
    pub py_console_preset: usize,
    pub py_console_code: String,
    pub py_console_query: String,
    pub py_console_kind: String,
    pub py_console_file: Option<PathBuf>,
    pub py_console_last_saved: String,
    pub py_console_env: Vec<(String, String)>,
    pub py_console_stdout: Vec<String>,
    pub py_console_stdout_text: String,
    pub py_console_stderr: Vec<String>,
    pub py_console_stderr_text: String,
    pub py_console_status: String,
    pub py_console_running: bool,

    pub pan_offset: egui::Vec2,
    pub zoom_level: f32,
    pub dragging_node: Option<u64>,
    pub is_loading: bool,
    pub ui_inited: bool,
    pub appearance_open: bool,
    pub theme_mode: u8,
    pub theme_accent: egui::Color32,
    pub theme_bg: egui::Color32,
    pub theme_panel: egui::Color32,
    pub theme_text: egui::Color32,
    pub theme_dirty: bool,
    pub simple_layout: bool,
    pub lab_expr: String,
    pub lab_ans: f64,
    pub lab_history: Vec<String>,
    pub plot_expr: String,
    pub plot_x_min: f64,
    pub plot_x_max: f64,
    pub plot_samples: usize,
    pub plot_auto: bool,
    pub plot_status: String,
    pub plot_points: Vec<(f64, f64)>,
    pub plot_last_expr: String,
    pub plot_last_x_min: f64,
    pub plot_last_x_max: f64,
    pub plot_last_samples: usize,

    pub rx: Receiver<GuiMessage>,
    pub tx: Sender<GuiMessage>,
}

#[derive(Debug, Clone)]
pub struct GlobalFindHit {
    pub scope: usize,
    pub line_no: usize,
    pub text: String,
    pub va: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    pub theme_mode: u8,
    pub theme_accent: u32,
    pub theme_bg: u32,
    pub theme_panel: u32,
    pub theme_text: u32,
    pub simple_layout: bool,
    pub xref_mode: u8,
    pub xref_show_call: bool,
    pub xref_show_jump: bool,
    pub xref_show_data: bool,
    pub xref_show_string: bool,
    pub xref_show_pointer: bool,
    pub py_console_preset: usize,
    pub global_find_case_sensitive: bool,
    pub global_find_scope: usize,
    pub plot_expr: String,
    pub plot_x_min: f64,
    pub plot_x_max: f64,
    pub plot_samples: usize,
    pub plot_auto: bool,
}

impl Default for UserSettings {
    fn default() -> Self {
        fn pack(c: egui::Color32) -> u32 {
            let [r, g, b, a] = c.to_array();
            u32::from_le_bytes([r, g, b, a])
        }
        Self {
            theme_mode: 0,
            theme_accent: pack(egui::Color32::from_rgb(78, 201, 176)),
            theme_bg: pack(egui::Color32::from_rgb(22, 22, 24)),
            theme_panel: pack(egui::Color32::from_rgb(30, 30, 34)),
            theme_text: pack(egui::Color32::from_rgb(230, 230, 230)),
            simple_layout: true,
            xref_mode: 0,
            xref_show_call: true,
            xref_show_jump: true,
            xref_show_data: true,
            xref_show_string: true,
            xref_show_pointer: true,
            py_console_preset: 0,
            global_find_case_sensitive: false,
            global_find_scope: 0,
            plot_expr: "sin(x)".to_string(),
            plot_x_min: -10.0,
            plot_x_max: 10.0,
            plot_samples: 512,
            plot_auto: true,
        }
    }
}

#[allow(dead_code)]
pub struct GraphNode {
    pub text: String,
    pub pos: egui::Pos2,
    pub size: egui::Vec2,
    pub successors: Vec<u64>,
}

impl Default for SnekReverseApp {
    fn default() -> Self {
        let mut tree = DockState::new(vec!["Disassembly".to_owned()]);
        let surface = tree.main_surface_mut();
        let [_main, right] = surface.split_right(
            NodeIndex::root(),
            0.70,
            vec![
                "Decompilation (C/C++)".to_owned(),
                "Decompilation (Rust)".to_owned(),
                "Hex View".to_owned(),
                "Graph View".to_owned(),
                "SNEK Lab".to_owned(),
            ],
        );
        let _ = surface.split_left(
            NodeIndex::root(),
            0.22,
            vec![
                "Functions".to_owned(),
                "Strings".to_owned(),
                "Cross References".to_owned(),
            ],
        );
        let _ = surface.split_below(right, 0.72, vec!["Python Console".to_owned(), "Logs".to_owned()]);

        let (tx, rx) = channel();

        Self {
            tree,
            file_path: None,
            raw_bytes: Vec::new(),
            disassembled_code: vec!["No file loaded.".to_string()],
            disassembly_text: "No file loaded.".to_string(),
            disassembly_export_text: "No file loaded.".to_string(),
            listing_rows: Vec::new(),
            cursor_va: None,
            hex_cursor_offset: None,
            hex_patch_input: String::new(),
            hex_patch_status: String::new(),
            hex_dump_text: String::new(),
            hex_dump_len: 0,
            extracted_assets: vec![],
            analysis_data: vec!["Load a file to see analysis data.".to_string()],
            analysis_data_text: "Load a file to see analysis data.".to_string(),
            decompiled_c: vec!["/* C/C++ Pseudocode will appear here */".to_string()],
            decompiled_c_text: "/* C/C++ Pseudocode will appear here */".to_string(),
            decompiled_rust: vec!["// Rust Pseudocode will appear here".to_string()],
            decompiled_rust_text: "// Rust Pseudocode will appear here".to_string(),
            ir_view: vec![],
            ir_text: String::new(),
            ssa_view: vec![],
            ssa_text: String::new(),
            loops_text: String::new(),
            types_text: String::new(),
            alias_text: String::new(),
            strings_list: vec![],
            strings_text: String::new(),
            functions_list: vec![],
            functions_text: String::new(),
            imports_list: vec![],
            imports_text: String::new(),
            exports_list: vec![],
            exports_text: String::new(),
            file_info: vec![],
            file_info_text: String::new(),
            memory_map: vec![],
            xrefs: vec![],
            xrefs_text: String::new(),
            signatures: vec![],
            signatures_text: String::new(),
            stack_view: vec![],
            stack_view_text: String::new(),
            registers_state: vec![],
            registers_text: String::new(),
            logs: vec!["[SYSTEM] SNEK Reverse Initialized.".to_string()],
            logs_text: "[SYSTEM] SNEK Reverse Initialized.".to_string(),
            graph_nodes: HashMap::new(),
            code_bytes: Vec::new(),
            code_base_va: 0,
            selected_function: None,
            is_64_bit: false,
            loaded_sections: Vec::new(),
            workspace_dir: None,
            project_db: ProjectDb::default(),
            goto_open: false,
            goto_input: String::new(),
            search_open: false,
            search_query: String::new(),
            search_hits: Vec::new(),
            search_index: 0,
            global_find_open: false,
            global_find_query: String::new(),
            global_find_case_sensitive: false,
            global_find_scope: 0,
            global_find_results: Vec::new(),
            global_find_index: 0,
            rename_open: false,
            rename_target: None,
            rename_input: String::new(),
            symbol_filter: String::new(),
            label_open: false,
            label_target: None,
            label_input: String::new(),
            comment_open: false,
            comment_target: None,
            comment_input: String::new(),
            nav_back: Vec::new(),
            nav_forward: Vec::new(),
            xref_open: false,
            xref_mode: 0,
            xref_focus_to: None,
            xref_query: String::new(),
            xref_show_call: true,
            xref_show_jump: true,
            xref_show_data: true,
            xref_show_string: true,
            xref_show_pointer: true,
            py_console_preset: 0,
            py_console_code: String::new(),
            py_console_query: String::new(),
            py_console_kind: String::new(),
            py_console_file: None,
            py_console_last_saved: String::new(),
            py_console_env: vec![],
            py_console_stdout: vec![],
            py_console_stdout_text: String::new(),
            py_console_stderr: vec![],
            py_console_stderr_text: String::new(),
            py_console_status: String::new(),
            py_console_running: false,
            pan_offset: egui::vec2(0.0, 0.0),
            zoom_level: 1.0,
            dragging_node: None,
            is_loading: false,
            ui_inited: false,
            appearance_open: false,
            theme_mode: 0,
            theme_accent: egui::Color32::from_rgb(78, 201, 176),
            theme_bg: egui::Color32::from_rgb(22, 22, 24),
            theme_panel: egui::Color32::from_rgb(30, 30, 34),
            theme_text: egui::Color32::from_rgb(230, 230, 230),
            theme_dirty: true,
            simple_layout: true,
            lab_expr: String::new(),
            lab_ans: 0.0,
            lab_history: Vec::new(),
            plot_expr: "sin(x)".to_string(),
            plot_x_min: -10.0,
            plot_x_max: 10.0,
            plot_samples: 512,
            plot_auto: true,
            plot_status: String::new(),
            plot_points: Vec::new(),
            plot_last_expr: String::new(),
            plot_last_x_min: 0.0,
            plot_last_x_max: 0.0,
            plot_last_samples: 0,
            tx,
            rx,
        }
    }
}

impl SnekReverseApp {
    fn make_tree_simple() -> DockState<String> {
        let mut tree = DockState::new(vec!["Disassembly".to_owned()]);
        let surface = tree.main_surface_mut();
        let [_main, right] = surface.split_right(
            NodeIndex::root(),
            0.70,
            vec![
                "Decompilation (C/C++)".to_owned(),
                "Decompilation (Rust)".to_owned(),
                "Hex View".to_owned(),
                "Graph View".to_owned(),
                "SNEK Lab".to_owned(),
            ],
        );
        let _ = surface.split_left(
            NodeIndex::root(),
            0.22,
            vec![
                "Functions".to_owned(),
                "Strings".to_owned(),
                "Cross References".to_owned(),
            ],
        );
        let _ = surface.split_below(right, 0.72, vec!["Python Console".to_owned(), "Logs".to_owned()]);
        tree
    }

    fn make_tree_advanced() -> DockState<String> {
        let mut tree = DockState::new(vec!["Graph View".to_owned()]);
        let surface = tree.main_surface_mut();
        let [_graph, right_pane] = surface.split_right(
            NodeIndex::root(),
            0.70,
            vec![
                "Decompilation (C/C++)".to_owned(),
                "Decompilation (Rust)".to_owned(),
                "Hex View".to_owned(),
                "SNEK Lab".to_owned(),
            ],
        );
        let _ = surface.split_below(right_pane, 0.5, vec!["Registers".to_owned(), "Stack View".to_owned(), "Entropy Graph".to_owned()]);
        let _ = surface.split_left(
            NodeIndex::root(),
            0.20,
            vec![
                "Symbol Tree".to_owned(),
                "Functions".to_owned(),
                "Bookmarks".to_owned(),
                "Strings".to_owned(),
                "Imports".to_owned(),
                "Exports".to_owned(),
            ],
        );
        let _ = surface.split_below(
            NodeIndex::root(),
            0.75,
            vec![
                "Disassembly".to_owned(),
                "Analysis Data".to_owned(),
                "IR".to_owned(),
                "SSA".to_owned(),
                "Loops".to_owned(),
                "Types".to_owned(),
                "Alias".to_owned(),
                "Cross References".to_owned(),
                "Python Console".to_owned(),
                "Logs".to_owned(),
            ],
        );
        tree
    }

    pub fn reset_layout(&mut self, simple: bool) {
        self.tree = if simple { Self::make_tree_simple() } else { Self::make_tree_advanced() };
        self.simple_layout = simple;
    }

    pub fn show_tab(&mut self, tab_name: &str) {
        if let Some((surface_index, node_index, tab_index)) = self.tree.find_tab(&tab_name.to_owned()) {
            self.tree.set_active_tab((surface_index, node_index, tab_index));
        } else {
            self.tree.main_surface_mut().push_to_first_leaf(tab_name.to_owned());
        }
    }
    pub fn update_state(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                GuiMessage::DisassemblyUpdate(lines) => {
                    self.disassembled_code = lines;
                    self.disassembly_text = self.disassembled_code.join("\n");
                }
                GuiMessage::ListingUpdate(rows) => {
                    self.listing_rows = rows;
                    if self.cursor_va.is_none() {
                        self.cursor_va = self.listing_rows.first().map(|r| r.address);
                    }
                    let mut out = String::new();
                    for row in &self.listing_rows {
                        if let Some(lbl) = self.project_db.labels.get(&row.address) {
                            out.push_str(lbl);
                            out.push_str(":\n");
                        }
                        out.push_str(&format!("{:#010x}  ", row.address));
                        for b in &row.bytes {
                            out.push_str(&format!("{:02X} ", b));
                        }
                        out.push_str("  ");
                        for tok in &row.tokens {
                            out.push_str(&tok.text);
                        }
                        if let Some(c) = self.project_db.comments.get(&row.address) {
                            out.push_str(" ; ");
                            out.push_str(c);
                        }
                        out.push('\n');
                    }
                    self.disassembly_export_text = out;
                }
                GuiMessage::GraphUpdate(nodes) => {
                    self.graph_nodes = nodes;
                    self.is_loading = false;
                }
                GuiMessage::AnalysisDataUpdate(data) => {
                    self.analysis_data = data;
                    self.analysis_data_text = self.analysis_data.join("\n");
                }
                GuiMessage::IrUpdate(lines) => {
                    self.ir_view = lines;
                    self.ir_text = self.ir_view.join("\n");
                }
                GuiMessage::SsaUpdate(lines) => {
                    self.ssa_view = lines;
                    self.ssa_text = self.ssa_view.join("\n");
                }
                GuiMessage::LoopsUpdate(lines) => {
                    self.loops_text = lines.join("\n");
                }
                GuiMessage::TypesUpdate(lines) => {
                    self.types_text = lines.join("\n");
                }
                GuiMessage::AliasUpdate(lines) => {
                    self.alias_text = lines.join("\n");
                }
                GuiMessage::DecompilationUpdateC(c_code) => {
                    self.decompiled_c = c_code;
                    self.decompiled_c_text = self.decompiled_c.join("\n");
                }
                GuiMessage::DecompilationUpdateRust(rust_code) => {
                    self.decompiled_rust = rust_code;
                    self.decompiled_rust_text = self.decompiled_rust.join("\n");
                }
                GuiMessage::StringsUpdate(strings) => {
                    self.strings_list = strings;
                    let mut out = String::new();
                    for s in &self.strings_list {
                        out.push_str(&format!("{:#010x}  {}\n", s.va, s.text));
                    }
                    self.strings_text = out;
                }
                GuiMessage::ImportsUpdate(imports) => {
                    self.imports_list = imports;
                    self.imports_text = self.imports_list.join("\n");
                }
                GuiMessage::ExportsUpdate(exports) => {
                    self.exports_list = exports;
                    self.exports_text = self.exports_list.join("\n");
                }
                GuiMessage::FunctionsUpdate(funcs) => {
                    self.functions_list = funcs;
                    self.functions_text = self.functions_list.join("\n");
                }
                GuiMessage::RegistersUpdate(regs) => {
                    self.registers_state = regs;
                    self.registers_text = self.registers_state.join("\n");
                }
                GuiMessage::StackUpdate(stack) => {
                    self.stack_view = stack;
                    self.stack_view_text = self.stack_view.join("\n");
                }
                GuiMessage::XrefsUpdate(xrefs) => {
                    self.xrefs = xrefs;
                    let mut out = String::new();
                    for x in &self.xrefs {
                        let kind = match x.kind {
                            XrefKind::Call => "call",
                            XrefKind::Jump => "jump",
                            XrefKind::Data => "data",
                            XrefKind::String => "string",
                            XrefKind::Pointer => "ptr",
                        };
                        if let Some(p) = &x.preview {
                            out.push_str(&format!("{:#010x} -> {:#010x}  {}  {}\n", x.from, x.to, kind, p));
                        } else {
                            out.push_str(&format!("{:#010x} -> {:#010x}  {}\n", x.from, x.to, kind));
                        }
                    }
                    self.xrefs_text = out;
                }
                GuiMessage::FileInfoUpdate(info) => {
                    self.file_info = info;
                    self.file_info_text = self.file_info.join("\n");
                }
                GuiMessage::PythonConsoleResult(res) => {
                    self.py_console_stdout = res.stdout;
                    self.py_console_stderr = res.stderr;
                    self.py_console_stdout_text = self.py_console_stdout.join("\n");
                    self.py_console_stderr_text = self.py_console_stderr.join("\n");
                    self.py_console_status = res.status;
                    for cmd in res.commands {
                        match cmd {
                            PythonCommand::Goto(va) => self.goto_any_va(va),
                            PythonCommand::FocusXrefsTo(va) => self.focus_xrefs_to(va),
                            PythonCommand::Rename(va, name) => self.set_function_name(va, name),
                            PythonCommand::Label(va, name) => self.set_label(va, name),
                            PythonCommand::Comment(va, comment) => self.set_comment(va, comment),
                            PythonCommand::Bookmark(va) => self.toggle_bookmark(va),
                            PythonCommand::PatchFileOffset(off, bytes) => {
                                if self.patch_file_offset(off, &bytes).is_ok() {
                                    if let Some(va) = self.selected_function {
                                        self.analyze_function(va);
                                    }
                                }
                            }
                        }
                    }
                    self.py_console_running = false;
                }
                GuiMessage::ParseError(err) => {
                    self.disassembled_code = vec![err];
                    self.is_loading = false;
                }
            }
        }
    }

    fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur = String::new();
        for ch in s.chars() {
            if ch.is_ascii_hexdigit() {
                cur.push(ch);
                if cur.len() == 2 {
                    let b = u8::from_str_radix(&cur, 16).ok()?;
                    out.push(b);
                    cur.clear();
                }
            }
        }
        if !cur.is_empty() {
            return None;
        }
        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    pub fn patch_file_offset(&mut self, file_offset: usize, bytes: &[u8]) -> Result<(), String> {
        if self.raw_bytes.is_empty() {
            return Err("No file loaded".to_string());
        }
        if file_offset >= self.raw_bytes.len() {
            return Err("Offset out of range".to_string());
        }
        if file_offset + bytes.len() > self.raw_bytes.len() {
            return Err("Patch exceeds file size".to_string());
        }
        self.raw_bytes[file_offset..file_offset + bytes.len()].copy_from_slice(bytes);

        for sec in &mut self.loaded_sections {
            let sec_off = sec.file_offset as usize;
            let sec_end = sec_off.saturating_add(sec.bytes.len());
            if file_offset >= sec_off && file_offset < sec_end {
                let in_sec = file_offset - sec_off;
                let n = bytes.len().min(sec.bytes.len().saturating_sub(in_sec));
                if n != 0 {
                    sec.bytes[in_sec..in_sec + n].copy_from_slice(&bytes[..n]);
                }
            }
        }
        self.hex_dump_len = 0;
        self.hex_dump_text.clear();
        Ok(())
    }

    pub fn patch_hex_cursor(&mut self) -> Result<(), String> {
        let off = self.hex_cursor_offset.ok_or_else(|| "Select an offset in Hex View first".to_string())?;
        let bytes = Self::parse_hex_bytes(&self.hex_patch_input).ok_or_else(|| "Invalid hex bytes".to_string())?;
        self.patch_file_offset(off, &bytes)?;
        if let Some(va) = self.cursor_va {
            self.analyze_function(va);
        }
        Ok(())
    }

    pub fn python_scripts_dir(&self) -> Option<PathBuf> {
        self.workspace_dir.as_ref().map(|d| d.join("python_scripts"))
    }

    pub fn list_python_scripts(&self) -> Vec<PathBuf> {
        let Some(dir) = self.python_scripts_dir() else {
            return vec![];
        };
        let mut out = Vec::new();
        let rd = std::fs::read_dir(dir);
        let Ok(rd) = rd else {
            return vec![];
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()).unwrap_or("") == "py" {
                out.push(p);
            }
        }
        out.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        out
    }

    pub fn load_python_script(&mut self, path: PathBuf) {
        if let Ok(code) = std::fs::read_to_string(&path) {
            self.py_console_file = Some(path);
            self.py_console_code = code.clone();
            self.py_console_last_saved = code;
            self.py_console_stdout = vec!["[loaded]".to_string()];
            self.py_console_stdout_text = self.py_console_stdout.join("\n");
            self.py_console_stderr.clear();
            self.py_console_stderr_text.clear();
            self.py_console_status = String::new();
        } else {
            self.py_console_stdout = vec![];
            self.py_console_stdout_text.clear();
            self.py_console_stderr = vec!["[error] failed to load script".to_string()];
            self.py_console_stderr_text = self.py_console_stderr.join("\n");
            self.py_console_status = String::new();
        }
    }

    pub fn save_python_script(&mut self) -> Result<(), String> {
        let Some(path) = self.py_console_file.clone() else {
            return Err("No script file selected".to_string());
        };
        let dir = path.parent().ok_or_else(|| "Invalid script path".to_string())?;
        let _ = std::fs::create_dir_all(dir);
        std::fs::write(&path, self.py_console_code.as_bytes()).map_err(|e| format!("{:?}", e))?;
        self.py_console_last_saved = self.py_console_code.clone();
        Ok(())
    }

    pub fn python_presets(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("Custom", ""),
            ("Indicators Report", PY_INDICATORS_SCRIPT),
            ("Strings Search", PY_STRINGS_SEARCH_SCRIPT),
            ("Xref Report", PY_XREF_REPORT_SCRIPT),
            ("Mark URL Strings", PY_MARK_URL_STRINGS_SCRIPT),
        ]
    }

    pub fn run_python_console(&mut self) {
        if self.py_console_running {
            return;
        }
        let presets = self.python_presets();
        let idx = self.py_console_preset.min(presets.len().saturating_sub(1));
        let (_name, preset_src) = presets[idx];
        let source = if idx == 0 { self.py_console_code.clone() } else { preset_src.to_string() };
        self.py_console_running = true;
        self.py_console_stdout = vec!["[running]".to_string()];
        self.py_console_stderr.clear();
        self.py_console_status = String::new();

        let tx = self.tx.clone();
        let preset_idx = idx;
        let q = self.py_console_query.clone();
        let k = self.py_console_kind.clone();
        let envs = self.py_console_env.clone();
        let file_path = self.file_path.clone();
        let workspace_dir = self.workspace_dir.clone();
        let selected_function = self.selected_function;
        let is_64 = self.is_64_bit;
        let strings = self.strings_list.clone();
        let xrefs = self.xrefs.clone();
        let funcs = self.functions_list.clone();
        let imports = self.imports_list.clone();
        let exports = self.exports_list.clone();
        let memory_map = self.memory_map.clone();

        thread::spawn(move || {
            #[derive(Serialize)]
            struct CtxString {
                va: u64,
                text: String,
            }
            #[derive(Serialize)]
            struct CtxXref {
                from: u64,
                to: u64,
                kind: String,
                preview: Option<String>,
            }
            #[derive(Serialize)]
            struct PyCtx {
                file_path: Option<String>,
                workspace_dir: Option<String>,
                selected_function: Option<u64>,
                is_64_bit: bool,
                strings: Vec<CtxString>,
                xrefs: Vec<CtxXref>,
                functions: Vec<String>,
                imports: Vec<String>,
                exports: Vec<String>,
                memory_map: Vec<String>,
            }

            let ctx = PyCtx {
                file_path: file_path.clone(),
                workspace_dir: workspace_dir.as_ref().map(|p| p.to_string_lossy().to_string()),
                selected_function,
                is_64_bit: is_64,
                strings: strings.into_iter().map(|s| CtxString { va: s.va, text: s.text }).collect(),
                xrefs: xrefs.into_iter().map(|x| {
                    let k = match x.kind {
                        XrefKind::Call => "call",
                        XrefKind::Jump => "jump",
                        XrefKind::Data => "data",
                        XrefKind::String => "string",
                        XrefKind::Pointer => "ptr",
                    }.to_string();
                    CtxXref { from: x.from, to: x.to, kind: k, preview: x.preview }
                }).collect(),
                functions: funcs,
                imports,
                exports,
                memory_map,
            };

            let dir = workspace_dir.unwrap_or_else(|| std::env::temp_dir().join("snek_reverse_workspace"));
            let run_dir = dir.join("python_console");
            let _ = std::fs::create_dir_all(&run_dir);
            let ctx_path = run_dir.join("context.json");
            let script_path = run_dir.join("run.py");

            if let Ok(j) = serde_json::to_vec_pretty(&ctx) {
                let _ = std::fs::write(&ctx_path, j);
            }
            let _ = std::fs::write(&script_path, source.as_bytes());

            let mut tried = Vec::new();
            for (exe, args) in [
                ("python", vec!["-u", script_path.to_string_lossy().as_ref()]),
                ("py", vec!["-3", "-u", script_path.to_string_lossy().as_ref()]),
                ("python3", vec!["-u", script_path.to_string_lossy().as_ref()]),
            ] {
                tried.push(exe.to_string());
                let mut cmd = Command::new(exe);
                cmd.args(args);
                cmd.current_dir(&run_dir);
                cmd.env("SNEK_CONTEXT", ctx_path.to_string_lossy().as_ref());
                if let Some(fp) = &file_path {
                    cmd.env("SNEK_FILE_PATH", fp);
                }
                cmd.env("SNEK_WORKSPACE_DIR", dir.to_string_lossy().as_ref());
                if let Some(fva) = selected_function {
                    cmd.env("SNEK_FUNCTION_VA", format!("{:#x}", fva));
                }
                if preset_idx == 2 && !q.trim().is_empty() {
                    cmd.env("SNEK_QUERY", q.trim());
                }
                if preset_idx == 3 && !k.trim().is_empty() {
                    cmd.env("SNEK_KIND", k.trim());
                }
                for (ek, ev) in &envs {
                    let key = ek.trim();
                    if key.is_empty() {
                        continue;
                    }
                    if key.eq_ignore_ascii_case("SNEK_CONTEXT")
                        || key.eq_ignore_ascii_case("SNEK_FILE_PATH")
                        || key.eq_ignore_ascii_case("SNEK_WORKSPACE_DIR")
                        || key.eq_ignore_ascii_case("SNEK_FUNCTION_VA")
                    {
                        continue;
                    }
                    cmd.env(key, ev);
                }

                match cmd.output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let mut stdout_lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
                        let stderr_lines: Vec<String> = stderr.lines().map(|s| s.to_string()).collect();

                        fn parse_u64(v: &serde_json::Value) -> Option<u64> {
                            if let Some(n) = v.as_u64() {
                                return Some(n);
                            }
                            let s = v.as_str()?.trim();
                            if s.starts_with("0x") || s.starts_with("0X") {
                                u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
                            } else {
                                s.parse::<u64>().ok()
                            }
                        }

                        fn parse_usize(v: &serde_json::Value) -> Option<usize> {
                            if let Some(n) = v.as_u64() {
                                return usize::try_from(n).ok();
                            }
                            let s = v.as_str()?.trim();
                            if s.starts_with("0x") || s.starts_with("0X") {
                                usize::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
                            } else {
                                s.parse::<usize>().ok()
                            }
                        }

                        fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
                            let mut out = Vec::new();
                            let mut cur = String::new();
                            for ch in s.chars() {
                                if ch.is_ascii_hexdigit() {
                                    cur.push(ch);
                                    if cur.len() == 2 {
                                        let b = u8::from_str_radix(&cur, 16).ok()?;
                                        out.push(b);
                                        cur.clear();
                                    }
                                }
                            }
                            if !cur.is_empty() || out.is_empty() {
                                return None;
                            }
                            Some(out)
                        }

                        let mut commands: Vec<PythonCommand> = Vec::new();
                        let mut cleaned_stdout: Vec<String> = Vec::new();
                        for line in stdout_lines.drain(..) {
                            let trimmed = line.trim();
                            if let Some(rest) = trimmed.strip_prefix("SNEK_CMD ") {
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
                                    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
                                    match op.as_str() {
                                        "goto" => {
                                            if let Some(va) = v.get("va").and_then(parse_u64) {
                                                commands.push(PythonCommand::Goto(va));
                                            }
                                        }
                                        "focus_xrefs_to" => {
                                            if let Some(va) = v.get("va").and_then(parse_u64) {
                                                commands.push(PythonCommand::FocusXrefsTo(va));
                                            }
                                        }
                                        "rename" => {
                                            if let (Some(va), Some(name)) = (
                                                v.get("va").and_then(parse_u64),
                                                v.get("name").and_then(|x| x.as_str()).map(|s| s.to_string()),
                                            ) {
                                                commands.push(PythonCommand::Rename(va, name));
                                            }
                                        }
                                        "label" => {
                                            if let (Some(va), Some(name)) = (
                                                v.get("va").and_then(parse_u64),
                                                v.get("name").and_then(|x| x.as_str()).map(|s| s.to_string()),
                                            ) {
                                                commands.push(PythonCommand::Label(va, name));
                                            }
                                        }
                                        "comment" => {
                                            if let (Some(va), Some(comment)) = (
                                                v.get("va").and_then(parse_u64),
                                                v.get("comment").and_then(|x| x.as_str()).map(|s| s.to_string()),
                                            ) {
                                                commands.push(PythonCommand::Comment(va, comment));
                                            }
                                        }
                                        "bookmark" => {
                                            if let Some(va) = v.get("va").and_then(parse_u64) {
                                                commands.push(PythonCommand::Bookmark(va));
                                            }
                                        }
                                        "patch_file_offset" => {
                                            if let (Some(off), Some(b)) = (
                                                v.get("offset").and_then(parse_usize),
                                                v.get("bytes").and_then(|x| x.as_str()).and_then(parse_hex_bytes),
                                            ) {
                                                commands.push(PythonCommand::PatchFileOffset(off, b));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                continue;
                            }
                            cleaned_stdout.push(line);
                        }

                        let status = format!("{}", output.status);
                        let _ = tx.send(GuiMessage::PythonConsoleResult(PythonConsoleRunResult {
                            stdout: cleaned_stdout,
                            stderr: stderr_lines,
                            status,
                            commands,
                        }));
                        return;
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            continue;
                        }
                        let _ = tx.send(GuiMessage::PythonConsoleResult(PythonConsoleRunResult {
                            stdout: vec![],
                            stderr: vec![format!("{:?}", e)],
                            status: "error".to_string(),
                            commands: vec![],
                        }));
                        return;
                    }
                }
            }
            let _ = tx.send(GuiMessage::PythonConsoleResult(PythonConsoleRunResult {
                stdout: vec![],
                stderr: vec![format!("no python interpreter found (tried: {})", tried.join(", "))],
                status: "error".to_string(),
                commands: vec![],
            }));
        });
    }

    pub fn read_va(&self, va: u64, max_len: usize) -> Vec<u8> {
        for sec in &self.loaded_sections {
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va < end {
                let off = (va - start) as usize;
                let end_off = (off + max_len).min(sec.bytes.len());
                return sec.bytes[off..end_off].to_vec();
            }
        }
        Vec::new()
    }

    fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        for sec in &self.loaded_sections {
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va < end {
                let delta = va - start;
                return Some(sec.file_offset.saturating_add(delta) as usize);
            }
        }
        None
    }

    fn is_executable_va(&self, va: u64) -> bool {
        for sec in &self.loaded_sections {
            if !sec.executable {
                continue;
            }
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va < end {
                return true;
            }
        }
        false
    }

    pub fn goto_any_va(&mut self, va: u64) {
        self.jump_to_any_va(va, true);
    }

    fn jump_to_any_va(&mut self, va: u64, push_history: bool) {
        if push_history {
            if let Some(cur) = self.cursor_va {
                if cur != va {
                    self.nav_back.push(cur);
                    self.nav_forward.clear();
                }
            }
        }

        self.cursor_va = Some(va);

        if self.is_executable_va(va) {
            self.show_tab("Disassembly");
            self.analyze_function(va);
            return;
        }

        self.hex_cursor_offset = self.va_to_file_offset(va);
        self.show_tab("Hex View");
    }

    pub fn analyze_function(&mut self, function_va: u64) {
        if self.loaded_sections.is_empty() {
            return;
        }

        self.selected_function = Some(function_va);
        self.disassembled_code = vec!["Analyzing function...".to_string()];
        self.listing_rows.clear();
        self.analysis_data.clear();
        self.graph_nodes.clear();
        self.decompiled_c = vec![];
        self.decompiled_rust = vec![];
        self.ir_view = vec![];
        self.ssa_view = vec![];
        self.loops_text.clear();
        self.types_text.clear();
        self.alias_text.clear();
        self.xrefs.clear();
        self.stack_view.clear();
        self.registers_state.clear();
        self.global_find_results.clear();
        self.global_find_index = 0;
        self.is_loading = true;

        let tx = self.tx.clone();
        let is_64 = self.is_64_bit;
        let strings = self.strings_list.clone();
        let loaded_sections = self.loaded_sections.clone();
        let workspace_dir = self.workspace_dir.clone();

        thread::spawn(move || {
            let decoder = X86Decoder::new(if is_64 { Architecture::X86_64 } else { Architecture::X86 });

            let read_va = |va: u64, max_len: usize| -> Vec<u8> {
                for sec in &loaded_sections {
                    let start = sec.start_va;
                    let end = start.saturating_add(sec.bytes.len() as u64);
                    if va >= start && va < end {
                        let off = (va - start) as usize;
                        let end_off = (off + max_len).min(sec.bytes.len());
                        return sec.bytes[off..end_off].to_vec();
                    }
                }
                Vec::new()
            };

            let mut queue: VecDeque<u64> = VecDeque::new();
            let mut seen_blocks = std::collections::HashSet::new();
            let mut inst_map: std::collections::BTreeMap<u64, crate::analysis::disasm::Instruction> = std::collections::BTreeMap::new();
            queue.push_back(function_va);

            while let Some(block_start) = queue.pop_front() {
                if !seen_blocks.insert(block_start) {
                    continue;
                }
                let mut addr = block_start;
                let mut steps = 0usize;

                loop {
                    if inst_map.contains_key(&addr) {
                        break;
                    }
                    let bytes = read_va(addr, 32);
                    if bytes.is_empty() {
                        break;
                    }
                    let decoded = decoder.disassemble_block(&bytes, addr);
                    if decoded.is_empty() {
                        break;
                    }
                    let inst = decoded[0].clone();
                    let len = inst.bytes.len().max(1) as u64;
                    let is_conditional = inst.is_jump && inst.mnemonic != "jmp";

                    inst_map.insert(inst.address, inst.clone());

                    if inst.mnemonic == "ret" {
                        break;
                    }

                    if inst.is_jump {
                        if let Some(t) = inst.target_address {
                            queue.push_back(t);
                        }
                        if is_conditional {
                            queue.push_back(addr.wrapping_add(len));
                        }
                        break;
                    }

                    addr = addr.wrapping_add(len);
                    steps += 1;
                    if steps > 20000 {
                        break;
                    }
                }
            }

            let instrs: Vec<_> = inst_map.into_values().collect();

            let mut lines = Vec::with_capacity(instrs.len());
            for inst in &instrs {
                lines.push(inst.to_string());
            }
            let _ = tx.send(GuiMessage::DisassemblyUpdate(lines));

            let listing = Self::build_listing(&instrs);
            let _ = tx.send(GuiMessage::ListingUpdate(listing));

            let (analysis, xrefs, regs, stack_lines) = Self::build_analysis_views_full(&instrs, &strings, &loaded_sections, is_64);
            let _ = tx.send(GuiMessage::AnalysisDataUpdate(analysis.clone()));
            let _ = tx.send(GuiMessage::XrefsUpdate(xrefs.clone()));
            let _ = tx.send(GuiMessage::RegistersUpdate(regs));
            let _ = tx.send(GuiMessage::StackUpdate(stack_lines));

            let decompiler = SnekDecompiler::new();
            let cfg = decompiler.build_cfg(&instrs);
            let nodes = Self::build_graph_layout_static(&cfg);
            let _ = tx.send(GuiMessage::GraphUpdate(nodes));

            let ir = crate::analysis::ir::lift_cfg(&cfg);
            let ir_txt = crate::analysis::ir::render_ir(&ir);
            let ir_lines = ir_txt.split('\n').map(|s| s.to_string()).collect::<Vec<_>>();
            let _ = tx.send(GuiMessage::IrUpdate(ir_lines));

            let loops_lines = crate::analysis::loops::render_loops(&ir);
            let _ = tx.send(GuiMessage::LoopsUpdate(loops_lines));

            let mut ssa = crate::analysis::ssa::to_ssa(&ir);
            ssa = crate::analysis::ssa::optimize(&ssa);
            let ssa_txt = crate::analysis::ir::render_ir(&ssa);
            let ssa_lines = ssa_txt.split('\n').map(|s| s.to_string()).collect::<Vec<_>>();
            let _ = tx.send(GuiMessage::SsaUpdate(ssa_lines));

            let types = crate::analysis::types::infer_var_types(&ssa);
            let types_lines = crate::analysis::types::render_types(&types);
            let _ = tx.send(GuiMessage::TypesUpdate(types_lines));

            let alias_lines = crate::analysis::alias::render_alias_summary(&ssa);
            let _ = tx.send(GuiMessage::AliasUpdate(alias_lines));

            let c_code = decompiler.generate_pseudocode(&cfg, "c");
            let rust_code = decompiler.generate_pseudocode(&cfg, "rust");
            let c_lines = c_code.split('\n').map(|s| s.to_string()).collect();
            let rust_lines = rust_code.split('\n').map(|s| s.to_string()).collect();
            let _ = tx.send(GuiMessage::DecompilationUpdateC(c_lines));
            let _ = tx.send(GuiMessage::DecompilationUpdateRust(rust_lines));

            if let Some(dir) = workspace_dir {
                let func_dir = dir.join("functions").join(format!("{:x}", function_va));
                let _ = std::fs::create_dir_all(&func_dir);
                let _ = std::fs::write(func_dir.join("disasm.asm"), instrs.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("\n"));
                let _ = std::fs::write(func_dir.join("analysis.txt"), analysis.join("\n"));
                let _ = std::fs::write(
                    func_dir.join("xrefs.txt"),
                    xrefs
                        .iter()
                        .map(|x| {
                            let k = match x.kind {
                                XrefKind::Call => "call",
                                XrefKind::Jump => "jump",
                                XrefKind::Data => "data",
                                XrefKind::String => "string",
                                XrefKind::Pointer => "ptr",
                            };
                            if let Some(p) = &x.preview {
                                format!("{:#010x} -> {:#010x} {} {}", x.from, x.to, k, p)
                            } else {
                                format!("{:#010x} -> {:#010x} {}", x.from, x.to, k)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
                let _ = std::fs::write(func_dir.join("decomp.c"), c_code);
                let _ = std::fs::write(func_dir.join("decomp.rs"), rust_code);
                let _ = std::fs::write(func_dir.join("ir.txt"), ir_txt);
                let _ = std::fs::write(func_dir.join("ssa.txt"), ssa_txt);
            }
        });
    }

    pub fn goto_va(&mut self, va: u64) {
        self.jump_to_va(va, true);
    }

    fn jump_to_va(&mut self, va: u64, push_history: bool) {
        if push_history {
            if let Some(cur) = self.cursor_va {
                if cur != va {
                    self.nav_back.push(cur);
                    self.nav_forward.clear();
                }
            }
        }
        self.cursor_va = Some(va);
        self.show_tab("Disassembly");
        self.analyze_function(va);
    }

    pub fn navigate_back(&mut self) {
        let Some(cur) = self.cursor_va else { return; };
        let Some(prev) = self.nav_back.pop() else { return; };
        self.nav_forward.push(cur);
        self.jump_to_any_va(prev, false);
    }

    pub fn navigate_forward(&mut self) {
        let Some(cur) = self.cursor_va else { return; };
        let Some(next) = self.nav_forward.pop() else { return; };
        self.nav_back.push(cur);
        self.jump_to_any_va(next, false);
    }

    pub fn apply_search(&mut self) {
        let q = self.search_query.trim().to_lowercase();
        self.search_hits.clear();
        self.search_index = 0;
        if q.is_empty() {
            return;
        }
        for row in &self.listing_rows {
            let mut hay = String::new();
            for t in &row.tokens {
                hay.push_str(&t.text);
                hay.push(' ');
            }
            if hay.to_lowercase().contains(&q) {
                self.search_hits.push(row.address);
            }
        }
        if let Some(first) = self.search_hits.first().copied() {
            self.cursor_va = Some(first);
        }
    }

    pub fn search_next(&mut self) {
        if self.search_hits.is_empty() {
            return;
        }
        self.search_index = (self.search_index + 1).min(self.search_hits.len() - 1);
        self.cursor_va = Some(self.search_hits[self.search_index]);
    }

    pub fn search_prev(&mut self) {
        if self.search_hits.is_empty() {
            return;
        }
        if self.search_index > 0 {
            self.search_index -= 1;
        }
        self.cursor_va = Some(self.search_hits[self.search_index]);
    }

    pub fn global_find_scopes() -> &'static [&'static str] {
        &[
            "All Tabs",
            "Disassembly",
            "Analysis Data",
            "IR",
            "SSA",
            "Loops",
            "Types",
            "Alias",
            "Decompilation (C/C++)",
            "Decompilation (Rust)",
            "Strings",
            "Functions",
            "Imports",
            "Exports",
            "Cross References",
            "Logs",
            "File Info",
            "Entropy Graph",
            "Registers",
            "Stack View",
            "Python stdout",
            "Python stderr",
            "Hex Dump",
        ]
    }

    fn global_find_scope_text(&self, scope: usize) -> (&'static str, &str) {
        match scope {
            1 => ("Disassembly", &self.disassembly_export_text),
            2 => ("Analysis Data", &self.analysis_data_text),
            3 => ("IR", &self.ir_text),
            4 => ("SSA", &self.ssa_text),
            5 => ("Loops", &self.loops_text),
            6 => ("Types", &self.types_text),
            7 => ("Alias", &self.alias_text),
            8 => ("Decompilation (C/C++)", &self.decompiled_c_text),
            9 => ("Decompilation (Rust)", &self.decompiled_rust_text),
            10 => ("Strings", &self.strings_text),
            11 => ("Functions", &self.functions_text),
            12 => ("Imports", &self.imports_text),
            13 => ("Exports", &self.exports_text),
            14 => ("Cross References", &self.xrefs_text),
            15 => ("Logs", &self.logs_text),
            16 => ("File Info", &self.file_info_text),
            17 => ("Entropy Graph", &self.signatures_text),
            18 => ("Registers", &self.registers_text),
            19 => ("Stack View", &self.stack_view_text),
            20 => ("Python stdout", &self.py_console_stdout_text),
            21 => ("Python stderr", &self.py_console_stderr_text),
            22 => ("Hex Dump", &self.hex_dump_text),
            _ => ("All Tabs", ""),
        }
    }

    pub fn apply_global_find(&mut self) {
        let q_raw = self.global_find_query.trim().to_string();
        self.global_find_results.clear();
        self.global_find_index = 0;
        if q_raw.is_empty() {
            return;
        }

        let q = if self.global_find_case_sensitive { q_raw.clone() } else { q_raw.to_lowercase() };

        let mut scopes: Vec<usize> = Vec::new();
        if self.global_find_scope == 0 {
            scopes.extend(1..Self::global_find_scopes().len());
        } else {
            scopes.push(self.global_find_scope);
        }

        for scope in scopes {
            let (scope_name, text) = self.global_find_scope_text(scope);
            let scope_name = scope_name.to_string();
            let text = text.to_string();
            if text.is_empty() {
                continue;
            }
            for (idx, line) in text.lines().enumerate() {
                let hay = if self.global_find_case_sensitive { line.to_string() } else { line.to_lowercase() };
                if !hay.contains(&q) {
                    continue;
                }

                let trimmed = line.trim_start();
                let mut va: Option<u64> = None;
                if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                    let mut tok = String::new();
                    for ch in trimmed.chars().skip(2) {
                        if ch.is_ascii_hexdigit() {
                            tok.push(ch);
                        } else {
                            break;
                        }
                    }
                    if !tok.is_empty() {
                        if let Ok(v) = u64::from_str_radix(&tok, 16) {
                            va = Some(v);
                        }
                    }
                }

                self.global_find_results.push(GlobalFindHit {
                    scope,
                    line_no: idx + 1,
                    text: format!("{}:{:>6}  {}", scope_name, idx + 1, line),
                    va,
                });
                if self.global_find_results.len() >= 1000 {
                    break;
                }
            }
        }
    }

    pub fn compute_plot(&mut self) {
        let samples = self.plot_samples.clamp(16, 4096);
        self.plot_samples = samples;
        if !(self.plot_x_min.is_finite() && self.plot_x_max.is_finite()) {
            self.plot_status = "invalid x range".to_string();
            self.plot_points.clear();
            return;
        }
        if self.plot_x_max <= self.plot_x_min {
            self.plot_status = "x_max must be > x_min".to_string();
            self.plot_points.clear();
            return;
        }
        let expr = self.plot_expr.trim();
        if expr.is_empty() {
            self.plot_status = "missing expression".to_string();
            self.plot_points.clear();
            return;
        }

        let mut pts = Vec::with_capacity(samples);
        let mut vars: HashMap<String, f64> = HashMap::new();
        vars.insert("ans".to_string(), self.lab_ans);

        for i in 0..samples {
            let t = i as f64 / (samples - 1) as f64;
            let x = self.plot_x_min + (self.plot_x_max - self.plot_x_min) * t;
            vars.insert("x".to_string(), x);
            match crate::gui::calc::eval_expr(expr, &vars) {
                Ok(y) if y.is_finite() => pts.push((x, y)),
                Ok(_) => pts.push((x, f64::NAN)),
                Err(_) => pts.push((x, f64::NAN)),
            }
        }

        self.plot_points = pts;
        self.plot_last_expr = self.plot_expr.clone();
        self.plot_last_x_min = self.plot_x_min;
        self.plot_last_x_max = self.plot_x_max;
        self.plot_last_samples = self.plot_samples;
        self.plot_status = "ok".to_string();
    }

    fn pack_color(c: egui::Color32) -> u32 {
        let [r, g, b, a] = c.to_array();
        u32::from_le_bytes([r, g, b, a])
    }

    fn unpack_color(v: u32) -> egui::Color32 {
        let [r, g, b, a] = v.to_le_bytes();
        egui::Color32::from_rgba_unmultiplied(r, g, b, a)
    }

    pub fn to_settings(&self) -> UserSettings {
        UserSettings {
            theme_mode: self.theme_mode,
            theme_accent: Self::pack_color(self.theme_accent),
            theme_bg: Self::pack_color(self.theme_bg),
            theme_panel: Self::pack_color(self.theme_panel),
            theme_text: Self::pack_color(self.theme_text),
            simple_layout: self.simple_layout,
            xref_mode: self.xref_mode,
            xref_show_call: self.xref_show_call,
            xref_show_jump: self.xref_show_jump,
            xref_show_data: self.xref_show_data,
            xref_show_string: self.xref_show_string,
            xref_show_pointer: self.xref_show_pointer,
            py_console_preset: self.py_console_preset,
            global_find_case_sensitive: self.global_find_case_sensitive,
            global_find_scope: self.global_find_scope,
            plot_expr: self.plot_expr.clone(),
            plot_x_min: self.plot_x_min,
            plot_x_max: self.plot_x_max,
            plot_samples: self.plot_samples,
            plot_auto: self.plot_auto,
        }
    }

    pub fn apply_settings(&mut self, s: &UserSettings) {
        self.theme_mode = s.theme_mode;
        self.theme_accent = Self::unpack_color(s.theme_accent);
        self.theme_bg = Self::unpack_color(s.theme_bg);
        self.theme_panel = Self::unpack_color(s.theme_panel);
        self.theme_text = Self::unpack_color(s.theme_text);
        self.simple_layout = s.simple_layout;
        self.xref_mode = s.xref_mode;
        self.xref_show_call = s.xref_show_call;
        self.xref_show_jump = s.xref_show_jump;
        self.xref_show_data = s.xref_show_data;
        self.xref_show_string = s.xref_show_string;
        self.xref_show_pointer = s.xref_show_pointer;
        self.py_console_preset = s.py_console_preset;
        self.global_find_case_sensitive = s.global_find_case_sensitive;
        self.global_find_scope = s.global_find_scope;
        self.plot_expr = s.plot_expr.clone();
        self.plot_x_min = s.plot_x_min;
        self.plot_x_max = s.plot_x_max;
        self.plot_samples = s.plot_samples;
        self.plot_auto = s.plot_auto;
        self.theme_dirty = true;
    }

    pub fn set_function_name(&mut self, va: u64, name: String) {
        let n = name.trim().to_string();
        if n.is_empty() {
            self.project_db.function_names.remove(&va);
        } else {
            self.project_db.function_names.insert(va, n);
        }
        self.save_db();
    }

    pub fn set_label(&mut self, va: u64, name: String) {
        let n = name.trim().to_string();
        if n.is_empty() {
            self.project_db.labels.remove(&va);
        } else {
            self.project_db.labels.insert(va, n);
        }
        self.save_db();
    }

    pub fn set_comment(&mut self, va: u64, comment: String) {
        let c = comment.trim().to_string();
        if c.is_empty() {
            self.project_db.comments.remove(&va);
        } else {
            self.project_db.comments.insert(va, c);
        }
        self.save_db();
    }

    pub fn focus_xrefs_to(&mut self, va: u64) {
        self.xref_focus_to = Some(va);
        self.xref_mode = 3;
        self.show_tab("Cross References");
    }

    pub fn clear_xref_focus(&mut self) {
        self.xref_focus_to = None;
        if self.xref_mode == 3 {
            self.xref_mode = 0;
        }
    }

    pub fn toggle_bookmark(&mut self, va: u64) {
        if self.project_db.bookmarks.contains(&va) {
            self.project_db.bookmarks.remove(&va);
        } else {
            self.project_db.bookmarks.insert(va);
        }
        self.save_db();
    }

    fn db_path(&self) -> Option<PathBuf> {
        self.workspace_dir.as_ref().map(|d| d.join("db.json"))
    }

    pub fn load_db(&mut self) {
        let Some(path) = self.db_path() else { return; };
        if let Some(db) = ProjectDb::load(&path) {
            self.project_db = db;
        }
    }

    pub fn save_db(&self) {
        let Some(path) = self.db_path() else { return; };
        let _ = self.project_db.save(&path);
    }


fn build_listing(instrs: &[crate::analysis::disasm::Instruction]) -> Vec<ListingRow> {
    let mut rows = Vec::with_capacity(instrs.len());
    for inst in instrs {
        let mut tokens = Vec::new();
        tokens.push(ListingToken { kind: ListingTokenKind::Mnemonic, text: inst.mnemonic.clone(), target: None });
        if !inst.operands.is_empty() {
            tokens.push(ListingToken { kind: ListingTokenKind::Punct, text: " ".to_string(), target: None });
        }
        for (i, op) in inst.operands.iter().enumerate() {
            if i > 0 {
                tokens.push(ListingToken { kind: ListingTokenKind::Punct, text: ", ".to_string(), target: None });
            }
            let low = op.to_lowercase();
            let mut kind = ListingTokenKind::Text;
            if low.starts_with("0x") || low.chars().all(|c| c.is_ascii_hexdigit()) {
                kind = ListingTokenKind::Immediate;
            }
            let regs = [
                "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                "r8","r9","r10","r11","r12","r13","r14","r15",
                "eax","ebx","ecx","edx","esi","edi","ebp","esp",
            ];
            if regs.iter().any(|r| low.contains(r)) {
                kind = ListingTokenKind::Register;
            }
            let mut target = None;
            if inst.is_call || inst.is_jump {
                if let Some(t) = inst.target_address {
                    if op.contains(&format!("{:#x}", t)) || op.contains(&format!("{:#010x}", t)) || op.starts_with("0x") {
                        kind = ListingTokenKind::Address;
                        target = Some(t);
                    }
                }
            }
            if target.is_none() {
                if let Some(t) = inst.ref_address {
                    if op.contains("rip") {
                        kind = ListingTokenKind::Address;
                        target = Some(t);
                    }
                }
            }
            tokens.push(ListingToken { kind, text: op.clone(), target });
        }
        rows.push(ListingRow { address: inst.address, bytes: inst.bytes.clone(), tokens });
    }
    rows
}

    fn build_analysis_views_full(
        instrs: &[crate::analysis::disasm::Instruction],
        strings: &[StringEntry],
        sections: &[LoadedSection],
        is_64: bool,
    ) -> (Vec<String>, Vec<Xref>, Vec<String>, Vec<String>) {
        let regs_all = [
            "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
            "r8","r9","r10","r11","r12","r13","r14","r15",
            "eax","ebx","ecx","edx","esi","edi","ebp","esp",
        ];

        let mut xrefs: Vec<Xref> = Vec::new();
        let mut xref_seen: std::collections::HashSet<(u64, u64, u8)> = std::collections::HashSet::new();
        let mut calls = 0usize;
        let mut jumps = 0usize;

        let mut reads: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
        let mut writes: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();

        let mut sp_delta: i64 = 0;
        let mut stack_lines = Vec::new();

        let mut string_at: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
        for se in strings {
            string_at.insert(se.va, se.text.clone());
        }

        for inst in instrs {
            if inst.is_call {
                calls += 1;
                if let Some(t) = inst.target_address {
                    if xref_seen.insert((inst.address, t, XrefKind::Call as u8)) {
                        xrefs.push(Xref { from: inst.address, to: t, kind: XrefKind::Call, preview: None });
                    }
                } else if let Some(r) = inst.ref_address {
                    if Self::va_in_sections(sections, r) && xref_seen.insert((inst.address, r, XrefKind::Pointer as u8)) {
                        xrefs.push(Xref { from: inst.address, to: r, kind: XrefKind::Pointer, preview: Some("call *[mem]".to_string()) });
                    }
                }
            }
            if inst.is_jump {
                jumps += 1;
                if let Some(t) = inst.target_address {
                    if xref_seen.insert((inst.address, t, XrefKind::Jump as u8)) {
                        xrefs.push(Xref { from: inst.address, to: t, kind: XrefKind::Jump, preview: None });
                    }
                } else if let Some(r) = inst.ref_address {
                    if Self::va_in_sections(sections, r) && xref_seen.insert((inst.address, r, XrefKind::Pointer as u8)) {
                        xrefs.push(Xref { from: inst.address, to: r, kind: XrefKind::Pointer, preview: Some("jmp *[mem]".to_string()) });
                    }
                }
            }

            if let Some(r) = inst.ref_address {
                if Self::va_in_sections(sections, r) {
                    if xref_seen.insert((inst.address, r, XrefKind::Data as u8)) {
                        xrefs.push(Xref { from: inst.address, to: r, kind: XrefKind::Data, preview: None });
                    }

                    if let Some(s) = string_at.get(&r).cloned().or_else(|| Self::read_cstring_at(sections, r, 256)) {
                        if xref_seen.insert((inst.address, r, XrefKind::String as u8)) {
                            xrefs.push(Xref { from: inst.address, to: r, kind: XrefKind::String, preview: Some(s) });
                        }
                    } else if is_64 {
                        if let Some(ptr) = Self::read_u64_at(sections, r) {
                            if ptr != 0 && Self::va_in_sections(sections, ptr) {
                                if xref_seen.insert((inst.address, ptr, XrefKind::Pointer as u8)) {
                                    xrefs.push(Xref { from: inst.address, to: ptr, kind: XrefKind::Pointer, preview: Some(format!("[{:#010x}]", r)) });
                                }
                            }
                        }
                    }
                }
            }

            match inst.mnemonic.as_str() {
                "push" => sp_delta -= 8,
                "pop" => sp_delta += 8,
                _ => {}
            }

            let ops = &inst.operands;
            let mut mark_read = |op: &str| {
                let low = op.to_lowercase();
                for r in regs_all {
                    if low.contains(r) {
                        *reads.entry(r.to_string()).or_insert(0) += 1;
                    }
                }
            };
            let mut mark_write = |op: &str| {
                let low = op.to_lowercase();
                for r in regs_all {
                    if low.contains(r) {
                        *writes.entry(r.to_string()).or_insert(0) += 1;
                    }
                }
            };

            match inst.mnemonic.as_str() {
                "mov" | "lea" => {
                    if ops.len() == 2 {
                        mark_write(&ops[0]);
                        mark_read(&ops[1]);
                    }
                }
                "add" | "sub" => {
                    if ops.len() == 2 {
                        mark_read(&ops[0]);
                        mark_write(&ops[0]);
                        mark_read(&ops[1]);
                    }
                }
                "cmp" => {
                    if ops.len() == 2 {
                        mark_read(&ops[0]);
                        mark_read(&ops[1]);
                    }
                }
                _ => {
                    for op in ops {
                        mark_read(op);
                    }
                }
            }

            if inst.mnemonic == "sub" && inst.operands.get(0).map(|s| s.contains("sp") || s.contains("rsp") || s.contains("esp")).unwrap_or(false) {
                stack_lines.push(format!("{:#010x}: {} {}", inst.address, inst.mnemonic, inst.operands.join(", ")));
            }
        }

        let mut regs_view = Vec::new();
        for r in regs_all {
            let rd = reads.get(r).copied().unwrap_or(0);
            let wr = writes.get(r).copied().unwrap_or(0);
            if rd != 0 || wr != 0 {
                regs_view.push(format!("{:<4}  read {:<5} write {}", r, rd, wr));
            }
        }

        let mut analysis = Vec::new();
        analysis.push("--- Function Summary ---".to_string());
        analysis.push(format!("Instructions: {}", instrs.len()));
        analysis.push(format!("Calls: {}", calls));
        analysis.push(format!("Jumps: {}", jumps));
        analysis.push(format!("Stack delta estimate: {}", sp_delta));
        analysis.push("".to_string());

        let mut indicators: std::collections::HashSet<String> = std::collections::HashSet::new();
        let email_re = Regex::new(r"(?i)\b[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,255}\.[a-z]{2,24}\b").ok();
        let url_re = Regex::new(r#"(?i)\bhttps?://[^\s"'`<>]+"#).ok();
        let guid_re = Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").ok();
        let ipv4_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok();

        let bad_local_suffix = [
            ".dll", ".exe", ".sys", ".ocx", ".so", ".dylib", ".a", ".lib",
        ];
        let good_tlds = [
            "com","net","org","edu","gov","mil","io","co","us","uk","de","fr","ru","cn","jp","kr","info","biz","me","dev","app",
        ];

        for se in strings {
            let t = se.text.as_str();
            let low = t.to_lowercase();

            if let Some(re) = &url_re {
                for m in re.find_iter(t) {
                    indicators.insert(format!("URL: {}", m.as_str()));
                }
            }

            if let Some(re) = &email_re {
                for m in re.find_iter(t) {
                    let e = m.as_str();
                    let parts: Vec<&str> = e.split('@').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    let local = parts[0].to_lowercase();
                    let domain = parts[1].to_lowercase();
                    if local.is_empty() || domain.is_empty() {
                        continue;
                    }
                    if local.starts_with('.') || local.starts_with('_') || local.contains('\\') || local.contains('/') || local.contains(':') {
                        continue;
                    }
                    if bad_local_suffix.iter().any(|s| local.ends_with(s)) {
                        continue;
                    }
                    let tld = domain.rsplit('.').next().unwrap_or("");
                    if !good_tlds.contains(&tld) {
                        continue;
                    }
                    indicators.insert(format!("Email: {}", e));
                }
            }

            if low.contains("\\\\") || low.contains(":\\") {
                indicators.insert(format!("Path: {}", t));
            }
            if low.contains("hkey_") {
                indicators.insert(format!("Registry: {}", t));
            }
            if let Some(re) = &guid_re {
                for m in re.find_iter(t) {
                    indicators.insert(format!("GUID: {}", m.as_str()));
                }
            }
            if let Some(re) = &ipv4_re {
                for m in re.find_iter(t) {
                    indicators.insert(format!("IPv4: {}", m.as_str()));
                }
            }
        }

        if !indicators.is_empty() {
            let mut v: Vec<String> = indicators.into_iter().collect();
            v.sort();
            analysis.push("--- Indicators ---".to_string());
            analysis.extend(v);
        }

        stack_lines.insert(0, format!("Stack delta estimate: {}", sp_delta));

        (analysis, xrefs, regs_view, stack_lines)
    }

    fn va_in_sections(sections: &[LoadedSection], va: u64) -> bool {
        for sec in sections {
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va < end {
                return true;
            }
        }
        false
    }

    fn read_u64_at(sections: &[LoadedSection], va: u64) -> Option<u64> {
        for sec in sections {
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va + 7 < end {
                let off = (va - start) as usize;
                let b = &sec.bytes[off..off + 8];
                return Some(u64::from_le_bytes(b.try_into().ok()?));
            }
        }
        None
    }

    fn read_cstring_at(sections: &[LoadedSection], va: u64, max_len: usize) -> Option<String> {
        for sec in sections {
            let start = sec.start_va;
            let end = start.saturating_add(sec.bytes.len() as u64);
            if va >= start && va < end {
                let mut off = (va - start) as usize;
                let mut out = Vec::new();
                let limit = (off + max_len).min(sec.bytes.len());
                while off < limit {
                    let c = sec.bytes[off];
                    if c == 0 {
                        break;
                    }
                    out.push(c);
                    off += 1;
                }
                if out.len() >= 4 {
                    return Some(String::from_utf8_lossy(&out).into_owned());
                }
            }
        }
        None
    }

    pub fn load_file(&mut self, path: &str) {
        if let Ok(data) = std::fs::read(path) {
            self.file_path = Some(path.to_string());
            self.raw_bytes = data.clone();
            self.hex_dump_len = 0;
            self.hex_dump_text.clear();
            self.extracted_assets.clear();
            self.analysis_data.clear();
            self.analysis_data_text.clear();
            self.file_info.clear();
            self.file_info_text.clear();
            self.strings_list.clear();
            self.strings_text.clear();
            self.imports_list.clear();
            self.imports_text.clear();
            self.exports_list.clear();
            self.exports_text.clear();
            self.functions_list.clear();
            self.functions_text.clear();
            self.xrefs.clear();
            self.xrefs_text.clear();
            self.signatures.clear();
            self.signatures_text.clear();
            self.memory_map.clear();
            self.stack_view.clear();
            self.stack_view_text.clear();
            self.registers_state.clear();
            self.registers_text.clear();
            self.ir_view.clear();
            self.ir_text.clear();
            self.ssa_view.clear();
            self.ssa_text.clear();
            self.loops_text.clear();
            self.types_text.clear();
            self.alias_text.clear();
            self.global_find_results.clear();
            self.global_find_index = 0;
            self.decompiled_c = vec!["/* Analyzing... */".to_string()];
            self.decompiled_c_text = self.decompiled_c.join("\n");
            self.decompiled_rust = vec!["// Analyzing...".to_string()];
            self.decompiled_rust_text = self.decompiled_rust.join("\n");
            self.disassembled_code = vec!["Analyzing binary... please wait.".to_string()];
            self.disassembly_text = self.disassembled_code.join("\n");
            self.disassembly_export_text = self.disassembly_text.clone();
            self.graph_nodes.clear();
            self.is_loading = true;

            let file_name = std::path::Path::new(path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("target");
            let mut safe = String::new();
            for c in file_name.chars() {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    safe.push(c);
                } else {
                    safe.push('_');
                }
            }
            let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("snek_projects");
            let proj_dir = base_dir.join(format!("{}_{}", safe, data.len()));
            let _ = std::fs::create_dir_all(&proj_dir);
            self.workspace_dir = Some(proj_dir.clone());
            self.project_db = ProjectDb::default();
            self.load_db();
            let scripts_dir = proj_dir.join("python_scripts");
            let _ = std::fs::create_dir_all(&scripts_dir);
            let defaults = [
                ("indicators.py", PY_INDICATORS_SCRIPT),
                ("search_strings.py", PY_STRINGS_SEARCH_SCRIPT),
                ("xrefs.py", PY_XREF_REPORT_SCRIPT),
                ("mark_urls.py", PY_MARK_URL_STRINGS_SCRIPT),
            ];
            for (name, src) in defaults {
                let p = scripts_dir.join(name);
                if !p.exists() {
                    let _ = std::fs::write(&p, src.as_bytes());
                }
            }
            if let Ok(pe) = PeParser::new(&data) {
                let mut file_info = vec![];
                file_info.push(format!("File Path: {}", path));
                file_info.push(format!("Architecture: {}", if pe.is_64_bit { "x86_64" } else { "x86" }));
                file_info.push(format!("Entry Point: {:#010x}", pe.entry_point()));
                file_info.push(format!("Image Base: {:#010x}", pe.image_base));
                self.file_info = file_info.clone();
                let _ = self.tx.send(GuiMessage::FileInfoUpdate(file_info));

                self.loaded_sections = pe.sections.iter().map(|s| LoadedSection {
                    name: s.name.clone(),
                    start_va: pe.image_base + s.virtual_address,
                    bytes: s.raw_data.clone(),
                    file_offset: s.raw_offset,
                    executable: s.executable,
                    readable: s.readable,
                    writable: s.writable,
                }).collect();
                if let Some(dir) = &self.workspace_dir {
                    let _ = std::fs::create_dir_all(dir);
                    let _ = std::fs::write(dir.join("file_info.txt"), self.file_info.join("\n"));
                }
                
                self.extracted_assets.push("--- Sections ---".to_string());
                
                let mut strings = vec![];
                
                for sec in &pe.sections {
                    self.extracted_assets.push(format!("{} (Size: {})", sec.name, sec.size));
                    if sec.name == ".rdata" || sec.name == ".data" {
                        let mut current_start: Option<usize> = None;
                        let mut current_str = String::new();
                        for (i, &b) in sec.raw_data.iter().enumerate() {
                            if b.is_ascii_graphic() || b == b' ' {
                                if current_start.is_none() {
                                    current_start = Some(i);
                                }
                                current_str.push(b as char);
                            } else {
                                if current_str.len() >= 4 {
                                    let start = current_start.unwrap_or(0) as u64;
                                    strings.push(StringEntry {
                                        va: pe.image_base + sec.virtual_address + start,
                                        text: current_str.clone(),
                                    });
                                }
                                current_str.clear();
                                current_start = None;
                            }
                        }
                        if current_str.len() >= 4 {
                            let start = current_start.unwrap_or(0) as u64;
                            strings.push(StringEntry {
                                va: pe.image_base + sec.virtual_address + start,
                                text: current_str.clone(),
                            });
                        }
                    }
                }
                
                self.strings_list = strings.clone();
                let _ = self.tx.send(GuiMessage::StringsUpdate(strings.clone()));
                if let Some(dir) = &self.workspace_dir {
                    let _ = std::fs::write(
                        dir.join("strings.txt"),
                        self.strings_list
                            .iter()
                            .map(|s| format!("{:#010x} {}", s.va, s.text))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }

                let mut imports = vec![];
                self.extracted_assets.push("--- Imports ---".to_string());
                for imp in pe.imports() {
                    self.extracted_assets.push(imp.clone());
                    imports.push(imp);
                }
                self.imports_list = imports.clone();
                let _ = self.tx.send(GuiMessage::ImportsUpdate(imports));
                if let Some(dir) = &self.workspace_dir {
                    let _ = std::fs::write(dir.join("imports.txt"), self.imports_list.join("\n"));
                }

                let exports = pe.exports();
                self.exports_list = exports.clone();
                if !exports.is_empty() {
                    self.extracted_assets.push("--- Exports ---".to_string());
                    for e in exports.iter().take(200) {
                        self.extracted_assets.push(e.clone());
                    }
                }
                let _ = self.tx.send(GuiMessage::ExportsUpdate(exports));
                if let Some(dir) = &self.workspace_dir {
                    let _ = std::fs::write(dir.join("exports.txt"), self.exports_list.join("\n"));
                }
                
                let mut entropy_graph = vec![];
                entropy_graph.push("Section Entropy (Shannon):".to_string());
                for sec in &pe.sections {
                    let entropy_val = shannon_entropy(&sec.raw_data);
                    let warn = entropy_val >= 7.5 || sec.name.to_ascii_uppercase().contains("UPX");
                    let bar_len = ((entropy_val / 8.0) * 40.0).round().clamp(0.0, 40.0) as usize;
                    let mut bar = String::new();
                    for _ in 0..bar_len {
                        bar.push('#');
                    }
                    for _ in bar_len..40 {
                        bar.push('-');
                    }
                    entropy_graph.push(format!(
                        "{:<8}  {:>4.2} / 8.00  [{}]{}",
                        sec.name,
                        entropy_val,
                        bar,
                        if warn { "  [HIGH]" } else { "" }
                    ));
                }
                self.signatures = entropy_graph;

                let mut mem_map = vec![];
                mem_map.push("Virtual Address      Size       Protections   Name".to_string());
                mem_map.push("---------------------------------------------------------".to_string());
                for sec in &pe.sections {
                    let mut perms = String::new();
                    if sec.readable { perms.push('R'); } else { perms.push('-'); }
                    if sec.writable { perms.push('W'); } else { perms.push('-'); }
                    if sec.executable { perms.push('X'); } else { perms.push('-'); }
                    
                    mem_map.push(format!("{:#010x}     {:<10} {}          {}", 
                        sec.virtual_address + pe.image_base, 
                        sec.size, 
                        perms, 
                        sec.name
                    ));
                }
                self.memory_map = mem_map;
                if let Some(dir) = &self.workspace_dir {
                    let _ = std::fs::write(dir.join("memory_map.txt"), self.memory_map.join("\n"));
                }

                let entry_rva = pe.entry_point;
                let entry_va = pe.entry_point();

                let mut selected_rva_base: u64 = 0;
                let mut selected_bytes: Vec<u8> = Vec::new();

                for sec in &pe.sections {
                    let start = sec.virtual_address;
                    let end = sec.virtual_address.saturating_add(sec.size.max(sec.raw_data.len() as u64));
                    if entry_rva >= start && entry_rva < end && !sec.raw_data.is_empty() {
                        selected_rva_base = sec.virtual_address;
                        selected_bytes = sec.raw_data.clone();
                        break;
                    }
                }

                if selected_bytes.is_empty() {
                    for sec in &pe.sections {
                        if sec.executable && !sec.raw_data.is_empty() {
                            selected_rva_base = sec.virtual_address;
                            selected_bytes = sec.raw_data.clone();
                            break;
                        }
                    }
                }

                if selected_bytes.is_empty() {
                    for sec in &pe.sections {
                        if !sec.raw_data.is_empty() {
                            selected_rva_base = sec.virtual_address;
                            selected_bytes = sec.raw_data.clone();
                            break;
                        }
                    }
                }

                if !selected_bytes.is_empty() {
                    self.code_bytes = selected_bytes.clone();
                    self.code_base_va = pe.image_base + selected_rva_base;
                    self.is_64_bit = pe.is_64_bit;

                    let tx = self.tx.clone();
                    let is_64 = self.is_64_bit;
                    let sections = self.loaded_sections.clone();
                    thread::spawn(move || {
                        let decoder = X86Decoder::new(if is_64 { Architecture::X86_64 } else { Architecture::X86 });
                        let mut funcs = std::collections::BTreeSet::new();
                        funcs.insert(format!("{:#010x}", entry_va));
                        for sec in &sections {
                            if !sec.executable || sec.bytes.is_empty() {
                                continue;
                            }
                            let scan_len = std::cmp::min(sec.bytes.len(), 1024 * 1024);
                            for f in decoder.identify_functions(&sec.bytes[..scan_len], sec.start_va) {
                                funcs.insert(format!("{:#010x}", f));
                            }
                        }
                        let _ = tx.send(GuiMessage::FunctionsUpdate(funcs.into_iter().collect()));
                    });

                    self.analyze_function(entry_va);

                } else {
                    self.disassembled_code = vec!["No code section found for entry point.".to_string()];
                    self.is_loading = false;
                }

            } else {
                self.disassembled_code = vec!["Failed to parse file as PE.".to_string()];
                self.is_loading = false;
            }
        }
    }

    fn build_graph_layout_static(cfg: &ControlFlowGraph) -> HashMap<u64, GraphNode> {
        let mut graph_nodes = HashMap::new();
        if cfg.blocks.is_empty() { return graph_nodes; }

        let mut layers: HashMap<u64, usize> = HashMap::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((cfg.entry_block, 0));
        
        let mut max_layer = 0;
        
        while let Some((addr, depth)) = queue.pop_front() {
            if layers.contains_key(&addr) {
                continue;
            }
            
            layers.insert(addr, depth);
            max_layer = max_layer.max(depth);
            
            if let Some(block) = cfg.blocks.get(&addr) {
                for &succ in &block.successors {
                    queue.push_back((succ, depth + 1));
                }
            }
        }

        let mut layer_counts = vec![0; max_layer + 1];
        let mut layer_widths: HashMap<usize, f32> = HashMap::new();
        let vertical_spacing = 200.0;
        let horizontal_spacing = 280.0;

        for (addr, _) in &cfg.blocks {
            let layer = *layers.get(addr).unwrap_or(&0);
            *layer_widths.entry(layer).or_insert(0.0) += horizontal_spacing;
        }

        for (i, (addr, block)) in cfg.blocks.iter().enumerate() {
            let layer = *layers.get(addr).unwrap_or(&0);
            if layer >= layer_counts.len() { continue; }
            
            let index_in_layer = layer_counts[layer];
            layer_counts[layer] += 1;

            let mut text = format!("{:#010x}:\n", addr);
            for inst in &block.instructions {
                text.push_str(&format!("{} {}\n", inst.mnemonic, inst.operands.join(", ")));
            }

            let lines = block.instructions.len() + 1;
            let width = 220.0;
            let height = (lines as f32 * 14.0) + 20.0;

            let total_layer_width = layer_widths.get(&layer).unwrap_or(&0.0);
            let start_x = -(*total_layer_width / 2.0);
            let x = start_x + (index_in_layer as f32 * horizontal_spacing);
            let y = layer as f32 * vertical_spacing;

            graph_nodes.insert(*addr, GraphNode {
                text,
                pos: egui::pos2(x + 800.0, y + 100.0),
                size: egui::vec2(width, height),
                successors: block.successors.clone(),
            });

            if i % 100 == 0 {
                std::thread::yield_now();
            }
        }
        graph_nodes
    }
}

pub mod viewer;
pub use viewer::run_gui;
