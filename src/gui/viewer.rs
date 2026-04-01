use eframe::egui;
use rfd::FileDialog;
use egui_dock::{DockArea, TabViewer};
use super::{SnekReverseApp, UserSettings};

fn parse_hex_va(s: &str) -> Option<u64> {
    let cleaned = s.trim().trim_start_matches("0x");
    u64::from_str_radix(cleaned, 16).ok()
}

fn format_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02X}", b));
    }
    out
}

fn token_color(kind: &crate::gui::ListingTokenKind) -> egui::Color32 {
    match kind {
        crate::gui::ListingTokenKind::Mnemonic => egui::Color32::from_rgb(86, 156, 214),
        crate::gui::ListingTokenKind::Register => egui::Color32::from_rgb(206, 145, 120),
        crate::gui::ListingTokenKind::Immediate => egui::Color32::from_rgb(181, 206, 168),
        crate::gui::ListingTokenKind::Address => egui::Color32::from_rgb(220, 220, 170),
        crate::gui::ListingTokenKind::Punct => egui::Color32::GRAY,
        crate::gui::ListingTokenKind::Text => egui::Color32::LIGHT_GRAY,
    }
}

fn name_for_va(app: &SnekReverseApp, va: u64) -> Option<String> {
    if let Some(l) = app.project_db.labels.get(&va) {
        return Some(l.clone());
    }
    if let Some(n) = app.project_db.function_names.get(&va) {
        return Some(n.clone());
    }
    None
}

fn xref_kind_text(kind: &crate::gui::XrefKind) -> &'static str {
    match kind {
        crate::gui::XrefKind::Call => "call",
        crate::gui::XrefKind::Jump => "jump",
        crate::gui::XrefKind::Data => "data",
        crate::gui::XrefKind::String => "string",
        crate::gui::XrefKind::Pointer => "ptr",
    }
}

fn xref_kind_enabled(app: &SnekReverseApp, kind: &crate::gui::XrefKind) -> bool {
    match kind {
        crate::gui::XrefKind::Call => app.xref_show_call,
        crate::gui::XrefKind::Jump => app.xref_show_jump,
        crate::gui::XrefKind::Data => app.xref_show_data,
        crate::gui::XrefKind::String => app.xref_show_string,
        crate::gui::XrefKind::Pointer => app.xref_show_pointer,
    }
}

fn xref_mode_text(app: &SnekReverseApp) -> String {
    match app.xref_mode {
        1 => "To Cursor".to_string(),
        2 => "From Cursor".to_string(),
        3 => format!("To Focus {}", app.xref_focus_to.map(|v| format!("{:#010x}", v)).unwrap_or_else(|| "-".to_string())),
        _ => "All".to_string(),
    }
}

fn visuals_for(app: &SnekReverseApp) -> egui::Visuals {
    let mut v = match app.theme_mode {
        1 => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };

    v.selection.bg_fill = app.theme_accent;
    v.selection.stroke.color = app.theme_accent;
    v.hyperlink_color = app.theme_accent;

    if app.theme_mode == 2 {
        v.panel_fill = app.theme_panel;
        v.window_fill = app.theme_panel;
        v.extreme_bg_color = app.theme_bg;
        v.faint_bg_color = app.theme_panel;
        v.code_bg_color = app.theme_bg;
        v.override_text_color = Some(app.theme_text);
        v.widgets.noninteractive.bg_fill = app.theme_panel;
        v.widgets.inactive.bg_fill = app.theme_panel;
        v.widgets.hovered.bg_fill = app.theme_bg;
        v.widgets.active.bg_fill = app.theme_bg;
    }

    v
}

struct SnekTabViewer<'a> {
    app: &'a mut SnekReverseApp,
}

impl<'a> TabViewer for SnekTabViewer<'a> {
    type Tab = String;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.clone().into()
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        match tab.as_str() {
            "Assets" => {
                ui.heading("Extracted Assets");
                let mut export = self.app.extracted_assets.join("\n");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(export.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut export)
                        .id_source("assets_export")
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(20),
                );
            }
            "Analysis Data" => {
                ui.heading("Analysis & Cross-References");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.analysis_data_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.analysis_data_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(24),
                );
            }
            "IR" => {
                ui.heading("Intermediate Representation (IR)");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.ir_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.ir_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(24),
                );
            }
            "SSA" => {
                ui.heading("SSA Form");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.ssa_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.ssa_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(24),
                );
            }
            "Loops" => {
                ui.heading("Loops");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.loops_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.loops_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "Types" => {
                ui.heading("Type Inference");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.types_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.types_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "Alias" => {
                ui.heading("Alias Analysis");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.alias_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.alias_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "SNEK Lab" => {
                ui.heading("SNEK Lab");
                ui.horizontal(|ui| {
                    if ui.button("Copy History").clicked() {
                        ui.ctx().copy_text(self.app.lab_history.join("\n"));
                    }
                    if ui.button("Clear").clicked() {
                        self.app.lab_history.clear();
                        self.app.lab_ans = 0.0;
                    }
                    ui.monospace("Calculator + Plotter");
                });
                ui.separator();

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading("Calculator");
                        ui.horizontal(|ui| {
                            ui.label("Expr:");
                            let resp = ui.add(egui::TextEdit::singleline(&mut self.app.lab_expr).desired_width(360.0));
                            let do_eval = ui.button("Eval").clicked()
                                || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                            if do_eval {
                                let mut vars: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
                                vars.insert("ans".to_string(), self.app.lab_ans);
                                match crate::gui::calc::eval_expr(&self.app.lab_expr, &vars) {
                                    Ok(v) => {
                                        self.app.lab_ans = v;
                                        self.app.lab_history.push(format!("{} = {}", self.app.lab_expr.trim(), v));
                                    }
                                    Err(e) => {
                                        self.app.lab_history.push(format!("{} -> error: {}", self.app.lab_expr.trim(), e));
                                    }
                                }
                            }
                        });
                        ui.monospace("vars: ans, pi, e");
                        ui.monospace("funcs: sin cos tan asin acos atan sqrt abs ln log exp floor ceil round pow min max");
                        ui.separator();
                        ui.heading(format!("ans = {}", self.app.lab_ans));
                        egui::ScrollArea::both().auto_shrink([false, false]).max_height(360.0).show(ui, |ui| {
                            for line in self.app.lab_history.iter().rev().take(200) {
                                ui.monospace(line);
                            }
                        });
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        ui.heading("Plotter");
                        ui.horizontal(|ui| {
                            ui.label("f(x) =");
                            ui.add(egui::TextEdit::singleline(&mut self.app.plot_expr).desired_width(300.0));
                        });
                        ui.horizontal(|ui| {
                            ui.label("x_min");
                            ui.add(egui::DragValue::new(&mut self.app.plot_x_min).speed(0.1));
                            ui.label("x_max");
                            ui.add(egui::DragValue::new(&mut self.app.plot_x_max).speed(0.1));
                            ui.label("samples");
                            ui.add(egui::DragValue::new(&mut self.app.plot_samples).speed(1.0));
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.app.plot_auto, "Auto");
                            let changed = self.app.plot_last_expr != self.app.plot_expr
                                || self.app.plot_last_x_min != self.app.plot_x_min
                                || self.app.plot_last_x_max != self.app.plot_x_max
                                || self.app.plot_last_samples != self.app.plot_samples;
                            if ui.button("Plot").clicked() || (self.app.plot_auto && changed) {
                                self.app.compute_plot();
                            }
                            if ui.button("Copy CSV").clicked() {
                                let mut out = String::new();
                                out.push_str("x,y\n");
                                for (x, y) in &self.app.plot_points {
                                    out.push_str(&format!("{},{}\n", x, y));
                                }
                                ui.ctx().copy_text(out);
                            }
                            if !self.app.plot_status.is_empty() {
                                ui.monospace(&self.app.plot_status);
                            }
                        });

                        let desired = egui::vec2(ui.available_width().max(300.0), 420.0);
                        let (rect, resp) = ui.allocate_exact_size(desired, egui::Sense::hover());
                        let painter = ui.painter_at(rect);
                        painter.rect_stroke(rect, 4.0, egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.fg_stroke.color));

                        let mut ymin = f64::INFINITY;
                        let mut ymax = f64::NEG_INFINITY;
                        for (_, y) in &self.app.plot_points {
                            if y.is_finite() {
                                ymin = ymin.min(*y);
                                ymax = ymax.max(*y);
                            }
                        }
                        if !ymin.is_finite() || !ymax.is_finite() || ymin == ymax || self.app.plot_points.is_empty() {
                            painter.text(
                                rect.center(),
                                egui::Align2::CENTER_CENTER,
                                "no data",
                                egui::FontId::monospace(14.0),
                                ui.visuals().text_color(),
                            );
                        } else {
                            let x0 = self.app.plot_x_min;
                            let x1 = self.app.plot_x_max;
                            let ypad = (ymax - ymin) * 0.05;
                            ymin -= ypad;
                            ymax += ypad;

                            let map_x = |x: f64| -> f32 {
                                rect.left() + (((x - x0) / (x1 - x0)) as f32) * rect.width()
                            };
                            let map_y = |y: f64| -> f32 {
                                rect.bottom() - (((y - ymin) / (ymax - ymin)) as f32) * rect.height()
                            };

                            for i in 1..5 {
                                let t = i as f32 / 5.0;
                                let x = rect.left() + rect.width() * t;
                                let y = rect.top() + rect.height() * t;
                                painter.line_segment(
                                    [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                                    egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
                                );
                                painter.line_segment(
                                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                                    egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
                                );
                            }

                            if x0 <= 0.0 && x1 >= 0.0 {
                                let x = map_x(0.0);
                                painter.line_segment(
                                    [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                                    egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.fg_stroke.color),
                                );
                            }
                            if ymin <= 0.0 && ymax >= 0.0 {
                                let y = map_y(0.0);
                                painter.line_segment(
                                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                                    egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.fg_stroke.color),
                                );
                            }

                            let mut seg: Vec<egui::Pos2> = Vec::new();
                            for (x, y) in &self.app.plot_points {
                                if !y.is_finite() {
                                    if seg.len() >= 2 {
                                        painter.add(egui::Shape::line(seg.clone(), egui::Stroke::new(2.0, self.app.theme_accent)));
                                    }
                                    seg.clear();
                                    continue;
                                }
                                seg.push(egui::pos2(map_x(*x), map_y(*y)));
                            }
                            if seg.len() >= 2 {
                                painter.add(egui::Shape::line(seg, egui::Stroke::new(2.0, self.app.theme_accent)));
                            }

                            if resp.hovered() {
                                if let Some(pos) = resp.hover_pos() {
                                    let tx = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0) as f64;
                                    let x = x0 + (x1 - x0) * tx;
                                    let mut vars: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
                                    vars.insert("x".to_string(), x);
                                    vars.insert("ans".to_string(), self.app.lab_ans);
                                    if let Ok(y) = crate::gui::calc::eval_expr(&self.app.plot_expr, &vars) {
                                        painter.circle_stroke(pos, 3.0, egui::Stroke::new(1.0, egui::Color32::WHITE));
                                        painter.text(
                                            pos + egui::vec2(8.0, -8.0),
                                            egui::Align2::LEFT_BOTTOM,
                                            format!("x={:.4} y={:.4}", x, y),
                                            egui::FontId::monospace(12.0),
                                            ui.visuals().text_color(),
                                        );
                                    }
                                }
                            }
                        }
                    });
                });
            }
            "Disassembly" => {
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.disassembly_export_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C in Export");
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.disassembly_export_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(14),
                        );
                    });
                ui.separator();
                if self.app.is_loading {
                    ui.centered_and_justified(|ui| {
                        ui.spinner();
                        ui.heading("Analyzing binary in background... this may take a few seconds.");
                    });
                } else {
                    let mut jump_to: Option<u64> = None;
                    let mut set_cursor: Option<u64> = None;
                    let mut label_for: Option<u64> = None;
                    let mut comment_for: Option<u64> = None;
                    let mut toggle_bm: Option<u64> = None;
                    let row_h = ui.text_style_height(&egui::TextStyle::Monospace).max(18.0);

                    let total = self.app.listing_rows.len();
                    let cursor = self.app.cursor_va;
                    egui::ScrollArea::both().auto_shrink([false, false]).show_rows(ui, row_h, total, |ui, range| {
                        for idx in range {
                            let row = &self.app.listing_rows[idx];
                            let selected = cursor == Some(row.address);
                            if let Some(lbl) = name_for_va(self.app, row.address) {
                                ui.monospace(egui::RichText::new(format!("{}:", lbl)).color(egui::Color32::from_rgb(78, 201, 176)));
                            }
                            ui.horizontal(|ui| {
                                let addr_txt = egui::RichText::new(format!("{:#010x}", row.address)).monospace();
                                let addr_resp = ui.selectable_label(selected, addr_txt);
                                if addr_resp.clicked() {
                                    set_cursor = Some(row.address);
                                }
                                addr_resp.context_menu(|ui| {
                                    if ui.button("Goto").clicked() {
                                        jump_to = Some(row.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Set Label").clicked() {
                                        label_for = Some(row.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Set Comment").clicked() {
                                        comment_for = Some(row.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Toggle Bookmark").clicked() {
                                        toggle_bm = Some(row.address);
                                        ui.close_menu();
                                    }
                                });
                                let bytes_txt = egui::RichText::new(format!("{:<24}", format_bytes(&row.bytes))).monospace().color(egui::Color32::from_rgb(160, 160, 160));
                                ui.label(bytes_txt);
                                for tok in &row.tokens {
                                    if let Some(tgt) = tok.target {
                                        let disp = name_for_va(self.app, tgt).unwrap_or_else(|| tok.text.clone());
                                        let t = egui::RichText::new(disp).monospace().color(token_color(&tok.kind));
                                        let resp = ui.link(t);
                                        if resp.clicked() {
                                            jump_to = Some(tgt);
                                        }
                                        resp.on_hover_text(format!("{:#010x}", tgt));
                                    } else {
                                        let t = egui::RichText::new(&tok.text).monospace().color(token_color(&tok.kind));
                                        ui.label(t);
                                    }
                                }
                                if let Some(c) = self.app.project_db.comments.get(&row.address) {
                                    ui.label(egui::RichText::new(format!(" ; {}", c)).monospace().color(egui::Color32::from_rgb(106, 153, 85)));
                                }
                            });
                        }
                    });
                    if let Some(va) = set_cursor {
                        self.app.cursor_va = Some(va);
                    }
                    if let Some(va) = toggle_bm {
                        self.app.toggle_bookmark(va);
                    }
                    if let Some(va) = label_for {
                        self.app.label_open = true;
                        self.app.label_target = Some(va);
                        self.app.label_input = self.app.project_db.labels.get(&va).cloned().unwrap_or_default();
                    }
                    if let Some(va) = comment_for {
                        self.app.comment_open = true;
                        self.app.comment_target = Some(va);
                        self.app.comment_input = self.app.project_db.comments.get(&va).cloned().unwrap_or_default();
                    }
                    if let Some(va) = jump_to {
                        self.app.goto_any_va(va);
                    }
                }
            }
            "Hex View" => {
                let bytes_per_line = 16;
                let total_lines = self.app.raw_bytes.len() / bytes_per_line;
                let sel_line = self.app.hex_cursor_offset.map(|o| o / bytes_per_line);

                ui.horizontal(|ui| {
                    let off = self.app.hex_cursor_offset.unwrap_or(0);
                    ui.monospace(format!("Offset: 0x{:08X}", off));
                    ui.label("Patch:");
                    ui.text_edit_singleline(&mut self.app.hex_patch_input);
                    if ui.button("Copy Line").clicked() {
                        let o = self.app.hex_cursor_offset.unwrap_or(0);
                        let base = (o / bytes_per_line) * bytes_per_line;
                        let end = (base + bytes_per_line).min(self.app.raw_bytes.len());
                        let chunk = &self.app.raw_bytes[base..end];
                        let hex_str: String = chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                        let ascii_str: String = chunk.iter().map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
                        }).collect();
                        let line = format!("{:08X}  {:<48} |{}|", base, hex_str, ascii_str);
                        ui.ctx().copy_text(line);
                    }
                    if ui.button("Copy Hex Dump").clicked() {
                        let mut out = String::new();
                        let mut row = 0usize;
                        while row * bytes_per_line < self.app.raw_bytes.len() {
                            let base = row * bytes_per_line;
                            let end = (base + bytes_per_line).min(self.app.raw_bytes.len());
                            let chunk = &self.app.raw_bytes[base..end];
                            let hex_str: String = chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                            let ascii_str: String = chunk.iter().map(|&b| {
                                if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
                            }).collect();
                            out.push_str(&format!("{:08X}  {:<48} |{}|\n", base, hex_str, ascii_str));
                            row += 1;
                        }
                        ui.ctx().copy_text(out);
                    }
                    if ui.button("Apply").clicked() {
                        self.app.hex_patch_status = match self.app.patch_hex_cursor() {
                            Ok(()) => "ok".to_string(),
                            Err(e) => e,
                        };
                    }
                    if ui.button("Save Patched As").clicked() {
                        if let Some(path) = FileDialog::new().save_file() {
                            self.app.hex_patch_status = match std::fs::write(&path, &self.app.raw_bytes) {
                                Ok(()) => format!("saved {}", path.to_string_lossy()),
                                Err(e) => format!("{:?}", e),
                            };
                        }
                    }
                    if !self.app.hex_patch_status.is_empty() {
                        ui.monospace(&self.app.hex_patch_status);
                    }
                });

                egui::CollapsingHeader::new("Export (Hex Dump)")
                    .default_open(false)
                    .show(ui, |ui| {
                        if self.app.hex_dump_len == 0 || self.app.hex_dump_len != self.app.raw_bytes.len() {
                            let mut out = String::new();
                            let mut row = 0usize;
                            while row * bytes_per_line < self.app.raw_bytes.len() {
                                let base = row * bytes_per_line;
                                let end = (base + bytes_per_line).min(self.app.raw_bytes.len());
                                let chunk = &self.app.raw_bytes[base..end];
                                let hex_str: String = chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                                let ascii_str: String = chunk.iter().map(|&b| {
                                    if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
                                }).collect();
                                out.push_str(&format!("{:08X}  {:<48} |{}|\n", base, hex_str, ascii_str));
                                row += 1;
                            }
                            self.app.hex_dump_text = out;
                            self.app.hex_dump_len = self.app.raw_bytes.len();
                        }
                        ui.horizontal(|ui| {
                            if ui.button("Copy All").clicked() {
                                ui.ctx().copy_text(self.app.hex_dump_text.clone());
                            }
                            ui.monospace("Ctrl+A, Ctrl+C");
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.hex_dump_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(14),
                        );
                    });
                ui.separator();
                
                egui::ScrollArea::vertical().show_rows(
                    ui,
                    ui.text_style_height(&egui::TextStyle::Monospace),
                    total_lines,
                    |ui, row_range| {
                        for row in row_range {
                            let offset = row * bytes_per_line;
                            let end = (offset + bytes_per_line).min(self.app.raw_bytes.len());
                            let chunk = &self.app.raw_bytes[offset..end];
                            
                            let hex_str: String = chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                            let ascii_str: String = chunk.iter().map(|&b| {
                                if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
                            }).collect();
                            
                            let line = format!("{:08X}  {:<48} |{}|", offset, hex_str, ascii_str);
                            let mut rt = egui::RichText::new(line).monospace();
                            if sel_line == Some(row) {
                                rt = rt.background_color(egui::Color32::from_rgb(40, 60, 90));
                            }
                            let resp = ui.add(egui::Label::new(rt).sense(egui::Sense::click()));
                            if resp.clicked() {
                                self.app.hex_cursor_offset = Some(offset);
                            }
                        }
                    }
                );
            }
            "Decompilation (C/C++)" => {
                ui.heading("Decompilation (C/C++)");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.decompiled_c_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.decompiled_c_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(26),
                );
            }
            "Decompilation (Rust)" => {
                ui.heading("Decompilation (Rust)");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.decompiled_rust_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.decompiled_rust_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(26),
                );
            }
            "Strings" => {
                ui.heading("Strings");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.strings_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                egui::ScrollArea::both().auto_shrink([false, false]).max_height(260.0).show(ui, |ui| {
                    let mut focus: Option<u64> = None;
                    for s in &self.app.strings_list {
                        ui.horizontal(|ui| {
                            let resp = ui.link(egui::RichText::new(format!("{:#010x}", s.va)).monospace());
                            resp.context_menu(|ui| {
                                if ui.button("Show Xrefs").clicked() {
                                    focus = Some(s.va);
                                    ui.close_menu();
                                }
                            });
                            if resp.clicked() {
                                focus = Some(s.va);
                            }
                            ui.monospace(&s.text);
                        });
                    }
                    if let Some(va) = focus {
                        self.app.focus_xrefs_to(va);
                    }
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.strings_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(16),
                        );
                    });
            }
            "Bookmarks" => {
                let bms: Vec<u64> = self.app.project_db.bookmarks.iter().copied().collect();
                let mut export = String::new();
                for va in &bms {
                    let name = name_for_va(self.app, *va).unwrap_or_else(|| format!("sub_{:x}", va));
                    export.push_str(&format!("{:#010x}  {}\n", va, name));
                }
                ui.heading("Bookmarks");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(export.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                egui::ScrollArea::both().auto_shrink([false, false]).max_height(240.0).show(ui, |ui| {
                    for va in bms {
                        let name = name_for_va(self.app, va).unwrap_or_else(|| format!("sub_{:x}", va));
                        if ui.link(egui::RichText::new(format!("{:#010x}  {}", va, name)).monospace()).clicked() {
                            self.app.goto_any_va(va);
                        }
                    }
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut export)
                                .id_source("bookmarks_export")
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(12),
                        );
                    });
            }
            "Functions" => {
                let funcs = self.app.functions_list.clone();
                let selected_va = self.app.selected_function;
                let names = self.app.project_db.function_names.clone();
                let bookmarks = self.app.project_db.bookmarks.clone();
                let mut clicked: Option<u64> = None;
                let mut rename: Option<u64> = None;
                let mut toggle_bm: Option<u64> = None;

                ui.heading("Functions");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.functions_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                egui::ScrollArea::both().auto_shrink([false, false]).max_height(260.0).show(ui, |ui| {
                    for f in &funcs {
                        let Some(addr) = parse_hex_va(f) else { continue; };
                        let name = names.get(&addr).cloned().unwrap_or_else(|| format!("sub_{:x}", addr));
                        let label = if bookmarks.contains(&addr) {
                            format!("* {:#010x}  {}", addr, name)
                        } else {
                            format!("  {:#010x}  {}", addr, name)
                        };
                        let resp = ui.selectable_label(selected_va == Some(addr), egui::RichText::new(label).monospace());
                        resp.context_menu(|ui| {
                            if ui.button("Rename").clicked() {
                                rename = Some(addr);
                                ui.close_menu();
                            }
                            if ui.button("Toggle Bookmark").clicked() {
                                toggle_bm = Some(addr);
                                ui.close_menu();
                            }
                        });
                        if resp.clicked() {
                            clicked = Some(addr);
                        }
                    }
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.functions_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(12),
                        );
                    });
                if let Some(addr) = toggle_bm {
                    self.app.toggle_bookmark(addr);
                }
                if let Some(addr) = rename {
                    self.app.rename_open = true;
                    self.app.rename_target = Some(addr);
                    self.app.rename_input = self.app.project_db.function_names.get(&addr).cloned().unwrap_or_default();
                }
                if let Some(addr) = clicked {
                    self.app.goto_va(addr);
                }
            }
            "File Info" => {
                ui.heading("File Info");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.file_info_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.file_info_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "Logs" => {
                self.app.logs_text = self.app.logs.join("\n");
                ui.heading("Logs");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.logs_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.logs_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(20),
                );
            }
            "Cross References" => {
                let cur = self.app.cursor_va;
                ui.heading("Cross References");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.xrefs_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.xrefs_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(10),
                        );
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(format!("Cursor: {}", cur.map(|v| format!("{:#010x}", v)).unwrap_or_else(|| "-".to_string())));
                    egui::ComboBox::from_id_source("xref_mode")
                        .selected_text(xref_mode_text(self.app))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.app.xref_mode, 0, "All");
                            ui.selectable_value(&mut self.app.xref_mode, 1, "To Cursor");
                            ui.selectable_value(&mut self.app.xref_mode, 2, "From Cursor");
                            if self.app.xref_focus_to.is_some() {
                                ui.selectable_value(&mut self.app.xref_mode, 3, "To Focus");
                            }
                        });
                    if ui.button("Clear Focus").clicked() {
                        self.app.clear_xref_focus();
                    }
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.app.xref_show_call, "Call");
                    ui.checkbox(&mut self.app.xref_show_jump, "Jump");
                    ui.checkbox(&mut self.app.xref_show_data, "Data");
                    ui.checkbox(&mut self.app.xref_show_string, "String");
                    ui.checkbox(&mut self.app.xref_show_pointer, "Ptr");
                    ui.separator();
                    ui.label("Filter:");
                    ui.add(egui::TextEdit::singleline(&mut self.app.xref_query).desired_width(200.0));
                });
                ui.separator();

                let query = self.app.xref_query.trim().to_lowercase();
                let focus_to = self.app.xref_focus_to;
                let mut jump: Option<u64> = None;

                let mut by_kind: Vec<(crate::gui::XrefKind, Vec<&crate::gui::Xref>)> = vec![
                    (crate::gui::XrefKind::Call, Vec::new()),
                    (crate::gui::XrefKind::Jump, Vec::new()),
                    (crate::gui::XrefKind::Data, Vec::new()),
                    (crate::gui::XrefKind::String, Vec::new()),
                    (crate::gui::XrefKind::Pointer, Vec::new()),
                ];

                for x in &self.app.xrefs {
                    if !xref_kind_enabled(self.app, &x.kind) {
                        continue;
                    }
                    match self.app.xref_mode {
                        1 => {
                            if let Some(c) = cur {
                                if x.to != c {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                        2 => {
                            if let Some(c) = cur {
                                if x.from != c {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                        3 => {
                            let Some(t) = focus_to else { continue; };
                            if x.to != t {
                                continue;
                            }
                        }
                        _ => {}
                    }
                    if !query.is_empty() {
                        let mut hay = format!("{:#x} {:#x} {}", x.from, x.to, xref_kind_text(&x.kind));
                        if let Some(p) = &x.preview {
                            hay.push(' ');
                            hay.push_str(p);
                        }
                        if !hay.to_lowercase().contains(&query) {
                            continue;
                        }
                    }
                    for (k, v) in &mut by_kind {
                        if *k == x.kind {
                            v.push(x);
                            break;
                        }
                    }
                }

                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    for (k, xs) in &by_kind {
                        if xs.is_empty() {
                            continue;
                        }
                        ui.heading(format!("{} ({})", xref_kind_text(k), xs.len()));
                        for x in xs {
                            ui.horizontal(|ui| {
                                if ui.link(egui::RichText::new(format!("{:#010x}", x.from)).monospace()).clicked() {
                                    jump = Some(x.from);
                                }
                                ui.label("->");
                                if ui.link(egui::RichText::new(format!("{:#010x}", x.to)).monospace()).clicked() {
                                    jump = Some(x.to);
                                }
                                if let Some(p) = &x.preview {
                                    ui.label(p);
                                }
                            });
                        }
                        ui.separator();
                    }
                });

                if let Some(va) = jump {
                    self.app.goto_any_va(va);
                }
            }
            "Entropy Graph" => {
                self.app.signatures_text = self.app.signatures.join("\n");
                ui.heading("Entropy Graph");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.signatures_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.signatures_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(16),
                );
            }
            "Symbol Tree" => {
                let mut export = String::new();
                export.push_str("Sections\n");
                for sec in &self.app.loaded_sections {
                    export.push_str(&format!("{}  {:#010x}  size {}\n", sec.name, sec.start_va, sec.bytes.len()));
                }
                export.push_str("\nFunctions\n");
                for s in &self.app.functions_list {
                    let va = parse_hex_va(s).unwrap_or(0);
                    let nm = name_for_va(self.app, va).unwrap_or_else(|| format!("sub_{:x}", va));
                    export.push_str(&format!("{:#010x}  {}\n", va, nm));
                }
                export.push_str("\nImports\n");
                for s in &self.app.imports_list {
                    export.push_str(s);
                    export.push('\n');
                }
                export.push_str("\nExports\n");
                for s in &self.app.exports_list {
                    export.push_str(s);
                    export.push('\n');
                }
                export.push_str("\nStrings\n");
                for s in &self.app.strings_list {
                    export.push_str(&format!("{:#010x}  {}\n", s.va, s.text));
                }
                export.push_str("\nBookmarks\n");
                let bms: Vec<u64> = self.app.project_db.bookmarks.iter().copied().collect();
                for va in bms {
                    let nm = name_for_va(self.app, va).unwrap_or_else(|| format!("sub_{:x}", va));
                    export.push_str(&format!("{:#010x}  {}\n", va, nm));
                }
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(export.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                egui::CollapsingHeader::new("Export")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut export)
                                .id_source("symbol_tree_export")
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(12),
                        );
                    });
                ui.separator();
                let q = self.app.symbol_filter.trim().to_lowercase();
                ui.horizontal(|ui| {
                    ui.label("Filter:");
                    ui.text_edit_singleline(&mut self.app.symbol_filter);
                    if ui.button("Clear").clicked() {
                        self.app.symbol_filter.clear();
                    }
                });
                ui.separator();

                let mut goto: Option<u64> = None;
                let mut focus_xrefs: Option<u64> = None;

                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    egui::CollapsingHeader::new("Sections").default_open(true).show(ui, |ui| {
                        for sec in &self.app.loaded_sections {
                            let name = format!("{}  {:#010x}  size {}", sec.name, sec.start_va, sec.bytes.len());
                            if !q.is_empty() && !name.to_lowercase().contains(&q) {
                                continue;
                            }
                            if ui.link(egui::RichText::new(name).monospace()).clicked() {
                                goto = Some(sec.start_va);
                            }
                        }
                    });

                    egui::CollapsingHeader::new("Functions").default_open(true).show(ui, |ui| {
                        for s in &self.app.functions_list {
                            let va = parse_hex_va(s).unwrap_or(0);
                            let nm = name_for_va(self.app, va).unwrap_or_else(|| format!("sub_{:x}", va));
                            let row = format!("{:#010x}  {}", va, nm);
                            if !q.is_empty() && !row.to_lowercase().contains(&q) {
                                continue;
                            }
                            if ui.link(egui::RichText::new(row).monospace()).clicked() {
                                goto = Some(va);
                            }
                        }
                    });

                    egui::CollapsingHeader::new("Imports").default_open(false).show(ui, |ui| {
                        for s in &self.app.imports_list {
                            if !q.is_empty() && !s.to_lowercase().contains(&q) {
                                continue;
                            }
                            ui.monospace(s);
                        }
                    });

                    egui::CollapsingHeader::new("Exports").default_open(false).show(ui, |ui| {
                        for s in &self.app.exports_list {
                            if !q.is_empty() && !s.to_lowercase().contains(&q) {
                                continue;
                            }
                            ui.monospace(s);
                        }
                    });

                    egui::CollapsingHeader::new("Strings").default_open(false).show(ui, |ui| {
                        for s in &self.app.strings_list {
                            let row = format!("{:#010x}  {}", s.va, s.text);
                            if !q.is_empty() && !row.to_lowercase().contains(&q) {
                                continue;
                            }
                            ui.horizontal(|ui| {
                                if ui.link(egui::RichText::new(format!("{:#010x}", s.va)).monospace()).clicked() {
                                    focus_xrefs = Some(s.va);
                                }
                                ui.monospace(&s.text);
                            });
                        }
                    });

                    egui::CollapsingHeader::new("Bookmarks").default_open(false).show(ui, |ui| {
                        let bms: Vec<u64> = self.app.project_db.bookmarks.iter().copied().collect();
                        for va in bms {
                            let nm = name_for_va(self.app, va).unwrap_or_else(|| format!("sub_{:x}", va));
                            let row = format!("{:#010x}  {}", va, nm);
                            if !q.is_empty() && !row.to_lowercase().contains(&q) {
                                continue;
                            }
                            if ui.link(egui::RichText::new(row).monospace()).clicked() {
                                goto = Some(va);
                            }
                        }
                    });

                    egui::CollapsingHeader::new("Workspace").default_open(false).show(ui, |ui| {
                        if let Some(dir) = &self.app.workspace_dir {
                            ui.monospace(format!("Dir: {}", dir.to_string_lossy()));
                            let scripts = self.app.list_python_scripts();
                            ui.monospace(format!("python_scripts: {}", scripts.len()));
                            for p in scripts.into_iter().take(50) {
                                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("script.py");
                                let row = format!("py: {}", name);
                                if !q.is_empty() && !row.to_lowercase().contains(&q) {
                                    continue;
                                }
                                if ui.link(egui::RichText::new(row).monospace()).clicked() {
                                    self.app.show_tab("Python Console");
                                    self.app.load_python_script(p);
                                }
                            }
                        } else {
                            ui.monospace("(no workspace yet)");
                        }
                    });
                });

                if let Some(va) = focus_xrefs {
                    self.app.focus_xrefs_to(va);
                }
                if let Some(va) = goto {
                    self.app.goto_any_va(va);
                }
            }
            "Imports" => {
                ui.heading("Imports");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.imports_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.imports_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(22),
                );
            }
            "Exports" => {
                ui.heading("Exports");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.exports_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.exports_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(22),
                );
            }
            "Registers" => {
                ui.heading("Registers");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.registers_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.registers_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "Stack View" => {
                ui.heading("Stack View");
                ui.horizontal(|ui| {
                    if ui.button("Copy All").clicked() {
                        ui.ctx().copy_text(self.app.stack_view_text.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                ui.separator();
                ui.add(
                    egui::TextEdit::multiline(&mut self.app.stack_view_text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(18),
                );
            }
            "Python Console" => {
                let presets = self.app.python_presets();
                let sel = self.app.py_console_preset.min(presets.len().saturating_sub(1));
                let scripts = self.app.list_python_scripts();

                ui.horizontal(|ui| {
                    egui::ComboBox::from_label("Script")
                        .selected_text(presets[sel].0)
                        .show_ui(ui, |ui| {
                            for (i, (name, _)) in presets.iter().enumerate() {
                                ui.selectable_value(&mut self.app.py_console_preset, i, *name);
                            }
                        });

                    if ui.add_enabled(!self.app.py_console_running, egui::Button::new("Run")).clicked() {
                        self.app.run_python_console();
                    }
                    if ui.button("Load Preset").clicked() {
                        self.app.py_console_file = None;
                        self.app.py_console_code = presets[sel].1.to_string();
                    }
                    if ui.add_enabled(self.app.py_console_file.is_some(), egui::Button::new("Save")).clicked() {
                        let _ = self.app.save_python_script();
                    }
                    if ui.button("Save As").clicked() {
                        let mut dlg = FileDialog::new();
                        if let Some(dir) = self.app.python_scripts_dir() {
                            dlg = dlg.set_directory(dir);
                        }
                        if let Some(path) = dlg.add_filter("Python", &["py"]).save_file() {
                            self.app.py_console_file = Some(path.clone());
                            let _ = self.app.save_python_script();
                        }
                    }
                    if ui.button("Clear").clicked() {
                        self.app.py_console_stdout.clear();
                        self.app.py_console_stderr.clear();
                        self.app.py_console_stdout_text.clear();
                        self.app.py_console_stderr_text.clear();
                        self.app.py_console_status.clear();
                    }
                });

                if sel == 2 {
                    ui.horizontal(|ui| {
                        ui.label("Query:");
                        ui.text_edit_singleline(&mut self.app.py_console_query);
                    });
                }
                if sel == 3 {
                    ui.horizontal(|ui| {
                        ui.label("Kind:");
                        ui.text_edit_singleline(&mut self.app.py_console_kind);
                    });
                }

                ui.separator();

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.monospace("Workspace scripts");
                        egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            if scripts.is_empty() {
                                ui.monospace("(no scripts in workspace)");
                            }
                            for p in scripts {
                                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("script.py");
                                let selected = self.app.py_console_file.as_ref().map(|x| x == &p).unwrap_or(false);
                                if ui.selectable_label(selected, name).clicked() {
                                    self.app.load_python_script(p);
                                }
                            }
                        });
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        if let Some(p) = &self.app.py_console_file {
                            ui.monospace(format!("File: {}", p.to_string_lossy()));
                        } else {
                            ui.monospace("File: (not saved)");
                        }
                        ui.monospace("Env: SNEK_CONTEXT, SNEK_FILE_PATH, SNEK_WORKSPACE_DIR, SNEK_FUNCTION_VA");
                        ui.monospace("Cmd: print('SNEK_CMD {\"op\":\"goto\",\"va\":\"0x140001000\"}')");
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.py_console_code)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(12),
                        );
                    });
                });

                egui::CollapsingHeader::new("Env Vars").default_open(false).show(ui, |ui| {
                    let mut remove: Option<usize> = None;
                    for (i, (k, v)) in self.app.py_console_env.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(k);
                            ui.text_edit_singleline(v);
                            if ui.button("X").clicked() {
                                remove = Some(i);
                            }
                        });
                    }
                    if let Some(i) = remove {
                        self.app.py_console_env.remove(i);
                    }
                    if ui.button("Add").clicked() {
                        self.app.py_console_env.push((String::new(), String::new()));
                    }
                });

                ui.separator();

                ui.monospace(format!("Status: {}", if self.app.py_console_status.is_empty() { "ready" } else { &self.app.py_console_status }));
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.monospace("stdout");
                        ui.horizontal(|ui| {
                            if ui.button("Copy").clicked() {
                                ui.ctx().copy_text(self.app.py_console_stdout_text.clone());
                            }
                            ui.monospace("Ctrl+A, Ctrl+C");
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.py_console_stdout_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(8),
                        );
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        ui.monospace("stderr");
                        ui.horizontal(|ui| {
                            if ui.button("Copy").clicked() {
                                ui.ctx().copy_text(self.app.py_console_stderr_text.clone());
                            }
                            ui.monospace("Ctrl+A, Ctrl+C");
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut self.app.py_console_stderr_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(8),
                        );
                    });
                });
            }
            "Graph View" => {
                let mut dot = String::new();
                dot.push_str("digraph cfg {\n");
                for (addr, node) in &self.app.graph_nodes {
                    let lbl = node.text.replace('"', "\\\"");
                    dot.push_str(&format!("  n_{:x} [label=\"{}\"];\n", addr, lbl));
                }
                for (addr, node) in &self.app.graph_nodes {
                    for succ in &node.successors {
                        dot.push_str(&format!("  n_{:x} -> n_{:x};\n", addr, succ));
                    }
                }
                dot.push_str("}\n");
                ui.horizontal(|ui| {
                    if ui.button("Copy CFG (DOT)").clicked() {
                        ui.ctx().copy_text(dot.clone());
                    }
                    ui.monospace("Ctrl+A, Ctrl+C");
                });
                egui::CollapsingHeader::new("Export (DOT)")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut dot)
                                .id_source("graph_dot_export")
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(10),
                        );
                    });
                ui.separator();
                let (response, painter) = ui.allocate_painter(ui.available_size(), egui::Sense::click_and_drag());
                
                if response.hovered() {
                    let scroll = ui.input(|i| i.raw_scroll_delta.y);
                    if scroll != 0.0 {
                        self.app.zoom_level += scroll * 0.001;
                        self.app.zoom_level = self.app.zoom_level.clamp(0.1, 3.0);
                    }
                }

                if response.dragged_by(egui::PointerButton::Middle) || (response.dragged() && self.app.dragging_node.is_none()) {
                    self.app.pan_offset += response.drag_delta() / self.app.zoom_level;
                }

                let offset = self.app.pan_offset;
                let zoom = self.app.zoom_level;

                let transform = |pos: egui::Pos2| -> egui::Pos2 {
                    let center = response.rect.center();
                    let scaled_pos = (pos.to_vec2() + offset) * zoom;
                    center + scaled_pos
                };

                for node in self.app.graph_nodes.values() {
                    for succ_addr in &node.successors {
                        if let Some(succ_node) = self.app.graph_nodes.get(succ_addr) {
                            let start = transform(node.pos + egui::vec2(node.size.x / 2.0, node.size.y));
                            let end = transform(succ_node.pos + egui::vec2(succ_node.size.x / 2.0, 0.0));
                            let stroke = egui::Stroke::new(2.0 * zoom, egui::Color32::from_rgb(100, 150, 200));
                            painter.line_segment([start, end], stroke);
                            
                            let dir = (end - start).normalized();
                            let arrow_size = 8.0 * zoom;
                            let arrow_pt1 = end - dir * arrow_size + dir.rot90() * (arrow_size / 2.0);
                            let arrow_pt2 = end - dir * arrow_size - dir.rot90() * (arrow_size / 2.0);
                            painter.add(egui::Shape::convex_polygon(
                                vec![end, arrow_pt1, arrow_pt2],
                                egui::Color32::from_rgb(100, 150, 200),
                                egui::Stroke::NONE,
                            ));
                        }
                    }
                }

                if let Some(pointer_pos) = response.interact_pointer_pos() {
                    if response.drag_started() {
                        for (addr, node) in &self.app.graph_nodes {
                            let screen_rect = egui::Rect::from_min_size(transform(node.pos), node.size * zoom);
                            if screen_rect.contains(pointer_pos) {
                                self.app.dragging_node = Some(*addr);
                                break;
                            }
                        }
                    }
                }

                if response.drag_stopped() {
                    self.app.dragging_node = None;
                }

                if let Some(dragged_addr) = self.app.dragging_node {
                    if response.dragged() {
                        if let Some(node) = self.app.graph_nodes.get_mut(&dragged_addr) {
                            node.pos += response.drag_delta() / zoom;
                        }
                    }
                }

                for (addr, node) in &self.app.graph_nodes {
                    let screen_pos = transform(node.pos);
                    let screen_size = node.size * zoom;
                    let rect = egui::Rect::from_min_size(screen_pos, screen_size);
                    
                    let bg_color = if self.app.dragging_node == Some(*addr) {
                        egui::Color32::from_rgb(60, 60, 80)
                    } else {
                        egui::Color32::from_rgb(40, 40, 40)
                    };

                    painter.rect_filled(rect, 5.0 * zoom, bg_color);
                    painter.rect_stroke(rect, 5.0 * zoom, egui::Stroke::new(1.0 * zoom, egui::Color32::GRAY));
                    
                    painter.text(
                        rect.min + (egui::vec2(10.0, 10.0) * zoom),
                        egui::Align2::LEFT_TOP,
                        &node.text,
                        egui::FontId::monospace(12.0 * zoom),
                        egui::Color32::WHITE,
                    );
                }
            }
            _ => { ui.label("Unknown Tab"); }
        }
    }
}

impl eframe::App for SnekReverseApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if let Ok(s) = serde_json::to_string(&self.to_settings()) {
            storage.set_string("user_settings", s);
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_state();

        if !self.ui_inited || self.theme_dirty {
            ctx.set_visuals(visuals_for(self));
            self.ui_inited = true;
            self.theme_dirty = false;
        }

        if ctx.input(|i| i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::F)) {
            self.search_open = true;
        }
        if ctx.input(|i| i.modifiers.ctrl && !i.modifiers.shift && i.key_pressed(egui::Key::F)) {
            self.global_find_open = true;
        }
        if ctx.input(|i| i.key_pressed(egui::Key::F3) && !i.modifiers.shift) {
            self.search_next();
        }
        if ctx.input(|i| i.key_pressed(egui::Key::F3) && i.modifiers.shift) {
            self.search_prev();
        }
        if ctx.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft)) {
            self.navigate_back();
        }
        if ctx.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight)) {
            self.navigate_forward();
        }
        
        if self.is_loading {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open Binary...").clicked() {
                        if let Some(path) = FileDialog::new().pick_file() {
                            let path_str = path.display().to_string();
                            self.load_file(&path_str);
                        }
                    }
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                
                ui.menu_button("View", |ui| {
                    if ui.button("Appearance...").clicked() { self.appearance_open = true; ui.close_menu(); }
                    ui.separator();
                    if ui.button("Reset Layout (Simple)").clicked() { self.reset_layout(true); ui.close_menu(); }
                    if ui.button("Reset Layout (Advanced)").clicked() { self.reset_layout(false); ui.close_menu(); }
                    ui.separator();
                    if ui.button("Disassembly").clicked() { self.show_tab("Disassembly"); ui.close_menu(); }
                    if ui.button("Decompilation (C/C++)").clicked() { self.show_tab("Decompilation (C/C++)"); ui.close_menu(); }
                    if ui.button("Decompilation (Rust)").clicked() { self.show_tab("Decompilation (Rust)"); ui.close_menu(); }
                    if ui.button("Hex View").clicked() { self.show_tab("Hex View"); ui.close_menu(); }
                    if ui.button("Graph View").clicked() { self.show_tab("Graph View"); ui.close_menu(); }
                    if ui.button("Functions").clicked() { self.show_tab("Functions"); ui.close_menu(); }
                    if ui.button("Strings").clicked() { self.show_tab("Strings"); ui.close_menu(); }
                    if ui.button("Cross References").clicked() { self.show_tab("Cross References"); ui.close_menu(); }
                    if ui.button("Python Console").clicked() { self.show_tab("Python Console"); ui.close_menu(); }
                    if ui.button("Logs").clicked() { self.show_tab("Logs"); ui.close_menu(); }
                    if ui.button("SNEK Lab").clicked() { self.show_tab("SNEK Lab"); ui.close_menu(); }
                    ui.separator();
                    ui.menu_button("Advanced Tabs", |ui| {
                        if ui.button("Analysis Data").clicked() { self.show_tab("Analysis Data"); ui.close_menu(); }
                        if ui.button("IR").clicked() { self.show_tab("IR"); ui.close_menu(); }
                        if ui.button("SSA").clicked() { self.show_tab("SSA"); ui.close_menu(); }
                        if ui.button("Loops").clicked() { self.show_tab("Loops"); ui.close_menu(); }
                        if ui.button("Types").clicked() { self.show_tab("Types"); ui.close_menu(); }
                        if ui.button("Alias").clicked() { self.show_tab("Alias"); ui.close_menu(); }
                        ui.separator();
                        if ui.button("Registers").clicked() { self.show_tab("Registers"); ui.close_menu(); }
                        if ui.button("Stack View").clicked() { self.show_tab("Stack View"); ui.close_menu(); }
                        if ui.button("Imports").clicked() { self.show_tab("Imports"); ui.close_menu(); }
                        if ui.button("Exports").clicked() { self.show_tab("Exports"); ui.close_menu(); }
                        if ui.button("Bookmarks").clicked() { self.show_tab("Bookmarks"); ui.close_menu(); }
                        if ui.button("Symbol Tree").clicked() { self.show_tab("Symbol Tree"); ui.close_menu(); }
                        if ui.button("Assets").clicked() { self.show_tab("Assets"); ui.close_menu(); }
                        if ui.button("Entropy Graph").clicked() { self.show_tab("Entropy Graph"); ui.close_menu(); }
                    });
                });

                ui.menu_button("Navigate", |ui| {
                    if ui.button("Back").clicked() {
                        self.navigate_back();
                        ui.close_menu();
                    }
                    if ui.button("Forward").clicked() {
                        self.navigate_forward();
                        ui.close_menu();
                    }
                    if ui.button("Goto Address...").clicked() {
                        self.goto_open = true;
                        ui.close_menu();
                    }
                    if ui.button("Find...").clicked() {
                        self.global_find_open = true;
                        ui.close_menu();
                    }
                    if ui.button("Find in Disassembly...").clicked() {
                        self.search_open = true;
                        ui.close_menu();
                    }
                    if ui.button("Current Function").clicked() {
                        if let Some(va) = self.selected_function {
                            self.goto_va(va);
                        }
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Appearance").clicked() {
                        self.appearance_open = true;
                    }
                    if ui.button(if self.theme_mode == 1 { "Dark" } else { "Light" }).clicked() {
                        self.theme_mode = if self.theme_mode == 1 { 0 } else { 1 };
                        self.theme_dirty = true;
                    }
                    let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().rect_filled(r, 2.0, self.theme_accent);
                    ui.monospace("SNEK");
                });
            });
        });

        if self.goto_open {
            let mut open = self.goto_open;
            let mut goto_target: Option<u64> = None;
            let mut should_close = false;
            egui::Window::new("Goto Address")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Enter a virtual address (hex), e.g. 140001000 or 0x140001000");
                    let resp = ui.add(egui::TextEdit::singleline(&mut self.goto_input).desired_width(300.0));
                    let go = ui.button("Go").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if go {
                        let cleaned = self.goto_input.trim().trim_start_matches("0x");
                        if let Ok(va) = u64::from_str_radix(cleaned, 16) {
                            goto_target = Some(va);
                            should_close = true;
                        }
                    }
                });
            if should_close {
                open = false;
            }
            self.goto_open = open;
            if let Some(va) = goto_target {
                self.goto_any_va(va);
            }
        }

        if self.appearance_open {
            let mut open = self.appearance_open;
            let mut dirty = false;
            egui::Window::new("Appearance")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    let old_mode = self.theme_mode;
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.theme_mode, 0, "Dark");
                        ui.selectable_value(&mut self.theme_mode, 1, "Light");
                        ui.selectable_value(&mut self.theme_mode, 2, "Custom");
                    });
                    if self.theme_mode != old_mode {
                        dirty = true;
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Accent");
                        dirty |= ui.color_edit_button_srgba(&mut self.theme_accent).changed();
                    });
                    if self.theme_mode == 2 {
                        ui.horizontal(|ui| {
                            ui.label("Background");
                            dirty |= ui.color_edit_button_srgba(&mut self.theme_bg).changed();
                        });
                        ui.horizontal(|ui| {
                            ui.label("Panel");
                            dirty |= ui.color_edit_button_srgba(&mut self.theme_panel).changed();
                        });
                        ui.horizontal(|ui| {
                            ui.label("Text");
                            dirty |= ui.color_edit_button_srgba(&mut self.theme_text).changed();
                        });
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Simple Layout").clicked() {
                            self.reset_layout(true);
                        }
                        if ui.button("Advanced Layout").clicked() {
                            self.reset_layout(false);
                        }
                    });
                });
            self.appearance_open = open;
            if dirty {
                self.theme_dirty = true;
            }
        }

        if self.global_find_open {
            let mut open = self.global_find_open;
            let mut apply = false;
            let mut do_prev = false;
            let mut do_next = false;
            egui::Window::new("Find")
                .collapsible(false)
                .resizable(true)
                .open(&mut open)
                .show(ctx, |ui| {
                    let scopes = SnekReverseApp::global_find_scopes();
                    ui.horizontal(|ui| {
                        ui.label("Query:");
                        let resp = ui.add(egui::TextEdit::singleline(&mut self.global_find_query).desired_width(260.0));
                        let go = ui.button("Search").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if go {
                            apply = true;
                        }
                    });
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_label("Scope")
                            .selected_text(scopes.get(self.global_find_scope).copied().unwrap_or("All Tabs"))
                            .show_ui(ui, |ui| {
                                for (i, s) in scopes.iter().enumerate() {
                                    ui.selectable_value(&mut self.global_find_scope, i, *s);
                                }
                            });
                        ui.checkbox(&mut self.global_find_case_sensitive, "Case sensitive");
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Prev").clicked() {
                            do_prev = true;
                        }
                        if ui.button("Next").clicked() {
                            do_next = true;
                        }
                        ui.label(format!("{} hits", self.global_find_results.len()));
                        if !self.global_find_results.is_empty() {
                            ui.label(format!(
                                "showing {}",
                                (self.global_find_index + 1).min(self.global_find_results.len())
                            ));
                        }
                    });
                    ui.separator();
                    let mut goto: Option<u64> = None;
                    let mut copy_line: Option<String> = None;
                    egui::ScrollArea::both().auto_shrink([false, false]).max_height(420.0).show(ui, |ui| {
                        for i in 0..self.global_find_results.len() {
                            let hit = self.global_find_results[i].clone();
                            let selected = i == self.global_find_index;
                            let text = hit.text.clone();
                            let va = hit.va;
                            let resp = ui.selectable_label(selected, egui::RichText::new(&text).monospace());
                            if resp.clicked() {
                                self.global_find_index = i;
                                goto = va;
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Copy line").clicked() {
                                    copy_line = Some(text.clone());
                                    ui.close_menu();
                                }
                                if let Some(va) = va {
                                    if ui.button("Goto VA").clicked() {
                                        goto = Some(va);
                                        ui.close_menu();
                                    }
                                }
                            });
                        }
                    });
                    if let Some(t) = copy_line {
                        ui.ctx().copy_text(t);
                    }
                    if let Some(va) = goto {
                        self.goto_any_va(va);
                    }
                });
            self.global_find_open = open;
            if apply {
                self.apply_global_find();
            }
            if do_prev && !self.global_find_results.is_empty() {
                if self.global_find_index == 0 {
                    self.global_find_index = self.global_find_results.len() - 1;
                } else {
                    self.global_find_index -= 1;
                }
            }
            if do_next && !self.global_find_results.is_empty() {
                self.global_find_index = (self.global_find_index + 1) % self.global_find_results.len();
            }
            if (do_prev || do_next) && !self.global_find_results.is_empty() {
                if let Some(hit) = self.global_find_results.get(self.global_find_index) {
                    if let Some(va) = hit.va {
                        self.goto_any_va(va);
                    }
                }
            }
        }

        if self.search_open {
            let mut open = self.search_open;
            let mut apply = false;
            let mut do_prev = false;
            let mut do_next = false;
            egui::Window::new("Find")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Search in current function listing");
                    let resp = ui.add(egui::TextEdit::singleline(&mut self.search_query).desired_width(300.0));
                    let go = ui.button("Search").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if go {
                        apply = true;
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Prev").clicked() {
                            do_prev = true;
                        }
                        if ui.button("Next").clicked() {
                            do_next = true;
                        }
                        ui.label(format!("{} hits", self.search_hits.len()));
                    });
                });
            self.search_open = open;
            if apply {
                self.apply_search();
            }
            if do_prev {
                self.search_prev();
            }
            if do_next {
                self.search_next();
            }
        }

        if self.rename_open {
            let mut open = self.rename_open;
            let mut should_apply = false;
            let target = self.rename_target;
            egui::Window::new("Rename Function")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Enter a new name");
                    let resp = ui.add(egui::TextEdit::singleline(&mut self.rename_input).desired_width(300.0));
                    let ok = ui.button("Apply").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ok {
                        should_apply = true;
                    }
                });
            self.rename_open = open;
            if should_apply {
                if let Some(va) = target {
                    self.set_function_name(va, self.rename_input.clone());
                }
                self.rename_open = false;
            }
        }

        if self.label_open {
            let mut open = self.label_open;
            let mut should_apply = false;
            let target = self.label_target;
            egui::Window::new("Set Label")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Enter a label");
                    let resp = ui.add(egui::TextEdit::singleline(&mut self.label_input).desired_width(300.0));
                    let ok = ui.button("Apply").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ok {
                        should_apply = true;
                    }
                });
            self.label_open = open;
            if should_apply {
                if let Some(va) = target {
                    self.set_label(va, self.label_input.clone());
                }
                self.label_open = false;
            }
        }

        if self.comment_open {
            let mut open = self.comment_open;
            let mut should_apply = false;
            let target = self.comment_target;
            egui::Window::new("Set Comment")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Enter a comment");
                    let resp = ui.add(egui::TextEdit::singleline(&mut self.comment_input).desired_width(400.0));
                    let ok = ui.button("Apply").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ok {
                        should_apply = true;
                    }
                });
            self.comment_open = open;
            if should_apply {
                if let Some(va) = target {
                    self.set_comment(va, self.comment_input.clone());
                }
                self.comment_open = false;
            }
        }

        let mut tree = self.tree.clone();
        let mut viewer = SnekTabViewer { app: self };
        egui::CentralPanel::default().show(ctx, |ui| {
            DockArea::new(&mut tree)
                .style(egui_dock::Style::from_egui(ctx.style().as_ref()))
                .show_inside(ui, &mut viewer);
        });
        self.tree = tree;
    }
}

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1600.0, 1000.0])
            .with_title("SNEK Reverse"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "SNEK Reverse",
        options,
        Box::new(|cc| {
            let mut app = SnekReverseApp::default();
            if let Some(storage) = cc.storage {
                if let Some(json) = storage.get_string("user_settings") {
                    if let Ok(s) = serde_json::from_str::<UserSettings>(&json) {
                        app.apply_settings(&s);
                        app.reset_layout(app.simple_layout);
                    }
                }
            }
            Box::new(app)
        }),
    )
}
