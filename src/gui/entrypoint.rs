use log::debug;
use std::{
    path::PathBuf,
    str::FromStr,
    thread::{self, JoinHandle},
};

use eframe::egui;

use crate::{
    cli::{Command, SignArgs},
    core,
};

pub fn main() {
    let native_options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "My egui App",
        native_options,
        Box::new(|cc| Ok(Box::new(MyEguiApp::new(cc)))),
    );
}

#[derive(Default)]
pub struct MyEguiApp {
    input: String,
    output: String,
    pin: String,
    handle: Option<JoinHandle<Result<(), core::CoreError>>>,
    status: String,
}

impl MyEguiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_global_style.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        Self::default()
    }
}

impl eframe::App for MyEguiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.input);
                    if ui.button("Browse...").clicked() {
                        if let Some(file) = rfd::FileDialog::new().pick_file() {
                            self.input = file.display().to_string();
                        };
                    }
                });
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.pin).password(false));
                    ui.label("Insert your PIN")
                });
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.output);
                    if ui.button("Browse...").clicked() {
                        if let Some(file) = rfd::FileDialog::new().pick_folder() {
                            self.output = file.display().to_string();
                        };
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Sign").clicked() {
                        let cli = crate::Cli {
                            command: {
                                Command::Sign(SignArgs {
                                    input: PathBuf::from_str(&self.input).unwrap(),
                                    mode: None,
                                    pin: Some(self.pin.clone()),
                                    output: {
                                        if self.output.trim().is_empty() {
                                            None
                                        } else {
                                            Some(PathBuf::from_str(&self.output).unwrap())
                                        }
                                    },
                                    content: None,
                                    detached: false,
                                })
                            },
                        };
                        let Ok(crate::core::Config::Sign(a)) = cli.try_into() else {
                            panic!("The cli I built should have worked")
                        };
                        self.handle = Some(thread::spawn(|| crate::core::sign(a)));
                    };
                    if let Some(handle) = &mut self.handle {
                        if handle.is_finished() {
                            match self.handle.take().unwrap().join().unwrap() {
                                Ok(()) => {
                                    self.status = "Done!".to_string();
                                }
                                Err(e) => {
                                    self.status = "Something went wrong :(".to_string();
                                    debug!("Got error while signing: {e}");
                                }
                            };
                        } else {
                            self.status = "Signing..".to_string();
                        };
                    };
                    ui.label(&self.status);
                });
            });
        });
    }
}
