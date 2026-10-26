// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{error::Error, path::PathBuf, str::FromStr, thread};

use log::debug;
use slint::{Model, ModelRc, SharedString, ToSharedString, VecModel, language::DragAction};

use crate::{
    cli::{Command::Sign, SignArgs},
    core::Config,
};

slint::include_modules!();

pub fn main() -> Result<(), Box<dyn Error>> {
    let ui = MainWindow::new()?;

    let weak = ui.as_weak();
    ui.on_add_files(move || {
        let Some(files) = rfd::FileDialog::new().pick_files() else {
            return;
        };
        let Some(strong) = weak.upgrade() else {
            return;
        };
        strong.set_files(ModelRc::from(
            strong
                .get_files()
                .iter()
                .chain(files.iter().map(|f| f.display().to_shared_string()))
                .collect::<Vec<_>>()
                .as_slice(),
        ));
    });

    let weak = ui.as_weak();
    ui.on_browse_output_dir(move || {
        let Some(folder) = rfd::FileDialog::new()
            .set_can_create_directories(true)
            .pick_folder()
        else {
            return;
        };
        let Some(strong) = weak.upgrade() else {
            return;
        };
        strong.set_output_directory(folder.display().to_shared_string());
    });

    let weak = ui.as_weak();
    ui.on_sign(move |files, pin, output_dir| {
        let files = files
            .iter()
            .map(|ss| PathBuf::from(&ss))
            .collect::<Vec<PathBuf>>();
        let pin = pin.to_string();
        let output_dir = PathBuf::from(&output_dir);
        let weak = weak.clone();
        thread::spawn(move || {
            weak.upgrade_in_event_loop(|strong| {
                strong.set_logs(strong.get_logs() + &format!("Starting signature process...\n"));
            });

            for file in files {
                let cli = crate::Cli {
                    command: Sign(SignArgs {
                        detached: false,
                        content: None,
                        input: file.clone(),
                        mode: None,
                        pin: Some(pin.clone()),
                        output: Some(output_dir.clone()),
                    }),
                };
                weak.upgrade_in_event_loop(move |strong| {
                    strong
                        .set_logs(strong.get_logs() + &format!("Signing {}...\n", file.display()));
                });
                let cfg: crate::Config = Config::try_from(cli).expect("Config should work");
                match cfg {
                    Config::Sign(sign_config) => {
                        if let Err(e) = crate::core::sign(sign_config) {
                            weak.upgrade_in_event_loop(move |strong| {
                                strong.set_logs(
                                    strong.get_logs() + &format!("There was an error: {e:?}\n"),
                                );
                            });
                        } else {
                            weak.upgrade_in_event_loop(move |strong| {
                                strong.set_logs(strong.get_logs() + &format!("Done.\n"));
                            });
                        };
                    }
                    Config::Extract(_) => panic!(),
                    Config::Gui => panic!(),
                }
            }
            weak.upgrade_in_event_loop(move |strong| {
                strong.set_logs(strong.get_logs() + &format!("Finished signing files.\n"));
            });
        });
    });

    ui.run()?;

    Ok(())
}
