// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{error::Error, path::PathBuf, thread};

use anyhow::Context;
use slint::{Model, ModelRc, ToSharedString};

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
            log(&weak, "Starting signature process...");

            if let Err(e) = sign_files(&weak, &files, &pin, output_dir) {
                log(&weak, format!("Error: {e:?}"));
            }

            log(&weak, format!("Finished signing files."));
        });
    });

    ui.run()?;

    Ok(())
}

fn log(ui: &slint::Weak<MainWindow>, msg: impl Into<String>) {
    let msg = msg.into();

    let _ = ui.upgrade_in_event_loop(move |window| {
        window.set_logs(window.get_logs() + &(msg + "\n"));
    });
}

fn sign_files(
    ui: &slint::Weak<MainWindow>,
    files: &[PathBuf],
    pin: &str,
    output_dir: PathBuf,
) -> anyhow::Result<()> {
    for file in files {
        log(ui, format!("Signing {}...", file.display()));

        let cli = crate::Cli {
            command: Sign(SignArgs {
                detached: false,
                content: None,
                input: file.to_owned(),
                mode: None,
                pin: Some(pin.to_owned()),
                output: Some(output_dir.to_owned()),
            }),
        };

        let cfg = Config::try_from(cli)?;

        let Config::Sign(sign_cfg) = cfg else {
            anyhow::bail!("Unexpected config variant");
        };

        crate::core::sign(sign_cfg).context(format!("When trying to sign {}", file.display()))?;

        log(ui, "Done.");
    }

    Ok(())
}
