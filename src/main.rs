mod cades;
mod cli;
mod core;
mod gui;
mod pades;
mod pkcs11;

use clap::Parser;
use env_logger::Env;
use log::debug;

use crate::{cli::Cli, core::Config};

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("firmina=info")).init();
    if std::env::args().len() == 1 {
        if let Err(e) = gui::entrypoint::main() {
            panic!("There was an error while running the GUI: {e:?}")
        };
        return;
    }
    debug!("parsing cli commands");
    let cli = Cli::parse();
    debug!("preparing backend config");
    let config = match Config::try_from(cli) {
        Ok(c) => c,
        Err(e) => panic!("There was an error while parsing the cli parameters: {e}"),
    };
    debug!("executing command");
    match config {
        Config::Sign(sign_config) => {
            if let Err(e) = core::sign(sign_config) {
                panic!("There was an error while signing: {e:?}")
            }
        }
        Config::Extract(extract_config) => {
            if let Err(e) = core::extract(extract_config) {
                panic!("There was an error while extracting: {e:?}")
            }
        }
        Config::Gui => {
            if let Err(e) = gui::entrypoint::main() {
                panic!("There was an error while running the GUI: {e:?}")
            };
        }
    };
}
