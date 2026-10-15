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
    debug!("parsing cli commands");
    let cli = Cli::parse();
    debug!("preparing backend config");
    let config = match Config::try_from(cli) {
        Ok(c) => c,
        Err(e) => panic!("There was an error while parsing the cli parameters: {e}"),
    };
    debug!("executing command");
    let res = match config {
        Config::Sign(sign_config) => core::sign(sign_config),
        Config::Extract(extract_config) => core::extract(extract_config),
        Config::Gui => {
            gui::entrypoint::main();
            Ok(())
        }
    };
    if let Err(e) = res {
        panic!("There was an error while executing the command: {e}");
    }
}
