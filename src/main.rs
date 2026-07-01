use std::{
    fs::{self, File},
    io::{Error, Write},
    path::PathBuf,
};

use clap::Parser;
use cryptoki::types::AuthPin;
use dialoguer::Password;
use env_logger::Env;
use log::debug;
use tempfile::tempdir;

use crate::cades::sign::{EncapContent, build_content_info};

#[cfg(target_os = "linux")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.so");

#[cfg(target_os = "linux")]
const LIB_NAME: &str = "libbit4xpki.so";

#[cfg(target_os = "windows")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/bit4xpki.dll");

#[cfg(target_os = "windows")]
const LIB_NAME: &str = "bit4xpki.dll";

#[cfg(target_os = "macos")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.dylib");

#[cfg(target_os = "macos")]
const LIB_NAME: &str = "libbit4xpki.dylib";

mod cades;

#[derive(clap::Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    ///Firma un documento in CADES usando una smart key
    Sign(Sign),
    ///Estrai il contenuto di un file p7m
    Extract(Extract),
}

#[derive(clap::Args, Debug)]
struct Sign {
    ///Pin della chiave per la firma
    #[arg(short, long)]
    pin: Option<String>,
    ///Percorso del file firmato, se non specificato viene messo a fianco all'originale
    #[arg(short, long)]
    output_path: Option<PathBuf>,
    ///Se produrre la firma separatamente, falso di default
    #[arg(short, long, default_value_t = false)]
    detach: bool,
    ///File da firmare
    input_path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct Extract {
    ///Percorso del file estratto, se non specificato viene messo a fianco dell'originale
    #[arg(short, long)]
    output_path: Option<PathBuf>,
    ///File da estrarre
    input_path: PathBuf,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("firmina=info")).init();
    let cli = Cli::parse();

    match cli.command {
        Command::Sign(sign) => sign_outer(sign),
        Command::Extract(e) => extract(e),
    }
}

fn sign_outer(sign_command: Sign) {
    debug!("Creating temporary directory to extract the needed libraries");
    let tempdir =
        tempdir().expect("Could not create a temporary directory for the necessary libraries");
    let libbit4xpki =
        extract_libs(tempdir.path().into()).expect("Could not extract the necessary openssl libs");

    sign(sign_command, libbit4xpki);
}

fn sign(sign_command: Sign, libbit4xpki: PathBuf) {
    let Sign {
        pin,
        input_path,
        output_path,
        detach,
    } = sign_command;

    if !(input_path.exists() && input_path.is_file()) {
        panic!("{} does not exist or is not a file", input_path.display())
    }

    debug!("Asking user for PIN");
    let pin = match pin {
        Some(s) => s,
        None => Password::new()
            .with_prompt("Enter your PIN")
            .interact()
            .expect("Could not get a PIN"),
    };

    let output_path =
        output_path.unwrap_or(input_path.with_added_extension(if detach { "p7s" } else { "p7m" }));

    let res = build_content_info(
        &EncapContent {
            detach: false,
            data: fs::read(input_path).unwrap(),
        },
        &libbit4xpki,
        &AuthPin::from(pin),
    );
    fs::write(output_path, rasn::der::encode(&res).unwrap()).unwrap();
    return;
}

fn extract_libs(temp_dir: PathBuf) -> Result<PathBuf, Error> {
    debug!("Extracting libs into {}", temp_dir.display());
    let libbit4xpki = temp_dir.join(LIB_NAME);

    debug!("Extracting {}", libbit4xpki.display());
    let mut file = File::create(&libbit4xpki)?;
    file.write_all(LIBBIT4IDXPKI)?;

    Ok(libbit4xpki)
}

fn extract(extract: Extract) {
    let Extract {
        output_path,
        input_path,
    } = extract;

    if !(input_path.exists() && input_path.is_file()) {
        panic!("{} does not exist or is not a file", input_path.display())
    }

    let output_path = match output_path {
        Some(p) => p,
        None => {
            if input_path.extension().is_some_and(|e| e == "p7m") {
                input_path
                    .file_stem()
                    .expect("Could not get the output path")
                    .into()
            } else {
                input_path.with_added_extension("out")
            }
        }
    };

    todo!()
}
