use std::{
    fs::{File, create_dir_all},
    io::{Error, Write},
    path::PathBuf,
};

use askama::Template;
use clap::Parser;
use dialoguer::Password;
use env_logger::Env;
use log::{debug, error, info};
use rexpect::spawn;
use tempfile::tempdir;

const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.so");
const PKCS11PROV: &[u8] = include_bytes!("../assets/pkcs11prov.so");

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
    let config_path =
        extract_libs(tempdir.path().into()).expect("Could not extract the necessary openssl libs");

    sign(sign_command, config_path);
}

fn sign(sign_command: Sign, openssl_conf: PathBuf) {
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

    let command = format!(
        "openssl cms -sign -cades -binary {detach} -outform DER \
        -in {} -out {} \
        -signer \"pkcs11:object=DS%20User%20Certificate3;type=cert\" \
        -inkey \"pkcs11:object=DS%20User%20Private%20Key%203;type=private\" \
        -config {}",
        input_path.display(),
        output_path.display(),
        openssl_conf.display(),
        detach = if detach { "" } else { "-nodetach" }
    );

    let timeout = 5000;

    info!("Running command: {command}");
    info!("Will timeout in {timeout}ms");
    let mut openssl = spawn(&command, Some(timeout)).expect("Could not start openssl process");

    while let Ok(out) = openssl.exp_regex("Enter PKCS#11 .* PIN for .*:") {
        openssl
            .send_line(&pin)
            .expect("Could not send PIN to openssl");
        debug!("Forwarding openssl output: \n{}", out.0.trim());
    }

    let status = openssl
        .process()
        .wait()
        .expect("Failed while waiting for openssl to exit");

    match status {
        rexpect::process::WaitStatus::Exited(_, 0) => {
            info!("Done. The output file is: {}", output_path.display())
        }
        rexpect::process::WaitStatus::Exited(_, s) => {
            error!(
                "openssl finished with status {}:\n{}",
                s,
                openssl.exp_eof().unwrap()
            );
        }
        s => panic!("The openssl command is in an unexpected state: {:?}", s),
    };
}

fn extract_libs(temp_dir: PathBuf) -> Result<PathBuf, Error> {
    debug!("Extracting libs into {}", temp_dir.display());
    let openssl_conf = temp_dir.join("openssl.conf");
    let pkcs11prov = temp_dir.join("pkcs11prov.so");
    let libbit4xpki = temp_dir.join("libbit4xpki.so");

    debug!("Creating temporary directory {}", temp_dir.display());
    create_dir_all(&temp_dir)?;

    debug!("Extracting {}", pkcs11prov.display());
    let mut file = File::create(&pkcs11prov)?;
    file.write_all(PKCS11PROV)?;
    debug!("Extracting {}", libbit4xpki.display());
    let mut file = File::create(&libbit4xpki)?;
    file.write_all(LIBBIT4IDXPKI)?;

    debug!("Rendering openssl.conf template");
    let contents = OpensslConf::new(pkcs11prov.clone(), libbit4xpki.clone())
        .render()
        .expect("Could not render openssl_conf template");

    debug!("Writing openssl.conf to {}", openssl_conf.display());
    let mut file = File::create(&openssl_conf)?;
    file.write_all(contents.as_bytes())?;

    Ok(openssl_conf)
}

#[derive(Template)]
#[template(path = "openssl_conf")]
struct OpensslConf {
    pkcs11prov: PathBuf,
    libbit4xpki: PathBuf,
}

impl OpensslConf {
    fn new(pkcs11prov: PathBuf, libbit4xpki: PathBuf) -> Self {
        OpensslConf {
            pkcs11prov,
            libbit4xpki,
        }
    }
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

    let command = format!(
        "openssl cms -verify -noverify -inform DER -in {} -out {}",
        input_path.display(),
        output_path.display()
    );

    let timeout = 5000;

    info!("Running command: {command}");
    info!("Will timeout in {timeout}ms");
    let mut openssl = spawn(&command, Some(timeout)).expect("Could not start openssl process");

    let status = openssl
        .process()
        .wait()
        .expect("Failed while waiting for openssl to exit");

    match status {
        rexpect::process::WaitStatus::Exited(_, 0) => {
            debug!(
                "Forwarding openssl output: \n{}",
                openssl.exp_eof().unwrap()
            );
            info!("Done. The output file is: {}", output_path.display())
        }
        rexpect::process::WaitStatus::Exited(_, s) => {
            error!(
                "openssl finished with status {}:\n{}",
                s,
                openssl.exp_eof().unwrap()
            );
        }
        s => panic!("The openssl command is in an unexpected state: {:?}", s),
    };
}
