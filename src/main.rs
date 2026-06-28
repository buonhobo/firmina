use std::{
    fs::{File, create_dir_all},
    io::{Error, Write},
    path::PathBuf,
};

use askama::Template;
use clap::Parser;
use dialoguer::Password;
use env_logger::Env;
use log::{debug, info};
use rexpect::spawn;
use tempfile::tempdir;

const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.so");
const PKCS11PROV: &[u8] = include_bytes!("../assets/pkcs11prov.so");

#[derive(clap::Parser, Debug)]
struct Cli {
    ///Pin della firma
    #[arg(short, long)]
    pin: Option<String>,
    ///File da firmare
    input_path: PathBuf,
    ///Percorso del file firmato
    #[arg(short, long)]
    output_path: Option<PathBuf>,
    ///Se produrre la firma separatamente
    #[arg(short, long, default_value_t = false)]
    detach: bool,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("firmina=info")).init();
    let cli = Cli::parse();

    debug!("Creating temporary directory to extract the needed libraries");
    let tempdir =
        tempdir().expect("Could not create a temporary directory for the necessary libraries");
    let config_path =
        extract_libs(tempdir.path().into()).expect("Could not extract the necessary openssl libs");
    sign(cli, config_path);
}

fn sign(sign_command: Cli, openssl_conf: PathBuf) {
    let Cli {
        pin,
        input_path,
        output_path,
        detach,
    } = sign_command;

    info!("Asking user for PIN");
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

    while let Ok(_) = openssl.exp_regex("Enter PKCS#11 .* PIN for .*:") {
        openssl
            .send_line(&pin)
            .expect("Could not send PIN to openssl");
    }

    info!("Done. The output file is: {}", output_path.display());
}

fn extract_libs(temp_dir: PathBuf) -> Result<PathBuf, Error> {
    info!("Extracting libs into {}", temp_dir.display());
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
