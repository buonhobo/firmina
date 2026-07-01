use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Error, Write},
    path::PathBuf,
};

use clap::Parser;
use dialoguer::Password;
use env_logger::Env;
use log::{debug, info};
use tempfile::tempdir;

use crate::{cades::Cades, pkcs11::PkcsSigner};

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
mod pkcs11;

#[derive(clap::Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Generate a CADES signature using your smart card
    Sign(SignArgs),
    /// Extract the payload of a CADES .p7m signature
    Extract(Extract),
}

#[derive(clap::Args, Debug)]
pub struct SignArgs {
    /// File to sign
    pub file: PathBuf,

    /// Treat the input as an existing CAdES container
    #[arg(long, short, default_value_t = false)]
    pub cades: bool,

    /// Whether to generate an attached or detached signature.
    #[arg(short, long, default_value_t = false)]
    pub detach: bool,

    /// Smart card PIN. If omitted, it will be requested interactively.
    #[arg(short, long, env = "FIRMINA_PIN")]
    pub pin: Option<String>,

    /// Output path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
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
        Command::Sign(sign_args) => sign(sign_args),
        Command::Extract(e) => extract(e),
    }
}

fn sign(sign_command: SignArgs) {
    debug!("Creating temporary directory to extract the needed libraries");
    let tempdir =
        tempdir().expect("Could not create a temporary directory for the necessary libraries");
    let libbit4xpki =
        extract_libs(tempdir.path().into()).expect("Could not extract the necessary openssl libs");

    let SignArgs {
        file,
        cades,
        detach,
        pin,
        output,
    } = sign_command;

    if !(file.exists() && file.is_file()) {
        panic!("{} does not exist or is not a file", file.display())
    }

    debug!("determining output path");

    let filename = file.file_name().expect("input file name is not valid");

    let extension = if detach { "p7s" } else { "p7m" };

    let default_name = PathBuf::from(filename).with_added_extension(extension);

    let output_path = match output {
        Some(path) if path.is_dir() => path.join(&default_name),
        Some(path) => path,
        None => default_name,
    };

    info!("loading input file");
    let mut cades_wrapper = if cades {
        debug!("loading preexisting cades file");
        let content = fs::read(file).expect("could not read input cades file");
        Cades::from_attached_signature(&content).expect("could not parse input cades file")
    } else {
        debug!("loading payload into new cades object");
        let payload = BufReader::new(File::open(file).unwrap());
        Cades::new(payload)
    };

    debug!("Asking user for PIN");
    let pin = match pin {
        Some(s) => s,
        None => Password::new()
            .with_prompt("Enter your PIN")
            .interact()
            .expect("Could not get a PIN"),
    };

    info!("signing file");
    cades_wrapper
        .sign(PkcsSigner::new(pin, &libbit4xpki).expect("could not load smart card device"))
        .expect("could not sign cades file using smart card");

    info!("decoding file");
    let res = if detach {
        cades_wrapper.finalize_detached()
    } else {
        cades_wrapper.finalize_attached()
    }
    .expect("could not encode cades signature");

    info!("writing to {}", output_path.display());
    fs::write(output_path, res).unwrap();
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

    info!("loading preexisting cades file");
    let mut cades_wrapper = {
        let content = fs::read(&input_path).expect("could not read input cades file");
        Cades::from_attached_signature(&content).expect("could not parse input cades file")
    };

    let filename = input_path
        .file_name()
        .expect("input file name is not valid");

    let default_name = PathBuf::from(filename)
        .file_stem()
        .expect("input file name is not valid")
        .into();

    let output_path = match output_path {
        Some(path) if path.is_dir() => path.join(&default_name),
        Some(path) => path,
        None => default_name,
    };

    info!("Writing content to {}", output_path.display());
    io::copy(
        cades_wrapper
            .get_payload()
            .expect("could not get cades payload"),
        &mut BufWriter::new(
            File::create(output_path).expect("could not open output path in write mode"),
        ),
    )
    .expect("there was an error while writing the content");
}
