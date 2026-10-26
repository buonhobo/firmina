use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Sign documents using CAdES or PAdES signatures.
#[derive(Parser, Debug)]
#[command(
    name = "firmina",
    author = "buonhobo",
    version,
    about = "sign files with cades or pades using bit4id smart cards",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, Default)]
pub enum Command {
    /// Create a digital signature.
    Sign(SignArgs),

    /// Extract the encapsulated content from an attached
    /// CAdES signature (.p7m).
    Extract(ExtractArgs),

    /// Start firmina's Graphical User Interface
    #[default]
    Gui,
}
#[derive(Args, Debug)]
pub struct ExtractArgs {
    /// Attached CAdES signature (.p7m).
    pub input: PathBuf,

    /// Output path.
    ///
    /// If omitted, a sensible default is chosen.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// File to sign.
    pub input: PathBuf,

    /// Override automatic input type detection.
    ///
    /// By default:
    /// - PDF files are signed using PAdES
    /// - CAdES files are co-signed
    /// - all other files are treated as generic files and signed using
    ///   attached CAdES (.p7m)
    #[arg(long = "as", visible_alias = "format", value_enum)]
    pub mode: Option<Mode>,

    /// Smart card or token PIN.
    #[arg(short, long, env = "FIRMINA_PIN", value_name = "PIN")]
    pub pin: Option<String>,

    /// Original content of a detached CAdES signature.
    ///
    /// When provided, `input` is interpreted as a detached
    /// `.p7s` signature and `content` is the signed document.
    #[arg(short, long, value_name = "FILE")]
    pub content: Option<PathBuf>,

    /// Output file.
    ///
    /// If omitted, a format-specific default name is generated.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Produce the resulting CAdES signature as detached (.p7s).
    ///
    /// If omitted, the resulting signature is produced as an
    /// attached CAdES container (.p7m).
    ///
    /// Applies both to new signatures and CAdES co-signing.
    ///
    /// Not applicable to PAdES signatures.
    #[arg(long, default_value_t = false)]
    pub detached: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Treat the input as a generic file and sign it using CAdES.
    Generic,

    /// Treat the input as an existing CAdES signature and add a new signer.
    Cades,

    /// Treat the input as a existing detached CAdES signature (p7s) and add a new signer.
    CadesDetached,

    /// Treat the input as a PDF and sign it using PAdES.
    Pades,
}
