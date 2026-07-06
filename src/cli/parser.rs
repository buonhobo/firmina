use std::path::{Path, PathBuf};

use crate::{
    cli::structs::{Cli, ExtractArgs, Mode, SignArgs},
    core::{
        AttachedCadesConfig, CadesConfig, Config, DetachedCadesConfig, ExtractConfig, PadesConfig,
        SignConfig, SignConfigType, SignatureType,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum CliParserError {
    #[error(transparent)]
    ClapError(#[from] clap::Error),
    #[error(transparent)]
    DialoguerError(#[from] dialoguer::Error),
}

impl TryFrom<Cli> for Config {
    type Error = CliParserError;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        match value.command {
            super::structs::Command::Extract(ExtractArgs { input, output }) => {
                let output = match output {
                    Some(output) => output,
                    None => infer_extract_output(&input)?,
                };
                let res = Config::Extract(ExtractConfig { output, input });
                Ok(res)
            }
            super::structs::Command::Sign(SignArgs {
                input,
                mode,
                pin,
                content,
                output,
                detached,
            }) => {
                validate_input(&input)?;

                let mode = match mode {
                    Some(mode) => mode,
                    None => infer_sign_mode(&input, &content)?,
                };

                let output = match output {
                    Some(output) => output,
                    None => infer_sign_output(&input, &mode, detached)?,
                };

                let sign_config_type =
                    infer_sign_config_type(content, mode, input, output, detached)?;

                let pin = match pin {
                    Some(pin) => pin,
                    None => ask_pin()?,
                };

                let signature = SignatureType::Pkcs11 { pin };
                let config = Config::Sign(SignConfig {
                    config_type: sign_config_type,
                    signature_type: signature,
                });

                Ok(config)
            }
        }
    }
}

fn validate_input(input: &PathBuf) -> Result<(), CliParserError> {
    if input.is_file() {
        Ok(())
    } else {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            "the provided path is not a file",
        ))?;
    }
}

fn infer_sign_output(
    input: &Path,
    mode: &Mode,
    detached: bool,
) -> Result<std::path::PathBuf, CliParserError> {
    match mode {
        Mode::Pades => {
            let stem = input.file_stem().ok_or_else(|| {
                clap::Error::raw(
                    clap::error::ErrorKind::InvalidValue,
                    "could not determine output filename",
                )
            })?;

            Ok(input.with_file_name(format!("{}.signed.pdf", stem.to_string_lossy())))
        }

        Mode::Generic | Mode::Cades | Mode::CadesDetached => {
            let ext = if detached { "p7s" } else { "p7m" };
            Ok(PathBuf::from(format!("{}.{}", input.display(), ext)))
        }
    }
}

fn ask_pin() -> Result<String, CliParserError> {
    let pin = dialoguer::Password::new()
        .with_prompt("Enter your PIN")
        .interact()?;
    Ok(pin)
}

fn infer_sign_mode(input: &Path, content: &Option<PathBuf>) -> Result<Mode, CliParserError> {
    if let Some(content) = content {
        validate_input(content)?;

        return match input.extension().and_then(|e| e.to_str()) {
            Some("p7s") => Ok(Mode::CadesDetached),
            _ => Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "--content requires a detached CAdES signature (.p7s) as input",
            )
            .into()),
        };
    }

    match input.extension().and_then(|e| e.to_str()) {
        Some("pdf") => Ok(Mode::Pades),
        Some("p7m") => Ok(Mode::Cades),
        Some("p7s") => Ok(Mode::CadesDetached),
        _ => Ok(Mode::Generic),
    }
}

fn infer_extract_output(input: &Path) -> Result<std::path::PathBuf, CliParserError> {
    let extension = input.extension().and_then(|e| e.to_str());

    if extension != Some("p7m") {
        return Err(clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            "extract expects an attached CAdES signature (.p7m)",
        )
        .into());
    }

    Ok(input.with_extension(""))
}

fn infer_sign_config_type(
    content: Option<PathBuf>,
    mode: Mode,
    input: PathBuf,
    output: PathBuf,
    detached: bool,
) -> Result<SignConfigType, CliParserError> {
    let input = match mode {
        // Content was provided and it should have been
        Mode::CadesDetached => SignConfigType::Cades(CadesConfig::Detached(DetachedCadesConfig {
            signature: input,
            content: content.ok_or_else(|| {
                clap::Error::raw(
                    clap::error::ErrorKind::ArgumentConflict,
                    "detached CAdES signatures (.p7s) require --content to be provided",
                )
            })?,
            detached,
            output,
        })),

        Mode::Generic => SignConfigType::Cades(CadesConfig::Attached(AttachedCadesConfig {
            input,
            output,
            detached,
            wrap: true,
        })),

        Mode::Cades => SignConfigType::Cades(CadesConfig::Attached(AttachedCadesConfig {
            input,
            output,
            detached,
            wrap: false,
        })),

        Mode::Pades => SignConfigType::Pades(PadesConfig { input, output }),
    };
    Ok(input)
}
