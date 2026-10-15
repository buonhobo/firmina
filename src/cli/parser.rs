use std::path::{Path, PathBuf};

use log::debug;

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
                debug!("parsing extract command");
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
                debug!("validating input path");
                validate_input(&input)?;

                let mode = match mode {
                    Some(mode) => mode,
                    None => infer_sign_mode(&input, &content)?,
                };

                let output = match output {
                    Some(output) => {
                        if output.is_dir() {
                            infer_sign_output(&input, &mode, detached, Some(&output))?
                        } else {
                            output
                        }
                    }
                    None => infer_sign_output(&input, &mode, detached, None)?,
                };

                let sign_config_type =
                    infer_sign_config_type(content, mode, input, output, detached)?;

                let pin = match pin {
                    Some(pin) => pin,
                    None => ask_pin()?,
                };

                debug!("parsing sign command");
                let signature = SignatureType::Pkcs11 { pin };
                let config = Config::Sign(SignConfig {
                    config_type: sign_config_type,
                    signature_type: signature,
                });

                Ok(config)
            }
            super::Command::Gui => Ok(Config::Gui),
        }
    }
}

fn validate_input(input: &PathBuf) -> Result<(), CliParserError> {
    debug!("validating input file: {}", input.display());
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
    output_dir: Option<&Path>,
) -> Result<std::path::PathBuf, CliParserError> {
    debug!("inferring output path");
    let mapped_input = match mode {
        Mode::Pades => input.with_extension("signed.pdf"),
        Mode::Generic => input.with_added_extension(if detached { "p7s" } else { "p7m" }),
        Mode::Cades | Mode::CadesDetached => {
            input.with_extension(if detached { "p7s" } else { "p7m" })
        }
    };
    match output_dir {
        None => Ok(mapped_input),
        Some(output) => Ok(output.join(mapped_input.file_name().ok_or(
            CliParserError::ClapError(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "the provided path is not a file",
            )),
        )?)),
    }
}

fn ask_pin() -> Result<String, CliParserError> {
    debug!("asking user for password");
    let pin = dialoguer::Password::new()
        .with_prompt("Enter your PIN")
        .interact()?;
    Ok(pin)
}

fn infer_sign_mode(input: &Path, content: &Option<PathBuf>) -> Result<Mode, CliParserError> {
    debug!("inferring signing signing mode");
    if let Some(content) = content {
        validate_input(content)?;

        debug!("detected detached signing mode");
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
    debug!("inferring extract output path");
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
    debug!("inferring signature config type");
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
