use std::fs::{self};

use log::debug;

use crate::{
    cades::Cades,
    core::{ExtractConfig, error::CoreError},
};

pub fn extract(config: ExtractConfig) -> Result<(), CoreError> {
    let ExtractConfig { input, output } = config;

    debug!("opening input file {input:?}");
    let bytes = fs::read(input)?;
    debug!("extracting content from input file");
    let extracted = Cades::from_attached_signature(&bytes)?.get_payload_bytes()?;
    debug!("writing content from input file");
    fs::write(output, extracted)?;
    Ok(())
}
