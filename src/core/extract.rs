use std::fs::{self, File};

use log::debug;

use crate::{
    cades::{Cades, Payload},
    core::{ExtractConfig, error::CoreError},
};

fn extract_inner<R: Payload + 'static>(cades_attached: R) -> Result<Vec<u8>, CoreError> {
    let res = Cades::new(cades_attached).get_payload_bytes()?;
    Ok(res)
}

pub fn extract(config: ExtractConfig) -> Result<(), CoreError> {
    let ExtractConfig { input, output } = config;

    debug!("opening input file");
    let bytes = File::open(input)?;
    debug!("extracting content from input file");
    let extracted = extract_inner(bytes)?;
    debug!("writing content from input file");
    fs::write(output, extracted)?;
    Ok(())
}
