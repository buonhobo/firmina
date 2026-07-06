use std::fs::{self, File};

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

    let bytes = File::open(input)?;
    let extracted = extract_inner(bytes)?;
    fs::write(output, extracted)?;
    Ok(())
}
