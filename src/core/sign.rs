use std::fs::{self, File};

use log::debug;

use crate::{
    cades::{Cades, CadesError, Signer},
    core::{
        AttachedCadesConfig, CadesConfig, DetachedCadesConfig, PadesConfig, SignConfig,
        SignatureType, error::CoreError,
    },
    pades::sign_pdf,
    pkcs11::PkcsSigner,
};

pub fn sign(config: SignConfig) -> Result<(), CoreError> {
    let SignConfig {
        config_type,
        signature_type,
    } = config;

    debug!("getting signer for signature");
    let signer = get_signer(signature_type)?;
    match config_type {
        super::SignConfigType::Pades(pades_config) => sign_pades(pades_config, signer)?,
        super::SignConfigType::Cades(cades_config) => sign_cades(cades_config, signer)?,
    };

    Ok(())
}

fn get_signer(sig_type: SignatureType) -> Result<Box<dyn Signer>, CoreError> {
    match sig_type {
        SignatureType::Pkcs11 { pin } => Ok(Box::new(
            PkcsSigner::new(pin).map_err(|e| CadesError::from(e))?,
        )),
    }
}

fn sign_pades(config: PadesConfig, signer: Box<dyn Signer>) -> Result<(), CoreError> {
    let PadesConfig { input, output } = config;
    debug!("signing pdf file");
    let signed = sign_pdf(input, signer)?;
    debug!("writing signed pdf file");
    fs::write(output, signed)?;
    Ok(())
}

fn sign_cades(config: CadesConfig, signer: Box<dyn Signer>) -> Result<(), CoreError> {
    match config {
        CadesConfig::Attached(AttachedCadesConfig {
            input,
            output,
            detached,
            wrap,
        }) => {
            let cades = if wrap {
                debug!("getting cades wrapper from generic input");
                Cades::new(File::open(input)?)
            } else {
                debug!("getting cades wrapper from cades input");
                Cades::from_attached_signature(&fs::read(input)?)?
            };
            debug!("signing cades file");
            let content = sign_cades_inner(cades, signer, detached)?;
            debug!("writing cades file");
            fs::write(output, content)?;
        }
        CadesConfig::Detached(DetachedCadesConfig {
            signature,
            content,
            output,
            detached,
        }) => {
            debug!("reading detached signature");
            let sig = fs::read(signature)?;
            debug!("initializing cades wrapper with detached content");
            let cades = Cades::from_detached_sig_content(&sig, File::open(content)?)?;
            debug!("signing cades file");
            let content = sign_cades_inner(cades, signer, detached)?;
            debug!("writing cades file");
            fs::write(output, content)?;
        }
    };
    Ok(())
}

fn sign_cades_inner(
    mut cades: Cades,
    signer: Box<dyn Signer>,
    detached: bool,
) -> Result<Vec<u8>, CoreError> {
    cades.sign(signer)?;
    let content = if detached {
        debug!("finalizing detached cades signature");
        cades.finalize_detached()?
    } else {
        debug!("finalizing attached cades signature");
        cades.finalize_attached()?
    };
    Ok(content)
}
