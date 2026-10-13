use std::io::Write;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
    types::AuthPin,
};
use log::debug;
use rasn::types::Oid;
use rasn_cms::{AlgorithmIdentifier, Certificate, SignatureAlgorithmIdentifier, SignatureValue};
use tempfile::NamedTempFile;

use crate::{
    cades::{CadesError, Signer, SignerError},
    pkcs11::PkcsSignerError::MissingCertificate,
};

#[cfg(target_os = "linux")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.so");

#[cfg(target_os = "windows")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/bit4xpki.dll");

#[cfg(target_os = "macos")]
const LIBBIT4IDXPKI: &[u8] = include_bytes!("../assets/libbit4xpki.dylib");

#[derive(Debug, thiserror::Error)]
pub enum PkcsSignerError {
    #[error("there was an error while interfacing with the smart card: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),
    #[error("missing certificate in pkcs11 device")]
    MissingCertificate,
    #[error("missing certificate value in pkcs11 device")]
    MissingCertificateValue,
    #[error("missing private key in pkcs11 device")]
    MissingPrivateKey,
    #[error("there was an error while loading the libraries: {0}")]
    IO(#[from] std::io::Error),
}
impl SignerError for PkcsSignerError {}

pub struct PkcsSigner {
    session: Session,
    certificate: Option<Certificate>,
    _tempfile: NamedTempFile,
}
impl PkcsSigner {
    pub fn new(pin: String) -> Result<Self, PkcsSignerError> {
        debug!("extracting library to temp file");
        let mut module = NamedTempFile::new()?;
        module.write_all(LIBBIT4IDXPKI)?;

        debug!(
            "loading bit4id from module in path {}",
            module.path().display()
        );
        #[cfg(target_os = "windows")]
        {
            use std::path::PathBuf;

            debug!("trying to load it from system32 first");
            let pkcs11 = Pkcs11::new(PathBuf::from("C:/Windows/System32/bit4xpki.dll"))?;
            debug!("it worked");
        }
        let pkcs11 = Pkcs11::new(module.path())?;
        debug!("initializing pkcs11 smart card reader");
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        debug!("finding smart cart slot");
        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots.get(0).ok_or(cryptoki::error::Error::InvalidValue)?;
        debug!("opening pkcs11 session");
        let session = pkcs11.open_ro_session(*slot)?;
        debug!("logging into smart card");
        session.login(cryptoki::session::UserType::User, Some(&AuthPin::from(pin)))?;

        let res = Self {
            session,
            certificate: None,
            _tempfile: module,
        };

        Ok(res)
    }
}

impl Signer for PkcsSigner {
    fn get_certificate(&mut self) -> Result<Certificate, CadesError> {
        if let Some(cert) = &self.certificate {
            return Ok(cert.clone());
        }

        debug!("finding certificate in smart card");
        let cert_handles = self
            .session
            .find_objects(&vec![
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Label(b"DS User Certificate3".to_vec()),
            ])
            .map_err(|e| CadesError::from(PkcsSignerError::from(e)))?;

        let Some(cert_handle) = cert_handles.get(0) else {
            return Err(MissingCertificate.into());
        };

        debug!("reading certificate from smart card");
        let cert = self
            .session
            .get_attributes(*cert_handle, &vec![AttributeType::Value])
            .map_err(|e| CadesError::from(PkcsSignerError::from(e)))?;

        let Some(Attribute::Value(val)) = cert.get(0) else {
            return Err(PkcsSignerError::MissingCertificateValue.into());
        };

        debug!("decoding certificate from smart card");
        let cert: Certificate = rasn::der::decode(&val)?;
        self.certificate = Some(cert.clone());

        Ok(cert)
    }

    fn get_signature_algorithm(&self) -> Result<SignatureAlgorithmIdentifier, CadesError> {
        let res = AlgorithmIdentifier {
            algorithm: Oid::new_unchecked(&[1, 2, 840, 113549, 1, 1, 11]).into(),
            parameters: None,
        };
        Ok(res)
    }

    fn sign_data(&self, data: &[u8]) -> Result<SignatureValue, CadesError> {
        debug!("finding private key from smart card");
        let key_handles = self
            .session
            .find_objects(&vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(b"DS User Private Key 3".to_vec()),
            ])
            .map_err(|e| CadesError::from(PkcsSignerError::from(e)))?;

        let Some(key_handle) = key_handles.get(0) else {
            return Err(PkcsSignerError::MissingPrivateKey.into());
        };

        debug!("signing data using smart card");
        let signature = self
            .session
            .sign(
                &cryptoki::mechanism::Mechanism::Sha256RsaPkcs,
                *key_handle,
                data,
            )
            .map_err(|e| CadesError::from(PkcsSignerError::from(e)))?;

        Ok(SignatureValue::from_slice(&signature))
    }
}
