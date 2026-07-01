use std::path::Path;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
    types::AuthPin,
};
use rasn::types::Oid;
use rasn_cms::{AlgorithmIdentifier, Certificate, SignatureAlgorithmIdentifier, SignatureValue};

use crate::{
    cades::{Signer, SignerError},
    pkcs11::PkcsSignerError::MissingCertificate,
};

pub struct PkcsSigner {
    session: Session,
    certificate: Option<Certificate>,
}
impl PkcsSigner {
    pub fn new(pin: String, module: &Path) -> Result<Self, cryptoki::error::Error> {
        let pkcs11 = Pkcs11::new(module)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots.get(0).ok_or(cryptoki::error::Error::InvalidValue)?;

        let session = pkcs11.open_ro_session(*slot)?;
        session.login(cryptoki::session::UserType::User, Some(&AuthPin::from(pin)))?;

        let res = Self {
            session,
            certificate: None,
        };

        Ok(res)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PkcsSignerError {
    #[error(transparent)]
    Cryptoki(#[from] cryptoki::error::Error),
    #[error("missing certificate in pkcs11 device")]
    MissingCertificate,
    #[error("missing certificate value in pkcs11 device")]
    MissingCertificateValue,
    #[error(transparent)]
    Decode(#[from] rasn::error::DecodeError),
    #[error("missing private key in pkcs11 device")]
    MissingPrivateKey,
}
impl SignerError for PkcsSignerError {}

impl Signer for PkcsSigner {
    type Error = PkcsSignerError;

    fn get_certificate(&mut self) -> Result<Certificate, Self::Error> {
        if let Some(cert) = &self.certificate {
            return Ok(cert.clone());
        }

        let cert_handles = self.session.find_objects(&vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(b"DS User Certificate3".to_vec()),
        ])?;

        let Some(cert_handle) = cert_handles.get(0) else {
            return Err(MissingCertificate);
        };

        let cert = self
            .session
            .get_attributes(*cert_handle, &vec![AttributeType::Value])?;

        let Some(Attribute::Value(val)) = cert.get(0) else {
            return Err(PkcsSignerError::MissingCertificateValue);
        };

        let cert: Certificate = rasn::der::decode(&val)?;
        self.certificate = Some(cert.clone());

        Ok(cert)
    }

    fn get_signature_algorithm(&self) -> Result<SignatureAlgorithmIdentifier, Self::Error> {
        let res = AlgorithmIdentifier {
            algorithm: Oid::new_unchecked(&[1, 2, 840, 113549, 1, 1, 11]).into(),
            parameters: None,
        };
        Ok(res)
    }

    fn sign_data(&self, data: &[u8]) -> Result<SignatureValue, Self::Error> {
        let key_handles = self.session.find_objects(&vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(b"DS User Private Key 3".to_vec()),
        ])?;

        let Some(key_handle) = key_handles.get(0) else {
            return Err(PkcsSignerError::MissingPrivateKey);
        };

        let signature = self.session.sign(
            &cryptoki::mechanism::Mechanism::Sha256RsaPkcs,
            *key_handle,
            data,
        )?;

        Ok(SignatureValue::from_slice(&signature))
    }
}
