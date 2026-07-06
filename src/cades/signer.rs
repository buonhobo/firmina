use std::fmt::{Debug, Display};

use rasn_cms::{
    Certificate, SignatureAlgorithmIdentifier, SignatureValue, SignedAttributes, UnsignedAttributes,
};

use crate::cades::CadesError;

pub trait SignerError: Display + Debug {}

impl<E: SignerError + 'static> From<E> for CadesError {
    fn from(value: E) -> Self {
        CadesError::Signer(Box::new(value))
    }
}

pub trait Signer {
    fn get_certificate(&mut self) -> Result<Certificate, CadesError>;
    fn sign_data(&self, data: &[u8]) -> Result<SignatureValue, CadesError>;
    fn get_signature_algorithm(&self) -> Result<SignatureAlgorithmIdentifier, CadesError>;

    fn get_additional_signed_attributes(&self) -> Result<Option<UnsignedAttributes>, CadesError> {
        Ok(None)
    }

    fn get_additional_unsigned_attributes(&self) -> Result<Option<SignedAttributes>, CadesError> {
        Ok(None)
    }
}
