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
    type Error: SignerError + 'static;

    fn get_certificate(&mut self) -> Result<Certificate, Self::Error>;
    fn sign_data(&self, data: &[u8]) -> Result<SignatureValue, Self::Error>;
    fn get_signature_algorithm(&self) -> Result<SignatureAlgorithmIdentifier, Self::Error>;

    fn get_additional_signed_attributes(&self) -> Result<Option<UnsignedAttributes>, Self::Error> {
        Ok(None)
    }

    fn get_additional_unsigned_attributes(&self) -> Result<Option<SignedAttributes>, Self::Error> {
        Ok(None)
    }
}
