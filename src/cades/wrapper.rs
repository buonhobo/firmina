use std::io::{Read, Seek};

use rasn::types::Integer;
use rasn_cms::{
    Attribute, CertificateChoices, CertificateSet, DigestAlgorithmIdentifier,
    EncapsulatedContentInfo, SignatureAlgorithmIdentifier, SignedData, SignerIdentifier,
    SignerInfos,
};

struct Cades<P: Read + Seek> {
    payload: P,
    signers: Vec<Box<dyn Signer<P>>>,
}

trait Signer<D: Read> {
    fn get_certificate(&self) -> CertificateChoices;
    fn get_signer_indentifier(&self) -> SignerIdentifier;
    fn get_digest_algorithm(&self) -> DigestAlgorithmIdentifier;
    fn get_signature_algorithm(&self) -> SignatureAlgorithmIdentifier;
    fn digest_data(&self, data: &D) -> Vec<u8>;
    fn sign_data(&self, data: &D) -> Vec<u8>;
    fn get_additional_signed_attributes(&self) -> Option<Vec<Attribute>> {
        None
    }
    fn get_additional_unsigned_attributes(&self) -> Option<Vec<Attribute>> {
        None
    }
}

enum SignatureType {
    Attached,
    Detached,
}

impl<P: Read + Seek> Cades<P> {
    pub fn new(payload: P) -> Self {
        Self {
            payload,
            signers: vec![],
        }
    }

    pub fn add_signer(&mut self, signer: impl Signer<P> + 'static) {
        self.signers.push(Box::new(signer));
    }

    pub fn finalize_attached(self) -> Vec<u8> {
        self.finalize(SignatureType::Attached)
    }

    pub fn finalize_detached(self) -> Vec<u8> {
        self.finalize(SignatureType::Detached)
    }

    fn finalize(self, signature_type: SignatureType) -> Vec<u8> {
        let signer_infos = self.get_signer_infos();
        let certificates = self.get_certificates();
        let encap_content_info = self.get_encap_content_info(signature_type);
        let version = self.get_version();
        let digest_algorithms = self.get_digest_algorithms();

        SignedData {
            version,
            digest_algorithms,
            encap_content_info,
            certificates: Some(certificates),
            crls: None,
            signer_infos,
        };

        todo!()
    }

    fn get_signer_infos(&self) -> SignerInfos {
        todo!()
    }

    fn get_certificates(&self) -> CertificateSet {
        todo!()
    }

    fn get_encap_content_info(&self, signature_type: SignatureType) -> EncapsulatedContentInfo {
        todo!()
    }

    fn get_version(&self) -> Integer {
        todo!()
    }

    fn get_digest_algorithms(&self) -> rasn::prelude::SetOf<rasn_cms::AlgorithmIdentifier> {
        todo!()
    }
}
