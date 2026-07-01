use std::{
    collections::HashSet,
    io::{Cursor, Read, Seek, SeekFrom},
};

use digest_io::IoWrapper;
use rasn::types::{Any, Integer, ObjectIdentifier, OctetString};
use rasn_cms::*;
use rasn_pkix::GeneralName;
use rasn_smime::ess::{EssCertIdv2, IssuerSerial, SigningCertificateV2};
use sha2::Digest;

use crate::cades::*;

pub trait Payload: Read + Seek {}
impl<P: Read + Seek> Payload for P {}

pub struct Cades {
    payload: Box<dyn Payload>,
    certificates: CertificateSet,
    signer_infos: SignerInfos,
}

enum SignatureType {
    Attached,
    Detached,
}

#[derive(Debug, thiserror::Error)]
pub enum CadesError {
    #[error(transparent)]
    Decode(#[from] rasn::error::DecodeError),
    #[error(transparent)]
    Encode(#[from] rasn::error::EncodeError),

    #[error("unsupported content type: {0}")]
    UnsupportedContentType(ObjectIdentifier),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("missing encapsulated content")]
    EncapsulatedContentMissing,
    #[error("there was a signer specific error: {0}")]
    Signer(Box<dyn SignerError>),
}

fn get_signed_data(bytes: &[u8]) -> Result<SignedData, CadesError> {
    let content_info: ContentInfo = rasn::der::decode(bytes)?;

    let signed_data_id: ObjectIdentifier = ID_SIGNED_DATA.into();
    if content_info.content_type != signed_data_id {
        return Err(CadesError::UnsupportedContentType(
            content_info.content_type,
        ));
    }
    let signed_data: SignedData = rasn::der::decode(&content_info.content.into_bytes())?;
    Ok(signed_data)
}

fn get_encap_content(
    encap_content_info: EncapsulatedContentInfo,
) -> Result<Cursor<Vec<u8>>, CadesError> {
    let data_id: ObjectIdentifier = ID_DATA.into();
    if encap_content_info.content_type != data_id {
        return Err(CadesError::UnsupportedContentType(
            encap_content_info.content_type,
        ));
    };

    let Some(content) = encap_content_info.content else {
        return Err(CadesError::EncapsulatedContentMissing);
    };

    let payload = Cursor::new(content.to_vec());
    Ok(payload)
}

impl Cades {
    pub fn from_attached_signature(bytes: &[u8]) -> Result<Self, CadesError> {
        let signed_data = get_signed_data(bytes)?;

        let payload = get_encap_content(signed_data.encap_content_info)?;
        let certificates = signed_data.certificates.unwrap_or(CertificateSet::new());
        let signer_infos = signed_data.signer_infos;

        let result = Self {
            payload: Box::new(payload),
            certificates,
            signer_infos,
        };

        Ok(result)
    }

    pub fn new(payload: impl Payload + 'static) -> Self {
        Self {
            payload: Box::new(payload),
            certificates: CertificateSet::new(),
            signer_infos: SignerInfos::new(),
        }
    }

    pub fn get_payload(&mut self) -> Result<&mut Box<dyn Payload>, CadesError> {
        self.payload.seek(SeekFrom::Start(0))?;
        Ok(&mut self.payload)
    }

    pub fn sign(&mut self, mut signer: impl Signer + 'static) -> Result<(), CadesError> {
        let cert_choice =
            CertificateChoices::Certificate(Box::new(signer.get_certificate()?.clone()));
        self.certificates.insert(cert_choice);

        let signer_info = self.get_signer_info(signer)?;
        self.signer_infos.insert(signer_info);

        Ok(())
    }

    pub fn finalize_attached(self) -> Result<Vec<u8>, CadesError> {
        self.finalize(SignatureType::Attached)
    }

    pub fn finalize_detached(self) -> Result<Vec<u8>, CadesError> {
        self.finalize(SignatureType::Detached)
    }

    fn finalize(mut self, signature_type: SignatureType) -> Result<Vec<u8>, CadesError> {
        let certificates = self.get_certificate_set();
        let encap_content_info = self.get_encap_content_info(signature_type)?;
        let version = self.get_version();
        let digest_algorithms = self.get_digest_algorithms();
        let signer_infos = self.signer_infos;

        let signed_data = SignedData {
            version,
            digest_algorithms,
            encap_content_info,
            certificates,
            signer_infos,
            crls: None,
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA.into(),
            content: Any::new(rasn::der::encode(&signed_data)?),
        };

        Ok(rasn::der::encode(&content_info)?)
    }

    fn get_certificate_set(&self) -> Option<CertificateSet> {
        if self.certificates.len() > 0 {
            Some(self.certificates.clone())
        } else {
            None
        }
    }

    fn get_payload_bytes(&mut self) -> Result<Vec<u8>, CadesError> {
        let mut buf = vec![];
        self.payload.seek(SeekFrom::Start(0))?;
        self.payload.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn get_encap_content_info(
        &mut self,
        signature_type: SignatureType,
    ) -> Result<EncapsulatedContentInfo, CadesError> {
        let content_type = ID_DATA.into();
        let content = match signature_type {
            SignatureType::Attached => Some(OctetString::from(self.get_payload_bytes()?)),
            SignatureType::Detached => None,
        };

        let res = EncapsulatedContentInfo {
            content_type,
            content,
        };
        Ok(res)
    }

    fn get_version(&self) -> Integer {
        /*
        todo: The RFC5652 states that this should be returned:

        IF ((certificates is present) AND
           (any certificates with a type of other are present)) OR
           ((crls is present) AND
           (any crls with a type of other are present))
        THEN version MUST be 5
        ELSE
           IF (certificates is present) AND
              (any version 2 attribute certificates are present)
           THEN version MUST be 4
           ELSE
              IF ((certificates is present) AND
                 (any version 1 attribute certificates are present)) OR
                 (any SignerInfo structures are version 3) OR
                 (encapContentInfo eContentType is other than id-data)
              THEN version MUST be 3
              ELSE version MUST be 1
        */
        Integer::from(1)
    }

    fn get_digest_algorithms(&self) -> DigestAlgorithmIdentifiers {
        self.signer_infos
            .to_vec()
            .iter()
            .map(|si| si.digest_algorithm.clone())
            .collect::<HashSet<AlgorithmIdentifier>>()
            .iter()
            .cloned()
            .collect::<Vec<AlgorithmIdentifier>>()
            .into()
    }

    fn get_signer_info(
        &mut self,
        mut signer: impl Signer + 'static,
    ) -> Result<SignerInfo, CadesError> {
        //RFC5652 says:
        //  If the SignerIdentifier is issuerAndSerialNumber,
        //      then the version MUST be 1.
        //  If the SignerIdentifier is subjectKeyIdentifier,
        //      then the version MUST be 3.
        let version = Integer::from(1);
        let signature_algorithm = signer.get_signature_algorithm()?;
        let digest_algorithm = get_digest_algorithm();
        let signed_attrs = self.get_signed_attrs(&mut signer)?;
        let sid = get_signer_identifier(&signer.get_certificate()?);
        let encoded_attrs = rasn::der::encode(&signed_attrs)?;
        let signature = signer.sign_data(&encoded_attrs)?;
        let unsigned_attrs = signer.get_additional_unsigned_attributes()?;

        let res = SignerInfo {
            version,
            sid,
            digest_algorithm,
            signed_attrs: Some(signed_attrs.into()),
            signature_algorithm,
            signature: OctetString::from(signature),
            unsigned_attrs,
        };

        Ok(res)
    }

    fn get_signed_attrs(
        &mut self,
        signer: &mut (impl Signer + 'static),
    ) -> Result<SignedAttributes, CadesError> {
        let mut attrs = signer
            .get_additional_signed_attributes()?
            .unwrap_or(SignedAttributes::new());

        attrs.insert(get_content_type_attr()?);
        attrs.insert(get_signing_time_attr()?);
        attrs.insert(self.get_message_digest_attr()?);
        attrs.insert(self.get_signing_certificate_v2_attr(signer)?);
        Ok(attrs)
    }

    fn get_signing_certificate_v2_attr(
        &self,
        signer: &mut (impl Signer + 'static),
    ) -> Result<rasn_cms::Attribute, CadesError> {
        let algo = get_digest_algorithm();
        let certificate = signer.get_certificate()?;
        let digest = DefaultDigest::digest(&rasn::der::encode(&certificate)?).to_vec();
        let octet = OctetString::from(digest.to_vec());
        let name = GeneralName::DirectoryName(certificate.tbs_certificate.issuer.clone());

        let issuer_serial = IssuerSerial {
            serial_number: certificate.tbs_certificate.serial_number.clone(),
            issuer: vec![name],
        };

        let cert = EssCertIdv2 {
            hash_algorithm: algo,
            cert_hash: octet,
            issuer_serial: Some(issuer_serial),
        };

        let value = SigningCertificateV2 {
            certs: vec![cert],
            policies: None,
        };

        let attr = rasn_cms::Attribute {
            r#type: ID_SIGNING_CERTIFICATE_V2.into(),
            values: vec![rasn::der::encode(&value)?.into()].into(),
        };
        Ok(attr)
    }

    fn get_message_digest_attr(&mut self) -> Result<rasn_cms::Attribute, CadesError> {
        self.payload.seek(SeekFrom::Start(0))?;
        let digest = digest_data(&mut self.payload)?;
        let octet = OctetString::from(digest.to_vec());
        let res = rasn_cms::Attribute {
            r#type: ID_MESSAGE_DIGEST.into(),
            values: vec![rasn::der::encode(&octet)?.into()].into(),
        };
        Ok(res)
    }
}

fn get_content_type_attr() -> Result<rasn_cms::Attribute, CadesError> {
    let value: ObjectIdentifier = ID_DATA.into();
    let res = rasn_cms::Attribute {
        r#type: ID_CONTENT_TYPE.into(),
        values: vec![rasn::der::encode(&value)?.into()].into(),
    };
    Ok(res)
}

fn get_signing_time_attr() -> Result<rasn_cms::Attribute, CadesError> {
    let now = chrono::Utc::now();
    let res = rasn_cms::Attribute {
        r#type: ID_SIGNING_TIME.into(),
        values: vec![rasn::der::encode(&now)?.into()].into(),
    };
    Ok(res)
}

fn get_signer_identifier(cert: &Certificate) -> SignerIdentifier {
    let serial_number = cert.tbs_certificate.serial_number.clone();
    let name = cert.tbs_certificate.issuer.clone();
    SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: name,
        serial_number,
    })
}

fn digest_data<R: Read>(data: &mut R) -> Result<Vec<u8>, CadesError> {
    let mut hasher = IoWrapper(DefaultDigest::new());
    std::io::copy(data, &mut hasher)?;
    Ok(hasher.0.finalize().to_vec())
}
