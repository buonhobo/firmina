/*
    ContentInfo
        ContentType (SignedData)
        Content (SignedData)
            version (1)
            digestAlgorithms
            encapContentInfo
                eContentType (id-data)
                eContent (id-data or none)
            certificates
                set of certificateChoices (Certificate from pkcs11 key)
            crls (optional)
            signerInfos
                version (1)
                sid (IssuerAndSerialNumber)
                digestAlgorithm
                signedAttrs
                    contentType (id-data)
                    signingTime
                    messageDigest
                    signingCertificateV2
                        certs
                            hashAlgorithm (optional, default is sha256)
                            certHash
                            issuerSerial (optional?)
                                issuer (GeneralNames, get them from Certificate Issuer generalnames, might need mapping)
                                serialNumber
                        policies (optional)
                signatureAlgorithm
                signature
                unsignedAttrs (optional)
*/

use std::path::Path;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
};
use rasn::types::{Any, Integer, ObjectIdentifier, Oid};
use rasn_cms::{
    AlgorithmIdentifier, Certificate, CertificateChoices, CertificateSet, ContentInfo,
    DigestAlgorithmIdentifiers, EncapsulatedContentInfo, IssuerAndSerialNumber, SignedAttributes,
    SignedData, SignerInfo, SignerInfos,
};

pub fn get_certificate_from_pkcs11(
    session: &Session,
) -> Result<Certificate, cryptoki::error::Error> {
    let object = session.find_objects(&vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Label(b"DS User Certificate3".to_vec()),
    ])?[0];
    let cert = session.get_attributes(object, &vec![AttributeType::Value])?[0].clone();
    let Attribute::Value(val) = cert else {
        unimplemented!()
    };

    rasn::der::decode(&val).map_err(|_| cryptoki::error::Error::InvalidValue)
}

pub fn build_content_info(encap_content: &EncapContent, module_path: &Path) -> ContentInfo {
    let content_type = ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_SIGNED_DATA);
    let content = build_signed_data(encap_content, module_path);
    let content = Any::new(rasn::der::encode(&content).unwrap());

    ContentInfo {
        content_type,
        content,
    }
}

fn build_signed_data(encap_content: &EncapContent, module_path: &Path) -> SignedData {
    let version = Integer::from(1);
    let encap_content_info = build_encap_content_info(encap_content);
    let (certificates, signer_infos) =
        build_certificates_signer_infos(encap_content, module_path).unwrap();
    let crls = None;
    let digest_algorithms = get_digests_from_signer_infos(&signer_infos);
    SignedData {
        version,
        digest_algorithms,
        encap_content_info,
        certificates,
        crls,
        signer_infos,
    }
}

fn get_digests_from_signer_infos(signer_infos: &SignerInfos) -> DigestAlgorithmIdentifiers {
    let mut result = DigestAlgorithmIdentifiers::new();
    for signer_info in signer_infos.to_vec() {
        result.insert(signer_info.digest_algorithm.clone());
    }
    result
}

fn build_certificates_signer_infos(
    encap_content: &EncapContent,
    module_path: &Path,
) -> Result<(Option<CertificateSet>, SignerInfos), cryptoki::error::Error> {
    let pkcs11 = Pkcs11::new(module_path.display().to_string())?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = pkcs11.get_slots_with_token()?[0];
    let session = pkcs11.open_ro_session(slot)?;
    let certificate = get_certificate_from_pkcs11(&session).unwrap();
    let signer_infos = build_signer_infos(encap_content, &certificate, &session);
    Ok((
        Some(CertificateSet::from_vec(vec![
            CertificateChoices::Certificate(Box::new(certificate)),
        ])),
        signer_infos,
    ))
}

pub struct EncapContent {
    pub detach: bool,
    pub data: Vec<u8>,
}

fn build_encap_content_info(encap_content: &EncapContent) -> EncapsulatedContentInfo {
    let content_type = ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_DATA);

    let EncapContent { detach, data } = encap_content;

    let content = if *detach {
        None
    } else {
        Some(data.to_owned().into())
    };

    let content = EncapsulatedContentInfo {
        content_type,
        content,
    };

    content
}

fn build_signer_infos(
    encap_content: &EncapContent,
    certificate: &Certificate,
    session: &Session,
) -> SignerInfos {
    let version = Integer::from(1);
    let sid =
        rasn_cms::SignerIdentifier::IssuerAndSerialNumber(build_issuer_serial_number(certificate));
    let digest_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_DIGEST_HMAC_SHA256),
        parameters: None,
    };
    let signature_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSA),
        parameters: None,
    };
    let signed_attrs = build_signed_attrs(certificate, encap_content);
    let signature = build_signature(session, encap_content, &signed_attrs);

    let signer_info = SignerInfo {
        version,
        sid,
        digest_algorithm,
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature,
        unsigned_attrs: None,
    };
    SignerInfos::from_vec(vec![signer_info])
}

fn build_signature(
    session: &Session,
    encap_content: &EncapContent,
    signed_attrs: &SignedAttributes,
) -> rasn::prelude::OctetString {
    // https://www.rfc-editor.org/info/rfc5652/#section-5.4
    todo!()
}

fn build_signed_attrs(certificate: &Certificate, encap_content: &EncapContent) -> SignedAttributes {
    todo!()
}

fn build_issuer_serial_number(certificate: &Certificate) -> IssuerAndSerialNumber {
    todo!()
}
