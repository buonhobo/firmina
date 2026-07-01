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

use chrono::Utc;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
    types::AuthPin,
};
use rasn::types::{Any, Integer, ObjectIdentifier, OctetString, Oid};
use rasn_cms::{
    AlgorithmIdentifier, Certificate, CertificateChoices, CertificateSet, ContentInfo,
    DigestAlgorithmIdentifiers, EncapsulatedContentInfo, IssuerAndSerialNumber, SignatureValue,
    SignedAttributes, SignedData, SignerInfo, SignerInfos,
};
use rasn_pkix::GeneralName;
use rasn_smime::ess::{EssCertIdv2, IssuerSerial, SigningCertificateV2};
use sha2::Digest;
pub fn get_certificate_from_pkcs11(session: &Session) -> Certificate {
    let object = session
        .find_objects(&vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(b"DS User Certificate3".to_vec()),
        ])
        .unwrap()[0];
    let cert = session
        .get_attributes(object, &vec![AttributeType::Value])
        .unwrap()[0]
        .clone();
    let Attribute::Value(val) = cert else {
        unimplemented!()
    };

    rasn::der::decode(&val).unwrap()
}

pub fn build_content_info(
    encap_content: &EncapContent,
    module_path: &Path,
    pin: &AuthPin,
) -> ContentInfo {
    let content_type = ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_SIGNED_DATA);
    let content = build_signed_data(encap_content, module_path, pin);
    let content = Any::new(rasn::der::encode(&content).unwrap());

    ContentInfo {
        content_type,
        content,
    }
}

fn build_signed_data(
    encap_content: &EncapContent,
    module_path: &Path,
    pin: &AuthPin,
) -> SignedData {
    let version = Integer::from(1);
    let encap_content_info = build_encap_content_info(encap_content);
    let (certificates, signer_infos) =
        build_certificates_signer_infos(encap_content, module_path, pin);
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
    pin: &AuthPin,
) -> (Option<CertificateSet>, SignerInfos) {
    let pkcs11 = Pkcs11::new(module_path.display().to_string()).unwrap();
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session(slot).unwrap();
    let certificate = get_certificate_from_pkcs11(&session);
    let signer_infos = build_signer_infos(encap_content, &certificate, &session, pin);
    (
        Some(CertificateSet::from_vec(vec![
            CertificateChoices::Certificate(Box::new(certificate)),
        ])),
        signer_infos,
    )
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
    pin: &AuthPin,
) -> SignerInfos {
    let version = Integer::from(1);
    let sid =
        rasn_cms::SignerIdentifier::IssuerAndSerialNumber(build_issuer_serial_number(certificate));
    let digest_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::from(
            Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256,
        ),
        parameters: None,
    };
    let signature_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::from(Oid::new(&[1, 2, 840, 113549, 1, 1, 11]).unwrap()),
        parameters: None,
    };
    let signed_attrs = build_signed_attrs(certificate, encap_content);
    let signature = build_signature(session, &signed_attrs, pin);

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
    signed_attrs: &SignedAttributes,
    pin: &AuthPin,
) -> SignatureValue {
    // https://www.rfc-editor.org/info/rfc5652/#section-5.4
    let bytes = rasn::der::encode(signed_attrs).unwrap();
    session
        .login(cryptoki::session::UserType::User, Some(pin))
        .unwrap();

    let key_handle = session
        .find_objects(&vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(b"DS User Private Key 3".to_vec()),
        ])
        .unwrap()[0];

    let signature = session
        .sign(
            &cryptoki::mechanism::Mechanism::Sha256RsaPkcs,
            key_handle,
            &bytes,
        )
        .unwrap();
    SignatureValue::from_slice(&signature)
}

fn build_signed_attrs(certificate: &Certificate, encap_content: &EncapContent) -> SignedAttributes {
    let mut attrs = SignedAttributes::new();
    attrs.insert(build_content_type_attr());
    attrs.insert(build_signing_time_attr());
    attrs.insert(build_message_digest_attr(encap_content));
    attrs.insert(build_signing_certificate_v2_attr(certificate));
    attrs
}

fn build_signing_certificate_v2_attr(certificate: &Certificate) -> rasn_cms::Attribute {
    let algo = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::from(
            Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256,
        ),
        parameters: None,
    };
    let digest = sha2::Sha256::digest(rasn::der::encode(certificate).unwrap());
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
    let certs = vec![cert];

    let value = SigningCertificateV2 {
        certs,
        policies: None,
    };

    rasn_cms::Attribute {
        r#type: ObjectIdentifier::from(
            Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_AA_SIGNING_CERTIFICATE_V2,
        ),
        values: vec![rasn::der::encode(&value).unwrap().into()].into(),
    }
}

fn build_message_digest_attr(encap_content: &EncapContent) -> rasn_cms::Attribute {
    let digest = sha2::Sha256::digest(&encap_content.data);
    let octet = OctetString::from(digest.to_vec());
    rasn_cms::Attribute {
        r#type: ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST),
        values: vec![rasn::der::encode(&octet).unwrap().into()].into(),
    }
}

fn build_signing_time_attr() -> rasn_cms::Attribute {
    let now = Utc::now();
    rasn_cms::Attribute {
        r#type: ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SIGNING_TIME),
        values: vec![rasn::der::encode(&now).unwrap().into()].into(),
    }
}

fn build_content_type_attr() -> rasn_cms::Attribute {
    let value = ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_DATA);
    rasn_cms::Attribute {
        r#type: ObjectIdentifier::from(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_CONTENT_TYPE),
        values: vec![rasn::der::encode(&value).unwrap().into()].into(),
    }
}

fn build_issuer_serial_number(certificate: &Certificate) -> IssuerAndSerialNumber {
    let serial_number = certificate.tbs_certificate.serial_number.clone();
    let name = certificate.tbs_certificate.issuer.clone();
    IssuerAndSerialNumber {
        issuer: name,
        serial_number,
    }
}
