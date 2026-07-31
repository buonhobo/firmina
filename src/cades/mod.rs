mod builder;
mod signer;

pub use builder::{Cades, CadesError};
use rasn::types::Oid;
use rasn_cms::AlgorithmIdentifier;
pub use signer::{Signer, SignerError};

const ID_DATA: &'static Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_DATA;
const ID_SIGNED_DATA: &'static Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_SIGNED_DATA;
const ID_SIGNING_CERTIFICATE_V2: &'static Oid =
    Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_AA_SIGNING_CERTIFICATE_V2;
const ID_MESSAGE_DIGEST: &'static Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST;
const ID_CONTENT_TYPE: &'static Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_CONTENT_TYPE;
const ID_SIGNING_TIME: &'static Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SIGNING_TIME;

const ID_SHA256: &'static Oid =
    Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256;
type DefaultDigest = sha2::Sha256;

fn get_digest_algorithm() -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: ID_SHA256.into(),
        parameters: None,
    }
}
