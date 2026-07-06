use std::path::PathBuf;

pub enum Config {
    Sign(SignConfig),
    Extract(ExtractConfig),
}

pub struct ExtractConfig {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub struct SignConfig {
    pub config_type: SignConfigType,
    pub signature_type: SignatureType,
}

pub enum SignatureType {
    Pkcs11 { pin: String },
}

pub enum SignConfigType {
    Pades(PadesConfig),
    Cades(CadesConfig),
}

pub enum CadesConfig {
    Attached(AttachedCadesConfig),
    Detached(DetachedCadesConfig),
}

pub struct AttachedCadesConfig {
    pub input: PathBuf,
    pub output: PathBuf,
    pub detached: bool,
    pub wrap: bool,
}

pub struct DetachedCadesConfig {
    pub signature: PathBuf,
    pub content: PathBuf,
    pub output: PathBuf,
    pub detached: bool,
}

pub struct PadesConfig {
    pub input: PathBuf,
    pub output: PathBuf,
}
