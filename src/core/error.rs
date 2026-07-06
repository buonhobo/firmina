use crate::{cades::CadesError, pades::PadesError};

#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("There was an error when working with a cades format: {0}")]
    Cades(#[from] CadesError),
    #[error("There was an error when signing a pdf: {0}")]
    Pades(#[from] PadesError),
    #[error("There was an io error: {0}")]
    IO(#[from] std::io::Error),
}
