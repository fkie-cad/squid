use thiserror::Error;

use crate::frontend::ao::AoError;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("The dependency '{0}' cannot be found in the search paths")]
    DependencyNotFound(String),

    #[error("Invalid ELF binary: {0}")]
    InvalidELF(String),

    #[error("Symbol resolution error: {0}")]
    SymbolResolutionError(String),

    #[error("Error with ewe file: {0}")]
    EweError(String),

    #[error("{0:?}")]
    AoError(#[from] AoError),

    #[error("Error symbolizing code: {0}")]
    CodeSymbolizationError(String),

    #[error("Symbolic loading of ELF file failed: {0}")]
    LoadingError(String),

    #[error("IO error: {0}")]
    IOError(String),

    #[error("The symbolic ELF loader produced an invalid process image: {0}")]
    InvalidProcessImage(String),
}
