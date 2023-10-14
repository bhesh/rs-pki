//! Possible Error Definitions
use alloc::string::String;

/// PKI Result mapping
pub type Result<T> = core::result::Result<T, Error>;

/// PKI Error definitions
#[derive(Debug)]
pub enum Error {
    /// Key error
    InvalidKey,

    /// Decryption error
    Decryption,

    /// Verification error
    Verification,

    /// Invalid signature
    InvalidSignature,

    /// Invalid OID
    InvalidOid,

    /// Encoding errors
    InvalidAsn1,

    #[cfg(feature = "rsa")]
    /// RSA errors
    Rsa(rsa::errors::Error),

    /// Unknown
    Unknown(String),
}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Error::InvalidAsn1
    }
}

impl From<spki::Error> for Error {
    fn from(error: spki::Error) -> Self {
        match error {
            spki::Error::OidUnknown { .. } => Error::InvalidOid,
            _ => Error::InvalidAsn1,
        }
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::errors::Error> for Error {
    fn from(error: rsa::errors::Error) -> Self {
        match error {
            rsa::errors::Error::Decryption => Error::Decryption,
            rsa::errors::Error::Verification => Error::Verification,
            rsa::errors::Error::Pkcs1(_) => Error::InvalidAsn1,
            rsa::errors::Error::Pkcs8(_) => Error::InvalidAsn1,
            _ => Error::Rsa(error),
        }
    }
}
