//! X.509 Certificate Requests

use crate::{
    error::{Error, Result},
    req::CertReqInfo,
    spki::AlgorithmIdentifierOwned,
    verify::verify_by_oid,
};
use der::{asn1::BitString, pem::PemLabel, Encode, Sequence};

/// CertReq
///
/// Similar to x509_cert::request::CertReq but has additional cryptographic functionality
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct CertReq {
    /// Certification request information.
    pub info: CertReqInfo,

    /// Signature algorithm identifier.
    pub algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl PemLabel for CertReq {
    const PEM_LABEL: &'static str = "CERTIFICATE REQUEST";
}

impl CertReq {
    /// Verifies the CSR signature with its own public key
    pub fn verify(&self) -> Result<()> {
        let public_key = self.info.public_key.to_der()?;
        let msg = self.info.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        let oid = &self.algorithm.oid;
        Ok(verify_by_oid(oid, &public_key, &msg, &sig)?)
    }
}
