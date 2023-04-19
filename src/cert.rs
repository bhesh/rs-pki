//! X.509 Certificates

use crate::{
    error::{Error, Result},
    spki::AlgorithmIdentifierOwned,
    verify::verify_by_oid,
};
use alloc::vec::Vec;
use der::{asn1::BitString, pem::PemLabel, Encode, Sequence, ValueOrd};
use signature::digest::Digest;

pub use x509_cert::certificate::{TbsCertificate, Version};

/// Certificate
///
/// Similar to x509_cert::Certificate but has additional cryptographic functionality
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Certificate {
    /// TBS Certificate
    pub tbs_certificate: TbsCertificate,

    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl PemLabel for Certificate {
    const PEM_LABEL: &'static str = "CERTIFICATE";
}

impl Certificate {
    /// Gets the hash of the certificte's name
    pub fn name_hash<D: Digest>(&self) -> Result<Vec<u8>> {
        Ok(D::digest(&self.tbs_certificate.subject.to_der()?).to_vec())
    }

    /// Gets the hash of the certificte's key
    pub fn key_hash<D: Digest>(&self) -> Result<Vec<u8>> {
        let key_bytes = match self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
        {
            Some(b) => b,
            None => return Err(Error::InvalidAsn1),
        };
        Ok(D::digest(key_bytes).to_vec())
    }

    /// Verifies the certificate given the issuer
    pub fn verify(&self, issuer: &Certificate) -> Result<()> {
        let public_key = issuer.tbs_certificate.subject_public_key_info.to_der()?;
        let msg = self.tbs_certificate.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        let oid = &self.signature_algorithm.oid;
        Ok(verify_by_oid(oid, &public_key, &msg, &sig)?)
    }
}
