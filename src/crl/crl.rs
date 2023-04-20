//! X.509 CRLs

use crate::{
    cert::Certificate,
    error::{Error, Result},
    verify::verify_by_oid,
};
use der::{asn1::BitString, Encode, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;

pub use x509_cert::crl::{RevokedCert, TbsCertList};

/// CertificateList
///
/// Similar to x509_cert::crl::CertificateList but has additional cryptographic functionality
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CertificateList {
    /// TBS Certificate List
    pub tbs_cert_list: TbsCertList,

    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl CertificateList {
    /// Verifies the CRL given the CA
    pub fn verify(&self, ca: &Certificate) -> Result<()> {
        let public_key = ca.tbs_certificate.subject_public_key_info.to_der()?;
        let msg = self.tbs_cert_list.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        let oid = &self.signature_algorithm.oid;
        Ok(verify_by_oid(oid, &public_key, &msg, &sig)?)
    }
}
