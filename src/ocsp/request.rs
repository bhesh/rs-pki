//! OCSP Request

use crate::{
    cert::Certificate,
    error::{Error, Result},
    ext::{pkix::name::GeneralName, Extensions},
    ocsp::{CertId, Version},
    serial_number::SerialNumber,
    verify::verify_by_oid,
};
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use core::{default::Default, option::Option};
use der::{asn1::BitString, Encode, Sequence};
use signature::digest::Digest;
use spki::AlgorithmIdentifierOwned;

/// OCSPRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspRequest {
    pub tbs_request: TbsRequest,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub optional_signature: Option<Signature>,
}

impl OcspRequest {
    /// Verifies the OCSP Request given the issuer
    pub fn verify(&self, issuer: &Certificate) -> Result<()> {
        let signature = match &self.optional_signature {
            Some(s) => s,
            None => return Err(Error::Verification),
        };
        let oid = &signature.signature_algorithm.oid;
        let msg = self.tbs_request.to_der()?;
        let sig = match signature.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        Ok(verify_by_oid(
            oid,
            &issuer.tbs_certificate.subject_public_key_info,
            &msg,
            &sig,
        )?)
    }
}

/// TBSRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsRequest {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub requestor_name: Option<GeneralName>,

    pub request_list: Vec<Request>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub request_extensions: Option<Extensions>,
}

/// Signature structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Signature {
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

/// Request structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Request ::= SEQUENCE {
///    reqCert                     CertID,
///    singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Request {
    pub req_cert: CertId,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions>,
}

impl Request {
    /// Generates the `Request` by hashing the issuer name and keys. This method will fail with
    /// invalid DER encoding.
    pub fn from_issuer<D: Digest + AssociatedOid>(
        issuer: &Certificate,
        serial_number: SerialNumber,
        single_request_extensions: Option<Extensions>,
    ) -> Result<Self> {
        Ok(Self {
            req_cert: CertId::from_issuer::<D>(issuer, serial_number)?,
            single_request_extensions,
        })
    }
}
