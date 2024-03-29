//! Basic OCSP Response

use crate::{
    cert::Certificate,
    crl::{CertificateList, RevokedCert},
    error::{Error, Result},
    ext::{pkix::CrlReason, Extensions},
    name::Name,
    serial_number::SerialNumber,
    time::Time,
    verify::verify_by_oid,
};
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use core::{default::Default, option::Option};
use der::{
    asn1::{BitString, GeneralizedTime, Null, OctetString},
    Choice, Decode, Encode, Enumerated, Sequence,
};
use signature::digest::Digest;
use spki::AlgorithmIdentifierOwned;

/// OCSP `Version` as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    V1 = 0,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

/// BasicOcspResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

impl BasicOcspResponse {
    /// Verifies the OCSP Response given the signing cert
    pub fn verify(&self, signing_cert: &Certificate) -> Result<()> {
        let oid = &self.signature_algorithm.oid;
        let msg = self.tbs_response_data.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        Ok(verify_by_oid(
            oid,
            &signing_cert.tbs_certificate.subject_public_key_info,
            &msg,
            &sig,
        )?)
    }
}

/// ResponseData structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

/// ResponderID structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponderID ::= CHOICE {
///    byName              [1] Name,
///    byKey               [2] KeyHash }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(KeyHash),
}

/// KeyHash structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
///                          -- (i.e., the SHA-1 hash of the value of the
///                          -- BIT STRING subjectPublicKey [excluding
///                          -- the tag, length, and number of unused
///                          -- bits] in the responder's certificate)
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type KeyHash = OctetString;

/// SingleResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_extensions: Option<Extensions>,
}

impl SingleResponse {
    /// Generates the `SingleResponse` from the CRL. If the provided serial is not listed in the CRL,
    /// the status is set to `Good`. If it is, it tries to convert `RevokedCert` into
    /// `RevokedInfo`. The revocation reason is set to `None` if it fails to parse the `CrlReason`
    /// extension.
    pub fn from_crl<D: Digest + AssociatedOid>(
        crl: &CertificateList,
        issuer: &Certificate,
        serial_number: SerialNumber,
        this_update: GeneralizedTime,
        next_update: Option<GeneralizedTime>,
        single_extensions: Option<Extensions>,
    ) -> Result<Self> {
        let cert_status = if let Some(revoked_certs) = &crl.tbs_cert_list.revoked_certificates {
            let mut filter = revoked_certs
                .iter()
                .filter(|rc| rc.serial_number == serial_number);
            match filter.next() {
                None => CertStatus::Good(Null),
                Some(rc) => CertStatus::Revoked(rc.into()),
            }
        } else {
            CertStatus::Good(Null)
        };
        Ok(SingleResponse {
            cert_id: CertId::from_issuer::<D>(issuer, serial_number)?,
            cert_status,
            this_update,
            next_update,
            single_extensions,
        })
    }
}

/// CertID structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// CertID ::= SEQUENCE {
///    hashAlgorithm           AlgorithmIdentifier,
///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
///    serialNumber            CertificateSerialNumber }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber,
}

impl CertId {
    /// Generates the CertId fields by hashing the issuer name and keys. This method will fail with
    /// invalid DER encoding.
    pub fn from_issuer<D: Digest + AssociatedOid>(
        issuer: &Certificate,
        serial_number: SerialNumber,
    ) -> Result<Self> {
        Ok(CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: D::OID,
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(issuer.name_hash::<D>()?)?,
            issuer_key_hash: OctetString::new(issuer.key_hash::<D>()?)?,
            serial_number,
        })
    }
}

/// CertStatus structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// CertStatus ::= CHOICE {
///    good                [0] IMPLICIT NULL,
///    revoked             [1] IMPLICIT RevokedInfo,
///    unknown             [2] IMPLICIT UnknownInfo }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(UnknownInfo),
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// RevokedInfo ::= SEQUENCE {
///    revocationTime          GeneralizedTime,
///    revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<CrlReason>,
}

impl From<RevokedCert> for RevokedInfo {
    fn from(rc: RevokedCert) -> Self {
        Self {
            revocation_time: match rc.revocation_date {
                Time::UtcTime(t) => GeneralizedTime::from_date_time(t.to_date_time()),
                Time::GeneralTime(t) => t.clone(),
            },
            revocation_reason: if let Some(extensions) = &rc.crl_entry_extensions {
                let mut filter = extensions
                    .iter()
                    .filter(|ext| ext.extn_id == CrlReason::OID);
                match filter.next() {
                    None => None,
                    Some(ext) => match CrlReason::from_der(ext.extn_value.as_bytes()) {
                        Ok(reason) => Some(reason),
                        Err(_) => None,
                    },
                }
            } else {
                None
            },
        }
    }
}

impl From<&RevokedCert> for RevokedInfo {
    fn from(rc: &RevokedCert) -> Self {
        Self {
            revocation_time: match rc.revocation_date {
                Time::UtcTime(t) => GeneralizedTime::from_date_time(t.to_date_time()),
                Time::GeneralTime(t) => t.clone(),
            },
            revocation_reason: if let Some(extensions) = &rc.crl_entry_extensions {
                let mut filter = extensions
                    .iter()
                    .filter(|ext| ext.extn_id == CrlReason::OID);
                match filter.next() {
                    None => None,
                    Some(ext) => match CrlReason::from_der(ext.extn_value.as_bytes()) {
                        Ok(reason) => Some(reason),
                        Err(_) => None,
                    },
                }
            } else {
                None
            },
        }
    }
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// UnknownInfo ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type UnknownInfo = Null;
