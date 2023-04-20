//! OCSP Extensions

use crate::{
    ext::{pkix::AuthorityInfoAccessSyntax, Extension},
    name::Name,
    spki::AlgorithmIdentifierOwned,
};
use alloc::vec::Vec;
use const_oid::db::rfc6960::{
    ID_PKIX_OCSP_ARCHIVE_CUTOFF, ID_PKIX_OCSP_CRL, ID_PKIX_OCSP_NONCE, ID_PKIX_OCSP_PREF_SIG_ALGS,
    ID_PKIX_OCSP_RESPONSE, ID_PKIX_OCSP_SERVICE_LOCATOR,
};
use der::{
    asn1::{GeneralizedTime, Ia5String, ObjectIdentifier, OctetString, Uint},
    Encode, Sequence,
};
use rand_core::CryptoRngCore;

/// Helps simplify the coversion of OCSP extensions
pub trait AsExtension {
    fn to_extension(&self) -> Result<Extension, der::Error>;
}

/// Nonce extension as defined in [RFC 6960 Section 4.4.1].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    bytes: Vec<u8>,
}

impl Nonce {
    pub fn new(nonce: &[u8]) -> Self {
        Self {
            bytes: Vec::from(nonce),
        }
    }

    /// Creates a new Nonce object given a random generator and a length
    pub fn generate<R: CryptoRngCore>(rng: &mut R, length: usize) -> Self {
        let mut bytes = Vec::with_capacity(length);
        let mut random = [0u8; 32];
        while bytes.len() < length {
            rng.fill_bytes(&mut random);
            bytes.extend_from_slice(&random);
        }
        bytes.resize(length, 0);
        Self { bytes }
    }
}

impl AsExtension for Nonce {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_NONCE,
            critical: false,
            extn_value: OctetString::new(self.bytes.as_slice())?,
        })
    }
}

/// CrlReferences extension as defined in [RFC 6960 Section 4.4.2]
pub type CrlReferences = Vec<CrlId>;

impl AsExtension for CrlReferences {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_CRL,
            critical: false,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// CrlID structure as defined in [RFC 6960 Section 4.4.2].
///
/// ```text
/// CrlID ::= SEQUENCE {
///     crlUrl               [0] EXPLICIT IA5String OPTIONAL,
///     crlNum               [1] EXPLICIT INTEGER OPTIONAL,
///     crlTime              [2] EXPLICIT GeneralizedTime OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlId {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_url: Option<Ia5String>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_num: Option<Uint>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_time: Option<GeneralizedTime>,
}

/// AcceptableResponses structure as defined in [RFC 6960 Section 4.4.3].
///
/// ```text
// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
///
/// [RFC 6960 Section 4.4.3]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.3
pub type AcceptableResponses = Vec<ObjectIdentifier>;

impl AsExtension for AcceptableResponses {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_RESPONSE,
            critical: false,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// ArchiveCutoff structure as defined in [RFC 6960 Section 4.4.4].
///
/// ```text
// ArchiveCutoff ::= GeneralizedTime
/// ```
///
/// [RFC 6960 Section 4.4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.4
pub type ArchiveCutoff = GeneralizedTime;

impl AsExtension for ArchiveCutoff {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_ARCHIVE_CUTOFF,
            critical: false,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// ServiceLocator structure as defined in [RFC 6960 Section 4.4.6].
///
/// ```text
/// ServiceLocator ::= SEQUENCE {
///    issuer                  Name,
///    locator                 AuthorityInfoAccessSyntax }
/// ```
///
/// [RFC 6960 Section 4.4.6]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.6
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ServiceLocator {
    pub issuer: Name,
    pub locator: Option<AuthorityInfoAccessSyntax>,
}

impl AsExtension for ServiceLocator {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_SERVICE_LOCATOR,
            critical: false,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// PreferredSignatureAlgorithms structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
pub type PreferredSignatureAlgorithms = Vec<PreferredSignatureAlgorithm>;

impl AsExtension for PreferredSignatureAlgorithms {
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: ID_PKIX_OCSP_PREF_SIG_ALGS,
            critical: false,
            extn_value: OctetString::new(self.to_der()?)?,
        })
    }
}

/// PreferredSignatureAlgorithm structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithm ::= SEQUENCE {
///    sigIdentifier   AlgorithmIdentifier,
///    certIdentifier  AlgorithmIdentifier OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PreferredSignatureAlgorithm {
    pub sig_identifier: AlgorithmIdentifierOwned,
    pub cert_identifier: Option<AlgorithmIdentifierOwned>,
}
