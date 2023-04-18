//! OCSP
//!
//! The ocsp module features encoders and decoders for the structures defined in
//! [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960).

pub mod builder;
mod request;
mod response;

pub use request::{OcspRequest, Request, Signature, TbsRequest};
pub use response::{
    AcceptableResponses, ArchiveCutoff, BasicOcspResponse, CertId, CertStatus, CrlId, KeyHash,
    OcspNoCheck, OcspResponse, OcspResponseStatus, PreferredSignatureAlgorithm,
    PreferredSignatureAlgorithms, ResponderId, ResponseBytes, ResponseData, RevokedInfo,
    ServiceLocator, SingleResponse, UnknownInfo, Version,
};
