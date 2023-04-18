//! OCSP Request and Response Building

use crate::{
    cert::Certificate,
    ocsp::{
        ext::{AsExtension, Nonce},
        CertId, OcspRequest, Request, Signature, TbsRequest, Version,
    },
};
use alloc::vec::Vec;
use der::{asn1::BitString, Encode};
use rand_core::CryptoRngCore;
use signature::{Keypair, SignatureEncoding, Signer};
use x509_cert::{ext::pkix::name::GeneralName, spki::DynSignatureAlgorithmIdentifier};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NonceTooBig,
    NonceTooSmall,
    Asn1(der::Error),
    PublicKey(x509_cert::spki::Error),
    Signature(signature::Error),
}

impl From<der::Error> for Error {
    fn from(other: der::Error) -> Error {
        Error::Asn1(other)
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(other: x509_cert::spki::Error) -> Error {
        Error::PublicKey(other)
    }
}

impl From<signature::Error> for Error {
    fn from(other: signature::Error) -> Error {
        Error::Signature(other)
    }
}

pub struct OcspRequestBuilder {
    /// TbsRequest
    tbs_request: TbsRequest,
}

impl OcspRequestBuilder {
    pub fn new(version: Version) -> Self {
        Self {
            tbs_request: TbsRequest {
                version,
                requestor_name: None,
                request_list: Vec::new(),
                request_extensions: None,
            },
        }
    }

    pub fn with_requestor_name(&mut self, name: GeneralName) -> &mut OcspRequestBuilder {
        self.tbs_request.requestor_name = Some(name);
        self
    }

    pub fn with_request(&mut self, request: Request) -> &mut OcspRequestBuilder {
        self.tbs_request.request_list.push(request);
        self
    }

    pub fn with_certid(&mut self, cert_id: CertId) -> &mut OcspRequestBuilder {
        self.with_request(Request {
            req_cert: cert_id,
            single_request_extensions: None,
        })
    }

    pub fn with_extension<E: AsExtension>(&mut self, ext: E) -> Result<&mut OcspRequestBuilder> {
        if let Some(extensions) = self.tbs_request.request_extensions.as_mut() {
            extensions.push(ext.to_extension()?);
        } else {
            self.tbs_request.request_extensions = Some(Vec::from([ext.to_extension()?]));
        }
        Ok(self)
    }

    pub fn with_nonce<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        length: usize,
    ) -> Result<&mut OcspRequestBuilder> {
        self.with_extension(Nonce::generate(rng, length))
    }

    pub fn build_and_sign<S, Sig>(
        &self,
        signer: &mut S,
        certificate_chain: Option<Vec<Certificate>>,
    ) -> Result<OcspRequest>
    where
        S: Keypair,
        S: Signer<Sig>,
        S::VerifyingKey: DynSignatureAlgorithmIdentifier,
        Sig: SignatureEncoding,
    {
        let verifying_key = signer.verifying_key();
        let signature_algorithm = verifying_key.signature_algorithm_identifier()?;
        let signature = signer.try_sign(&self.tbs_request.to_der()?)?;
        let signature = BitString::from_bytes(signature.to_bytes().as_ref())?;

        let optional_signature = Some(Signature {
            signature_algorithm,
            signature,
            certs: certificate_chain,
        });

        Ok(OcspRequest {
            tbs_request: self.tbs_request.clone(),
            optional_signature,
        })
    }

    pub fn build(&self) -> OcspRequest {
        OcspRequest {
            tbs_request: self.tbs_request.clone(),
            optional_signature: None,
        }
    }
}
