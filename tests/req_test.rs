//! Certificate Request Tests

use pki::{error::Error, req::CertReq};
use der::{asn1::BitString, DecodePem};
use std::fs;

#[test]
fn req_verify_rsa_good() {
    let req = fs::read_to_string("testdata/rsa2048-sha256-req.pem").expect("error reading CSR");
    let req = CertReq::from_pem(&req).expect("error parsing certificate request");
    req.verify().expect("error verifying");
}

#[test]
fn req_verify_rsa_bad() {
    let req = fs::read_to_string("testdata/rsa2048-sha256-req.pem").expect("error reading CSR");
    let mut req = CertReq::from_pem(&req).expect("error parsing certificate request");

    // Modify the signature slightly
    let mut sig = match req.signature.as_bytes() {
        Some(s) => Vec::from(s),
        None => panic!("invalid certificate request"),
    };
    sig[0] = if sig[0] == 0 { 1 } else { 0 };
    req.signature = BitString::from_bytes(&sig).expect("error making BitString");

    // Signature should fail
    match req.verify() {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}
