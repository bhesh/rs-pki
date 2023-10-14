//! Certificate Tests

use der::DecodePem;
use pki::{cert::Certificate, error::Error};
use std::fs;

#[cfg(feature = "rsa")]
#[test]
fn cert_verify_rsa_sha1_good() {
    let cert =
        fs::read_to_string("testdata/rsa2048-sha1-crt.pem").expect("error loading certificate");
    let cert = Certificate::from_pem(&cert).expect("error parsing certificate");
    cert.verify(&cert).expect("error verifying");
}

#[cfg(feature = "rsa")]
#[test]
fn cert_verify_rsa_sha1_bad() {
    let cert1 =
        fs::read_to_string("testdata/rsa2048-sha1-crt.pem").expect("error loading certificate");
    let cert1 = Certificate::from_pem(&cert1).expect("error parsing certificate");
    let cert2 =
        fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error loading certificate");
    let cert2 = Certificate::from_pem(&cert2).expect("error parsing certificate");
    match cert1.verify(&cert2) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn cert_verify_rsa_sha256_good() {
    let cert =
        fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error loading certificate");
    let cert = Certificate::from_pem(&cert).expect("error parsing certificate");
    cert.verify(&cert).expect("error verifying");
}

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn cert_verify_rsa_sha256_bad() {
    let cert1 =
        fs::read_to_string("testdata/rsa2048-sha1-crt.pem").expect("error loading certificate");
    let cert1 = Certificate::from_pem(&cert1).expect("error parsing certificate");
    let cert2 =
        fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error loading certificate");
    let cert2 = Certificate::from_pem(&cert2).expect("error parsing certificate");
    match cert2.verify(&cert1) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}
