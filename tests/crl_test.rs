//! CRL Tests

use der::{Decode, DecodePem};
use pki::{cert::Certificate, crl::CertificateList, error::Error};
use std::{fs, io::Read};

fn load_crl() -> CertificateList {
    let mut ifile = fs::File::open("testdata/GoodCACRL.crl").expect("error reading CRL");
    let mut crl = Vec::new();
    ifile.read_to_end(&mut crl).expect("error reading CRL file");
    CertificateList::from_der(&crl).expect("error parsing CRL")
}

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn crl_verify_rsa_good() {
    let cert = fs::read_to_string("testdata/GoodCACert.pem").expect("error reading ca file");
    let cert = Certificate::from_pem(&cert).expect("error parsing CA");
    let crl = load_crl();
    crl.verify(&cert).expect("error verifying");
}

#[cfg(all(feature = "rsa", feature = "sha2"))]
#[test]
fn crl_verify_rsa_bad() {
    let cert = fs::read_to_string("testdata/rsa2048-sha256-crt.pem")
        .expect("error reading certificate file");
    let cert = Certificate::from_pem(&cert).expect("error parsing certificate");
    let crl = load_crl();
    match crl.verify(&cert) {
        Ok(_) => panic!("should not have been good"),
        Err(Error::Verification) => {}
        Err(e) => panic!("{:?}", e),
    }
}
