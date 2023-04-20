PKI
===

A PKI library written in Rust.

This library extends a lot of RustCrypto but adds some additional convenience functionality.

## Modules

* cert (Certificate Objects)
* crl (Certificate List Objects)
* ocsp (OCSP Objects)
* req (Certificate Request Objects)

## Examples

### Certificate Verification

```rust
use pki::cert::Certificate;
use der::DecodePem;
use std::fs;

let issuer = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading issuer");
let cert = fs::read_to_string("testdata/amazon-crt.pem").expect("error reading certificate");

let issuer = Certificate::from_pem(&issuer).expect("error parsing certificate");
let cert = Certificate::from_pem(&cert).expect("error parsing certificate");
cert.verify(&issuer).expect("verification failed");
```

### CRL Verification

```rust
use pki::{cert::Certificate, crl::CertificateList};
use der::{Decode, DecodePem};
use std::{fs, io::Read};

let ca = fs::read_to_string("testdata/GoodCACert.pem").expect("error reading CA");
let mut crl = Vec::new();
let mut crl_file = fs::File::open("testdata/GoodCACRL.crl").expect("error opening CRL");
crl_file.read_to_end(&mut crl).expect("error reading CRL");

let ca = Certificate::from_pem(&ca).expect("error parsing CA");
let crl = CertificateList::from_der(&crl).expect("error parsing CRL");
crl.verify(&ca).expect("verification failed");
```

### CSR Verification

```rust
use pki::req::CertReq;
use der::DecodePem;
use std::fs;

let req = fs::read_to_string("testdata/rsa2048-sha256-req.pem").expect("error reading CSR");

let req = CertReq::from_pem(&req).expect("error parsing CSR");
req.verify().expect("verification failed");
```

### OCSP Verification

```rust
use pki::{
    cert::Certificate,
    ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus},
};
use der::{Decode, DecodePem};
use std::{fs, io::Read};

let signing_cert = fs::read_to_string("testdata/digicert-ca.pem")
    .expect("error reading signing certificate");
let mut res = Vec::new();
let mut res_file = fs::File::open("testdata/ocsp-amazon-resp.der")
    .expect("error opening OCSP response");
res_file.read_to_end(&mut res).expect("error reading OCSP response");

let signing_cert = Certificate::from_pem(&signing_cert)
    .expect("error parsing certificate");
let res = OcspResponse::from_der(&res).expect("error loading OCSP response");
match res.response_status {
    OcspResponseStatus::Successful => {
        let response_bytes = &res.response_bytes.expect("no response data");
        let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
            .expect("error encoding response bytes");
        basic_response.verify(&signing_cert).expect("verification failed");
    },
    _ => panic!("OCSP response failed"),
}
```
