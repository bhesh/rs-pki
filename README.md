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

let issuer = Certificate::from_pem(&issuer_pem).expect("error parsing certificate");
let cert = Certificate::from_pem(&cert_pem).expect("error parsing certificate");
cert.verify(&issuer).expect("verification failed");
```

### CRL Verification

```rust
use pki::{cert::Certificate, crl::CertificateList};
use der::{Decode, DecodePem};

let ca = Certificate::from_pem(&ca_pem).expect("error parsing CA");
let crl = CertificateList::from_der(&crl_der).expect("error parsing CRL");
crl.verify(&issuer).expect("verification failed");
```

### CSR Verification

```rust
use pki::req::CertReq;
use der::DecodePem;

let req = CertReq::from_pem(&req_pem).expect("error parsing CSR");
req.verify().expect("verification failed");
```

### OCSP Verification

```rust
use pki::{
    cert::Certificate,
    ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus},
};
use der::{Decode, DecodePem};

let signing_cert = Certificate::from_pem(&signing_cert_pem).expect("error parsing certificate");
let res = OcspResponse::from_der(&response).expect("error loading OCSP response");
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
