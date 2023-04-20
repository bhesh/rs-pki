OCSP
====

Parsing and building of OCSP requests and responses

## OCSP Request Building

```rust
use der::DecodePem;
use pki::{
    cert::Certificate,
    ocsp::{builder::OcspRequestBuilder, ext::Nonce, Request, Version},
};
use sha1::Sha1;
use std::fs;

let issuer = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading file");
let issuer = Certificate::from_pem(&issuer).expect("error formatting certificate");

let cert = fs::read_to_string("testdata/amazon-crt.pem").expect("error reading file");
let cert = Certificate::from_pem(&cert).expect("error formatting certificate");

let mut rng = rand::thread_rng();

let serial_number = &cert.tbs_certificate.serial_number;
let req = OcspRequestBuilder::new(Version::V1)
    .with_request(
        Request::from_issuer::<Sha1>(&issuer, serial_number.clone(), None)
            .expect("failed to build Request"),
    )
    .with_extension(Nonce::generate(&mut rng, 32))
    .expect("failed to build extension")
    .build();
```

## OCSP Responses

```rust
use pki::{
    cert::Certificate,
    ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus},
    serial_number::SerialNumber,
};
use der::{Decode, DecodePem};
use std::{fs, io::Read};

let signing_cert = fs::read_to_string("testdata/digicert-ca.pem")
    .expect("error reading signing certificate");
let cert = fs::read_to_string("testdata/amazon-crt.pem").expect("error reading file");
let mut res = Vec::new();
let mut res_file = fs::File::open("testdata/ocsp-amazon-resp.der")
    .expect("error opening OCSP response");
res_file.read_to_end(&mut res).expect("error reading OCSP response");

let signing_cert = Certificate::from_pem(&signing_cert)
    .expect("error parsing certificate");
let cert = Certificate::from_pem(&cert).expect("error formatting certificate");
let serial = &cert.tbs_certificate.serial_number;
let res = OcspResponse::from_der(&res).expect("error loading OCSP response");

match res.response_status {
    OcspResponseStatus::Successful => {
        let response_bytes = &res.response_bytes.expect("no response data");
        let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
            .expect("error encoding response bytes");
        basic_response.verify(&signing_cert).expect("verification failed");
        let mut filter = basic_response
            .tbs_response_data
            .responses
            .iter()
            .filter(|res| &res.cert_id.serial_number == serial)
            .map(|res| &res.cert_status);
        match filter.next() {
            Some(CertStatus::Good(_)) => { /* certificate is good */ }
            Some(_) => panic!("certificate is not valid"),
            None => panic!("serial not in OCSP response"),
        }
    },
    _ => panic!("OCSP response failed"),
}
```

## OCSP Response Building

```rust
use der::{asn1::GeneralizedTime, Decode, DecodePem};
use pki::{
    cert::Certificate,
    crl::CertificateList,
    ocsp::{
        builder::BasicOcspResponseBuilder, OcspResponse, SingleResponse, ResponderId,
        Version,
    },
    serial_number::SerialNumber,
    time::Time,
};
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    RsaPrivateKey,
};
use sha1::Sha1;
use sha2::Sha256;
use std::{fs, io::Read, time::Duration};

let signing_key =
    fs::read_to_string("testdata/rsa2048-sha256-key.pem").expect("error reading file");
let signing_key =
    RsaPrivateKey::from_pkcs8_pem(&signing_key).expect("error formatting signing key");
let signing_key = SigningKey::<Sha256>::new_with_prefix(signing_key);

let public_cert =
    fs::read_to_string("testdata/rsa2048-sha256-crt.pem").expect("error reading file");
let public_cert = Certificate::from_pem(&public_cert).expect("error formatting signing cert");

let issuer = fs::read_to_string("testdata/GoodCACert.pem").expect("error reading file");
let issuer = Certificate::from_pem(&issuer).expect("error formatting issuer");

let mut crl = Vec::new();
let mut crl_file = fs::File::open("testdata/GoodCACRL.crl").expect("error opening CRL");
crl_file.read_to_end(&mut crl).expect("error reading CRL");
let crl = CertificateList::from_der(&crl).expect("error formatting CRL");

// Build response
let res = OcspResponse::successful(
    BasicOcspResponseBuilder::new(
        Version::V1,
        ResponderId::ByName(public_cert.tbs_certificate.subject.clone()),
        GeneralizedTime::from_unix_duration(Duration::from_secs(0))
            .expect("error making produced_at"),
    )
    .with_single_response(
        SingleResponse::from_crl::<Sha1>(
            &crl,
            &issuer,
            SerialNumber::new(&[0xFu8]).expect("error making serial number"),
            match &crl.tbs_cert_list.this_update {
                Time::UtcTime(t) => GeneralizedTime::from_date_time(t.to_date_time()),
                Time::GeneralTime(t) => t.clone(),
            },
            match &crl.tbs_cert_list.next_update {
                Some(time) => match time {
                    Time::UtcTime(t) => Some(GeneralizedTime::from_date_time(t.to_date_time())),
                    Time::GeneralTime(t) => Some(t.clone()),
                },
                None => None,
            },
            None,
        )
        .expect("error making single response"),
    )
    .build_and_sign(&signing_key, Some(Vec::from([public_cert.clone()])))
    .expect("error signing response"),
)
.expect("error encoding ocsp response");
```
