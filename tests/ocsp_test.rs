//! OCSP Testing

use const_oid::db;
use der::{Decode, DecodePem, Encode};
use pki::{
    cert::Certificate,
    ocsp::{
        builder::OcspRequestBuilder, ext::Nonce, BasicOcspResponse, CertId, CertStatus,
        OcspRequest, OcspResponse, OcspResponseStatus, Version,
    },
};
use sha1::Sha1;
use std::{fs, io::Read};

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//     Certificate ID:
//         Hash Algorithm: sha1
//         Issuer Name Hash: A87E303106E4E88565CFE952598FA6DA7C00532F
//         Issuer Key Hash: 246E2B2DD06A925151256901AA9A47A689E74020
//         Serial Number: 0521674F03575F5BA5BD6B2BCCA0EB4B
//     Request Extensions:
//         OCSP Nonce:
//             0410D30E67AB08601B53B09AFE76657285A0
// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: 246E2B2DD06A925151256901AA9A47A689E74020
//     Produced At: Apr 17 12:36:29 2023 GMT
//     Responses:
//     Certificate ID:
//         Hash Algorithm: sha1
//         Issuer Name Hash: A87E303106E4E88565CFE952598FA6DA7C00532F
//         Issuer Key Hash: 246E2B2DD06A925151256901AA9A47A689E74020
//         Serial Number: 0521674F03575F5BA5BD6B2BCCA0EB4B
//     Cert Status: good
//     This Update: Apr 17 12:21:01 2023 GMT
//     Next Update: Apr 24 11:36:01 2023 GMT
//
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         00:26:b0:7a:7b:a4:3f:7c:0c:c8:0b:66:95:ad:e1:b5:ae:c8:
//         df:8e:87:f9:1c:0b:ce:5d:8b:91:da:05:b3:e5:b4:da:35:80:
//         7e:65:a0:b5:31:b3:a6:3a:d6:19:a5:dc:98:e8:fb:bb:d9:f1:
//         8b:1a:8a:7d:1a:00:f3:e9:4d:96:75:bc:69:ee:70:1f:03:8f:
//         f7:12:89:03:a5:77:84:f2:56:25:a8:8c:0c:77:0e:05:99:d1:
//         7e:42:11:91:9a:0c:49:1e:3e:5e:dd:01:bf:56:d6:1a:dc:83:
//         24:56:dd:ae:a0:f4:f8:60:fb:b3:76:c1:05:9e:98:9f:e7:54:
//         a8:27:4e:6a:35:81:c5:98:ff:45:b2:49:b1:b1:ae:2c:fa:a5:
//         65:37:32:b0:d7:ca:a5:1b:69:b5:9e:48:0c:b4:c7:52:81:32:
//         6e:e0:50:7b:e7:9a:e6:3f:33:fe:ea:c3:be:95:bb:e9:a7:72:
//         b9:be:f4:ce:b0:87:d1:1f:de:96:7c:f3:5e:70:0b:0d:8e:97:
//         b1:0c:40:14:00:0b:28:d7:08:04:08:2f:b7:03:bf:c2:4c:c1:
//         17:7f:95:e4:87:1e:25:2f:ab:cd:d6:d4:55:be:df:bf:99:5f:
//         cf:4e:59:98:aa:00:6c:d3:1b:44:58:87:71:b6:48:c6:f3:e0:
//         a2:9b:63:91

const ISSUER_NAME_HASH: &[u8] = &[
    0xa8, 0x7e, 0x30, 0x31, 0x06, 0xe4, 0xe8, 0x85, 0x65, 0xcf, 0xe9, 0x52, 0x59, 0x8f, 0xa6, 0xda,
    0x7c, 0x00, 0x53, 0x2f,
];

const ISSUER_KEY_HASH: &[u8] = &[
    0x24, 0x6e, 0x2b, 0x2d, 0xd0, 0x6a, 0x92, 0x51, 0x51, 0x25, 0x69, 0x01, 0xaa, 0x9a, 0x47, 0xa6,
    0x89, 0xe7, 0x40, 0x20,
];

const SERIAL_NUMBER: &[u8] = &[
    0x05, 0x21, 0x67, 0x4f, 0x03, 0x57, 0x5f, 0x5b, 0xa5, 0xbd, 0x6b, 0x2b, 0xcc, 0xa0, 0xeb, 0x4b,
];

const NONCE: &[u8] = &[
    0x04, 0x10, 0xd3, 0x0e, 0x67, 0xab, 0x08, 0x60, 0x1b, 0x53, 0xb0, 0x9a, 0xfe, 0x76, 0x65, 0x72,
    0x85, 0xa0,
];

#[test]
fn ocsp_request_sanity() {
    let mut req = fs::File::open("testdata/ocsp-amazon-req.der").expect("error opening file");
    let mut data = Vec::new();
    req.read_to_end(&mut data).expect("error reading file");
    let req = OcspRequest::from_der(&data).expect("error reading OCSP request");
    assert_eq!(&data, &req.to_der().expect("error encoding request"));
}

#[test]
fn ocsp_build_request() {
    let issuer = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading file");
    let issuer = Certificate::from_pem(&issuer).expect("error formatting certificate");

    let cert = fs::read_to_string("testdata/amazon-crt.pem").expect("error reading file");
    let cert = Certificate::from_pem(&cert).expect("error formatting certificate");

    let serial_number = &cert.tbs_certificate.serial_number;
    assert_eq!(SERIAL_NUMBER, serial_number.as_bytes());

    let req = OcspRequestBuilder::new(Version::V1)
        .with_certid(
            CertId::from_issuer::<Sha1>(&issuer, serial_number.clone())
                .expect("failed to build CertId"),
        )
        .with_extension(Nonce::new(NONCE))
        .expect("failed to build extension")
        .build();
    let mut ifile = fs::File::open("testdata/ocsp-amazon-req.der").expect("error opening file");
    let mut data = Vec::new();
    ifile.read_to_end(&mut data).expect("error reading file");
    assert_eq!(&data, &req.to_der().expect("failed to encode OCSP request"));
}

#[test]
fn ocsp_response_sanity() {
    let mut ifile = fs::File::open("testdata/ocsp-amazon-resp.der").expect("error opening file");
    let mut res = Vec::new();
    ifile.read_to_end(&mut res).expect("error reading file");
    let res = OcspResponse::from_der(&res).expect("error loading OCSP response");
    assert_eq!(res.response_status, OcspResponseStatus::Successful);

    let response_bytes = &res.response_bytes.expect("no response data");
    assert_eq!(
        &response_bytes.response_type,
        &db::rfc6960::ID_PKIX_OCSP_BASIC
    );
    let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
        .expect("error encoding response bytes");

    // ocsp.digicert.com does not seem to support nonces...
    //
    // let ext = &basic_response.tbs_response_data.response_extensions.expect("no extensions")[0];
    // assert_eq!(&ext.extn_id, &db::rfc6960::ID_PKIX_OCSP_NONCE);
    // assert_eq!(ext.critical, false);
    // assert_eq!(&ext.extn_value.as_bytes(), &NONCE);
    let single_response = &basic_response.tbs_response_data.responses[0];

    let cert_id = &single_response.cert_id;
    assert_eq!(&cert_id.issuer_name_hash.as_bytes(), &ISSUER_NAME_HASH);
    assert_eq!(&cert_id.issuer_key_hash.as_bytes(), &ISSUER_KEY_HASH);
    assert_eq!(&cert_id.serial_number.as_bytes(), &SERIAL_NUMBER);

    let cert_status = &single_response.cert_status;
    match cert_status {
        CertStatus::Good(_) => {}
        _ => panic!("status is not good"),
    };
}

#[test]
fn ocsp_verify_response() {
    let issuer = fs::read_to_string("testdata/digicert-ca.pem").expect("error reading file");
    let issuer = Certificate::from_pem(&issuer).expect("error formatting certificate");

    let mut ifile = fs::File::open("testdata/ocsp-amazon-resp.der").expect("error opening file");
    let mut res = Vec::new();
    ifile.read_to_end(&mut res).expect("error reading file");
    let res = OcspResponse::from_der(&res).expect("error loading OCSP response");
    assert_eq!(res.response_status, OcspResponseStatus::Successful);

    let response_bytes = &res.response_bytes.expect("no response data");
    assert_eq!(
        &response_bytes.response_type,
        &db::rfc6960::ID_PKIX_OCSP_BASIC
    );
    let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
        .expect("error encoding response bytes");

    basic_response.verify(&issuer).expect("verification failed");
}
