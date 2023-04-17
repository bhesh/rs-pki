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

#[cfg(test)]
mod tests {
    use crate::{
        cert::Certificate,
        ocsp::{
            builder::OcspRequestBuilder, BasicOcspResponse, CertId, CertStatus, OcspRequest,
            OcspResponse, OcspResponseStatus, Version,
        },
    };
    use const_oid::db;
    use der::{asn1::OctetString, Decode, DecodePem, Encode};
    use x509_cert::{ext::Extension, serial_number::SerialNumber, spki::AlgorithmIdentifier};

    const SIGNING_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIEizCCA3OgAwIBAgIQDI7gyQ1qiRWIBAYe4kH5rzANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0yODA4MDExMjAwMDBaMEQxCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxHjAcBgNVBAMTFURpZ2lDZXJ0IEdsb2Jh
bCBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANNIfL7zBYZd
W9UvhU5L4IatFaxhz1uvPmoKR/uadpFgC4przc/cV35gmAvkVNlW7SHMArZagV+X
au4CLyMnuG3UsOcGAngLH1ypmTb+u6wbBfpXzYEQQGfWMItYNdSWYb7QjHqXnxr5
IuYUL6nG6AEfq/gmD6yOTSwyOR2Bm40cZbIc22GoiS9g5+vCShjEbyrpEJIJ7RfR
ACvmfe8EiRROM6GyD5eHn7OgzS+8LOy4g2gxPR/VSpAQGQuBldYpdlH5NnbQtwl6
OErXb4y/E3w57bqukPyV93t4CTZedJMeJfD/1K2uaGvG/w/VNfFVbkhJ+Pi474j4
8V4Rd6rfArMCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0P
AQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
c3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmw0LmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmwwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmwwPQYD
VR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
ZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFCRuKy3QapJRUSVpAaqaR6aJ50AgMB8GA1Ud
IwQYMBaAFE4iVCAYlebjbuYP+vq5Eu0GF485MA0GCSqGSIb3DQEBCwUAA4IBAQAL
OYSR+ZfrqoGvhOlaOJL84mxZvzbIRacxAxHhBsCsMsdaVSnaT0AC9aHesO3ewPj2
dZ12uYf+QYB6z13jAMZbAuabeGLJ3LhimnftiQjXS8X9Q9ViIyfEBFltcT8jW+rZ
8uckJ2/0lYDblizkVIvP6hnZf1WZUXoOLRg9eFhSvGNoVwvdRLNXSmDmyHBwW4co
atc7TlJFGa8kBpJIERqLrqwYElesA8u49L3KJg6nwd3jM+/AVTANlVlOnAM2BvjA
jxSZnE0qnsHhfTuvcqdFuhOWKU4Z0BqYBvQ3lBetoxi6PrABDJXWKTUgNX31EGDk
92hiHuwZ4STyhxGs6QiA
-----END CERTIFICATE-----";

    // OCSP Request Data:
    //     Version: 1 (0x0)
    //     Requestor List:
    //         Certificate ID:
    //             Hash Algorithm: sha1
    //             Issuer Name Hash: A87E303106E4E88565CFE952598FA6DA7C00532F
    //             Issuer Key Hash: 246E2B2DD06A925151256901AA9A47A689E74020
    //             Serial Number: 0521674F03575F5BA5BD6B2BCCA0EB4B
    //     Request Extensions:
    //         OCSP Nonce:
    //             04102AB01B4B16CB56FAE4D19F53964B6FA7

    const REQ_DATA: &[u8] = &[
        0x30, 0x74, 0x30, 0x72, 0x30, 0x4b, 0x30, 0x49, 0x30, 0x47, 0x30, 0x07, 0x06, 0x05, 0x2b,
        0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14, 0xa8, 0x7e, 0x30, 0x31, 0x06, 0xe4, 0xe8, 0x85, 0x65,
        0xcf, 0xe9, 0x52, 0x59, 0x8f, 0xa6, 0xda, 0x7c, 0x00, 0x53, 0x2f, 0x04, 0x14, 0x24, 0x6e,
        0x2b, 0x2d, 0xd0, 0x6a, 0x92, 0x51, 0x51, 0x25, 0x69, 0x01, 0xaa, 0x9a, 0x47, 0xa6, 0x89,
        0xe7, 0x40, 0x20, 0x02, 0x10, 0x05, 0x21, 0x67, 0x4f, 0x03, 0x57, 0x5f, 0x5b, 0xa5, 0xbd,
        0x6b, 0x2b, 0xcc, 0xa0, 0xeb, 0x4b, 0xa2, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x2a, 0xb0, 0x1b,
        0x4b, 0x16, 0xcb, 0x56, 0xfa, 0xe4, 0xd1, 0x9f, 0x53, 0x96, 0x4b, 0x6f, 0xa7,
    ];

    const ISSUER_NAME_HASH: &[u8] = &[
        0xa8, 0x7e, 0x30, 0x31, 0x06, 0xe4, 0xe8, 0x85, 0x65, 0xcf, 0xe9, 0x52, 0x59, 0x8f, 0xa6,
        0xda, 0x7c, 0x00, 0x53, 0x2f,
    ];

    const ISSUER_KEY_HASH: &[u8] = &[
        0x24, 0x6e, 0x2b, 0x2d, 0xd0, 0x6a, 0x92, 0x51, 0x51, 0x25, 0x69, 0x01, 0xaa, 0x9a, 0x47,
        0xa6, 0x89, 0xe7, 0x40, 0x20,
    ];

    const SERIAL_NUMBER: &[u8] = &[
        0x05, 0x21, 0x67, 0x4f, 0x03, 0x57, 0x5f, 0x5b, 0xa5, 0xbd, 0x6b, 0x2b, 0xcc, 0xa0, 0xeb,
        0x4b,
    ];

    const NONCE: &[u8] = &[
        0x04, 0x10, 0x2a, 0xb0, 0x1b, 0x4b, 0x16, 0xcb, 0x56, 0xfa, 0xe4, 0xd1, 0x9f, 0x53, 0x96,
        0x4b, 0x6f, 0xa7,
    ];

    // OCSP Response Data:
    //     OCSP Response Status: successful (0x0)
    //     Response Type: Basic OCSP Response
    //     Version: 1 (0x0)
    //     Responder Id: 246E2B2DD06A925151256901AA9A47A689E74020
    //     Produced At: Apr 15 12:36:27 2023 GMT
    //     Responses:
    //     Certificate ID:
    //         Hash Algorithm: sha1
    //         Issuer Name Hash: A87E303106E4E88565CFE952598FA6DA7C00532F
    //         Issuer Key Hash: 246E2B2DD06A925151256901AA9A47A689E74020
    //         Serial Number: 0521674F03575F5BA5BD6B2BCCA0EB4B
    //     Cert Status: good
    //     This Update: Apr 15 12:21:01 2023 GMT
    //     Next Update: Apr 22 11:36:01 2023 GMT
    //     Signature Algorithm: sha256WithRSAEncryption
    //         19:1b:97:13:66:8f:0b:28:60:0d:c2:de:2f:7c:9e:9a:cb:7f:
    //         d1:a5:23:a5:fc:5d:c3:01:93:0f:05:8d:16:7f:7a:68:6c:ed:
    //         9a:e7:da:e9:df:d4:32:b7:02:7b:d0:55:59:89:c1:03:59:12:
    //         31:33:dc:07:91:90:e8:22:ee:58:e4:fe:e9:c0:ec:1e:e7:47:
    //         ef:7c:7f:5b:f4:d0:1e:1f:32:66:8a:67:d5:2f:af:64:d8:31:
    //         22:a8:4b:3d:75:b3:be:66:26:69:c6:3b:c3:9e:60:a5:27:3f:
    //         a4:65:d7:27:f3:ab:bf:44:6a:fe:a4:ab:ac:ce:54:37:8b:97:
    //         36:00:88:87:94:cf:f8:e9:f4:2a:10:6f:17:c9:c6:67:dc:53:
    //         75:f9:7b:61:00:45:4c:9e:6a:d2:50:4f:83:33:cb:6a:7f:11:
    //         d3:76:f4:7f:b6:e6:45:eb:fd:11:52:2e:49:3c:dd:19:72:45:
    //         6e:e0:38:e0:ac:06:ef:a1:d6:91:34:fb:9a:60:0f:a5:7c:37:
    //         1a:00:42:a4:20:10:33:42:0a:27:c0:2f:18:15:8f:bc:31:82:
    //         ac:2a:b7:cb:6a:a8:36:0d:cf:72:3a:94:9e:a5:18:76:9f:6a:
    //         a9:4f:d7:e5:e0:07:1a:36:57:8d:c6:2f:60:29:08:17:75:28:
    //         08:da:08:40

    const RES_DATA: &[u8] = &[
        0x30, 0x82, 0x01, 0xd3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0xcc, 0x30, 0x82, 0x01, 0xc8,
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0xb9,
        0x30, 0x82, 0x01, 0xb5, 0x30, 0x81, 0x9e, 0xa2, 0x16, 0x04, 0x14, 0x24, 0x6e, 0x2b, 0x2d,
        0xd0, 0x6a, 0x92, 0x51, 0x51, 0x25, 0x69, 0x01, 0xaa, 0x9a, 0x47, 0xa6, 0x89, 0xe7, 0x40,
        0x20, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x33, 0x30, 0x34, 0x31, 0x35, 0x31, 0x32, 0x33, 0x36,
        0x32, 0x37, 0x5a, 0x30, 0x73, 0x30, 0x71, 0x30, 0x49, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0xa8, 0x7e, 0x30, 0x31, 0x06, 0xe4, 0xe8, 0x85,
        0x65, 0xcf, 0xe9, 0x52, 0x59, 0x8f, 0xa6, 0xda, 0x7c, 0x00, 0x53, 0x2f, 0x04, 0x14, 0x24,
        0x6e, 0x2b, 0x2d, 0xd0, 0x6a, 0x92, 0x51, 0x51, 0x25, 0x69, 0x01, 0xaa, 0x9a, 0x47, 0xa6,
        0x89, 0xe7, 0x40, 0x20, 0x02, 0x10, 0x05, 0x21, 0x67, 0x4f, 0x03, 0x57, 0x5f, 0x5b, 0xa5,
        0xbd, 0x6b, 0x2b, 0xcc, 0xa0, 0xeb, 0x4b, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x33,
        0x30, 0x34, 0x31, 0x35, 0x31, 0x32, 0x32, 0x31, 0x30, 0x31, 0x5a, 0xa0, 0x11, 0x18, 0x0f,
        0x32, 0x30, 0x32, 0x33, 0x30, 0x34, 0x32, 0x32, 0x31, 0x31, 0x33, 0x36, 0x30, 0x31, 0x5a,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x01, 0x00, 0x19, 0x1b, 0x97, 0x13, 0x66, 0x8f, 0x0b, 0x28, 0x60, 0x0d,
        0xc2, 0xde, 0x2f, 0x7c, 0x9e, 0x9a, 0xcb, 0x7f, 0xd1, 0xa5, 0x23, 0xa5, 0xfc, 0x5d, 0xc3,
        0x01, 0x93, 0x0f, 0x05, 0x8d, 0x16, 0x7f, 0x7a, 0x68, 0x6c, 0xed, 0x9a, 0xe7, 0xda, 0xe9,
        0xdf, 0xd4, 0x32, 0xb7, 0x02, 0x7b, 0xd0, 0x55, 0x59, 0x89, 0xc1, 0x03, 0x59, 0x12, 0x31,
        0x33, 0xdc, 0x07, 0x91, 0x90, 0xe8, 0x22, 0xee, 0x58, 0xe4, 0xfe, 0xe9, 0xc0, 0xec, 0x1e,
        0xe7, 0x47, 0xef, 0x7c, 0x7f, 0x5b, 0xf4, 0xd0, 0x1e, 0x1f, 0x32, 0x66, 0x8a, 0x67, 0xd5,
        0x2f, 0xaf, 0x64, 0xd8, 0x31, 0x22, 0xa8, 0x4b, 0x3d, 0x75, 0xb3, 0xbe, 0x66, 0x26, 0x69,
        0xc6, 0x3b, 0xc3, 0x9e, 0x60, 0xa5, 0x27, 0x3f, 0xa4, 0x65, 0xd7, 0x27, 0xf3, 0xab, 0xbf,
        0x44, 0x6a, 0xfe, 0xa4, 0xab, 0xac, 0xce, 0x54, 0x37, 0x8b, 0x97, 0x36, 0x00, 0x88, 0x87,
        0x94, 0xcf, 0xf8, 0xe9, 0xf4, 0x2a, 0x10, 0x6f, 0x17, 0xc9, 0xc6, 0x67, 0xdc, 0x53, 0x75,
        0xf9, 0x7b, 0x61, 0x00, 0x45, 0x4c, 0x9e, 0x6a, 0xd2, 0x50, 0x4f, 0x83, 0x33, 0xcb, 0x6a,
        0x7f, 0x11, 0xd3, 0x76, 0xf4, 0x7f, 0xb6, 0xe6, 0x45, 0xeb, 0xfd, 0x11, 0x52, 0x2e, 0x49,
        0x3c, 0xdd, 0x19, 0x72, 0x45, 0x6e, 0xe0, 0x38, 0xe0, 0xac, 0x06, 0xef, 0xa1, 0xd6, 0x91,
        0x34, 0xfb, 0x9a, 0x60, 0x0f, 0xa5, 0x7c, 0x37, 0x1a, 0x00, 0x42, 0xa4, 0x20, 0x10, 0x33,
        0x42, 0x0a, 0x27, 0xc0, 0x2f, 0x18, 0x15, 0x8f, 0xbc, 0x31, 0x82, 0xac, 0x2a, 0xb7, 0xcb,
        0x6a, 0xa8, 0x36, 0x0d, 0xcf, 0x72, 0x3a, 0x94, 0x9e, 0xa5, 0x18, 0x76, 0x9f, 0x6a, 0xa9,
        0x4f, 0xd7, 0xe5, 0xe0, 0x07, 0x1a, 0x36, 0x57, 0x8d, 0xc6, 0x2f, 0x60, 0x29, 0x08, 0x17,
        0x75, 0x28, 0x08, 0xda, 0x08, 0x40,
    ];

    #[test]
    fn load_request() {
        let req = OcspRequest::from_der(&REQ_DATA).expect("error loading OCSP request");
        let cert_id = &req.tbs_request.request_list[0].req_cert;
        assert_eq!(&cert_id.issuer_name_hash.as_bytes(), &ISSUER_NAME_HASH);
        assert_eq!(&cert_id.issuer_key_hash.as_bytes(), &ISSUER_KEY_HASH);
        assert_eq!(&cert_id.serial_number.as_bytes(), &SERIAL_NUMBER);
        let ext = &req.tbs_request.request_extensions.expect("no extensions")[0];
        assert_eq!(&ext.extn_id, &db::rfc6960::ID_PKIX_OCSP_NONCE);
        assert_eq!(ext.critical, false);
        assert_eq!(&ext.extn_value.as_bytes(), &NONCE);
    }

    #[test]
    fn load_response() {
        let res = OcspResponse::from_der(&RES_DATA).expect("error loading OCSP response");
        assert_eq!(res.response_status, OcspResponseStatus::Successful);
        let response_bytes = &res.response_bytes.expect("no response data");
        assert_eq!(
            &response_bytes.response_type,
            &db::rfc6960::ID_PKIX_OCSP_BASIC
        );
        let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
            .expect("error encoding response bytes");
        // ocsp.digicert.com does not do nonces...
        // 
        // Probably because they're using their dogshit HID VA product for presigned responses.
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
    fn verify_response() {
        let res = OcspResponse::from_der(&RES_DATA).expect("error loading OCSP response");
        assert_eq!(res.response_status, OcspResponseStatus::Successful);
        let response_bytes = &res.response_bytes.expect("no response data");
        assert_eq!(
            &response_bytes.response_type,
            &db::rfc6960::ID_PKIX_OCSP_BASIC
        );
        let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
            .expect("error encoding response bytes");
        let issuer = Certificate::from_pem(&SIGNING_CERT).expect("error loading certificate");
        basic_response.verify(&issuer).expect("verification failed");
    }

    #[test]
    fn request_builder() {
        let req = OcspRequestBuilder::new(Version::V1)
            .with_certid(CertId {
                hash_algorithm: AlgorithmIdentifier {
                    oid: db::rfc5912::ID_SHA_1,
                    parameters: None,
                },
                issuer_name_hash: OctetString::new(ISSUER_NAME_HASH)
                    .expect("failed to make issuer name hash"),
                issuer_key_hash: OctetString::new(ISSUER_KEY_HASH)
                    .expect("failed to make issuer key hash"),
                serial_number: SerialNumber::new(SERIAL_NUMBER)
                    .expect("failed to make serial number"),
            })
            .with_extension(Extension {
                extn_id: db::rfc6960::ID_PKIX_OCSP_NONCE,
                critical: false,
                extn_value: OctetString::new(NONCE).expect("failed to make nonce"),
            })
            .build()
            .to_der()
            .expect("failed to encode OCSP request");
        assert_eq!(&req, &REQ_DATA);
    }
}
