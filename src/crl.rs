//! X.509 CRLs

use crate::{
    cert::Certificate,
    error::{Error, Result},
    verify::verify_by_oid,
};
use der::{asn1::BitString, Encode, Sequence, ValueOrd};
use x509_cert::{crl::TbsCertList, spki::AlgorithmIdentifierOwned};

/// CertificateList
///
/// Similar to x509_cert::crl::CertificateList but has additional cryptographic functionality
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CertificateList {
    /// TBS Certificate List
    pub tbs_cert_list: TbsCertList,

    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl CertificateList {
    /// Verifies the CRL given the CA
    pub fn verify(&self, issuer: &Certificate) -> Result<()> {
        let public_key = issuer.tbs_certificate.subject_public_key_info.to_der()?;
        let msg = self.tbs_cert_list.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        let oid = &self.signature_algorithm.oid;
        Ok(verify_by_oid(oid, &public_key, &msg, &sig)?)
    }
}

#[cfg(test)]
mod tests {

    use crate::{cert::Certificate, crl::CertificateList, error::Error};
    use der::{Decode, DecodePem};

    const RSA_SHA256: &str = "-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUZ+evGd94OegJAuRime281jEJh7UwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOcnNhMjA0OC1zaGEyNTYwHhcNMjMwNDE0MTUwNzQzWhcN
MjYwNDEzMTUwNzQzWjAZMRcwFQYDVQQDDA5yc2EyMDQ4LXNoYTI1NjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAIh6/32L7lnScThXsxnub+ATmL4HRxIl
ad//hlwerxLzXpYKvik8tIMb3gYiy83sU1PNXdCVegoMxi4+Di0deV9CX1VAUFeG
SAZRp5Ib5ZtsfgoyuqEHc4U/WzX6V5XdxJfwP6spI/rUsjBEY2g+ltRWWXQGSr/v
iOiNKwhx1rrXIsqCaFb39zIGYlyi/bpQwwmfkXgIEhkezbDdPWyqRT9XstWElOaV
clxMFoPLmWfPeQJF250c6GxAIZKN5B+qVvGC/THy928+RGZpsriOf0Izkdd2iiF/
kkmcmRAe9TFdEOPgLOHdjhyCC2rVjX65vQkRUeWn+mke1MrtZKePsY8CAwEAAaNT
MFEwHQYDVR0OBBYEFBkcFiSUOy5O4PnQ3lB87P1Uo16jMB8GA1UdIwQYMBaAFBkc
FiSUOy5O4PnQ3lB87P1Uo16jMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBABwMVy/mVaG8Mc9aX15hrnQD3XMD7lvASqeiTtaS16x8GOkemoAjjDih
mQ4hLN7ZnOj/eqaURxizBJd4f8VGxATlOWlDJO7AQbDQxx6jtJVZqhcw/elp/mga
7MZClbBZdKaFWCHNX6Q8hkKYc5AunVz/psyH5B5AQnPDQi3RcrqIccok3OCQNdGJ
SGIqHGE1ztNTTjmgzIyMpV0/fBEvCJfWVVyGP4vn7QN5ofUs/p+giRf1KGcmbRVI
QmOnlIJzMJB81/BUqxmJPApOjFumHc4Vx362V/uCbnwHKlO1m8kgilaOsXzFz+/h
VMhbXUpvpTLfrE9uM/R0W1X0j8YOl78=
-----END CERTIFICATE-----";

    const CA: &str = "-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf
MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg
QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE
BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT
B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37
Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa
BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47
RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn
UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+
VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9
yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ
XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC
AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m
tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo
3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu
FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s
6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG
QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=
-----END CERTIFICATE-----";

    const CRL: &[u8] = &[
        0x30, 0x82, 0x02, 0x00, 0x30, 0x81, 0xe9, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x40, 0x31, 0x0b, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1f, 0x30, 0x1d, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x13, 0x16, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74,
        0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20, 0x32, 0x30, 0x31, 0x31, 0x31, 0x10,
        0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x47, 0x6f, 0x6f, 0x64, 0x20, 0x43,
        0x41, 0x17, 0x0d, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30,
        0x5a, 0x17, 0x0d, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30,
        0x5a, 0x30, 0x44, 0x30, 0x20, 0x02, 0x01, 0x0e, 0x17, 0x0d, 0x31, 0x30, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
        0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 0x01, 0x30, 0x20, 0x02, 0x01, 0x0f, 0x17, 0x0d, 0x31,
        0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x31, 0x5a, 0x30, 0x0c, 0x30,
        0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 0x01, 0xa0, 0x2f, 0x30, 0x2d,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x58, 0x01,
        0x84, 0x24, 0x1b, 0xbc, 0x2b, 0x52, 0x94, 0x4a, 0x3d, 0xa5, 0x10, 0x72, 0x14, 0x51, 0xf5,
        0xaf, 0x3a, 0xc9, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x14, 0x04, 0x03, 0x02, 0x01, 0x01,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x01, 0x00, 0x3d, 0xbc, 0xf3, 0x0b, 0x8a, 0x29, 0xc3, 0xf0, 0x6e, 0xc5,
        0x6a, 0x84, 0xec, 0xbb, 0xc4, 0xf6, 0x8d, 0x4a, 0xd3, 0x8b, 0x53, 0x8b, 0x3c, 0x7c, 0x4a,
        0x9e, 0xb9, 0x41, 0xac, 0x03, 0xff, 0x78, 0x76, 0xbe, 0x55, 0x05, 0x75, 0x1c, 0x97, 0xd8,
        0xe4, 0x68, 0xea, 0xd5, 0xda, 0x4d, 0x83, 0x36, 0x6a, 0x0c, 0x88, 0x10, 0x33, 0x94, 0x07,
        0x3e, 0x6d, 0x1a, 0x4a, 0x03, 0x0d, 0xed, 0x49, 0x6d, 0xc7, 0xe5, 0xf3, 0x6f, 0x14, 0x6c,
        0xc0, 0xb9, 0xf0, 0x81, 0x0a, 0xd9, 0xed, 0xfe, 0xfa, 0x4e, 0x59, 0x32, 0xd4, 0x8f, 0xa3,
        0xcf, 0xbf, 0xe9, 0xdc, 0x01, 0x32, 0x9e, 0xb3, 0x51, 0xef, 0x6b, 0xfa, 0xe1, 0x26, 0x6d,
        0xe3, 0xa5, 0x21, 0xa5, 0x2b, 0x96, 0x04, 0x7a, 0x05, 0xd6, 0xe1, 0x15, 0xb6, 0x08, 0xab,
        0x4d, 0x93, 0x5f, 0x38, 0x46, 0x86, 0x50, 0x94, 0xcd, 0x39, 0xa4, 0xc0, 0xe5, 0x4e, 0x79,
        0xfe, 0x2c, 0x3d, 0x04, 0xa8, 0xc7, 0x37, 0x47, 0xbf, 0x55, 0xde, 0xce, 0x1a, 0x7a, 0xe4,
        0xe6, 0x1e, 0x85, 0xb2, 0x05, 0x8e, 0x89, 0xab, 0x06, 0x9f, 0xaf, 0xed, 0xca, 0x6f, 0x6d,
        0x78, 0x3b, 0x7f, 0x2f, 0x68, 0x65, 0x39, 0xdb, 0x19, 0xb2, 0xf5, 0xf5, 0x28, 0xf7, 0x34,
        0x13, 0x15, 0x07, 0x56, 0x32, 0x48, 0x50, 0x16, 0x13, 0xa2, 0x8a, 0xb2, 0xcb, 0xf0, 0xae,
        0x4f, 0x31, 0x47, 0x95, 0xae, 0x91, 0x61, 0x56, 0x2f, 0x26, 0xe4, 0x45, 0xe6, 0xa6, 0x02,
        0xc5, 0xad, 0x06, 0x4d, 0x92, 0xb7, 0x22, 0x60, 0xad, 0x27, 0x75, 0xdf, 0xb0, 0x67, 0x5f,
        0x2c, 0x42, 0x43, 0x67, 0xb4, 0xf5, 0xef, 0x10, 0x50, 0x1e, 0xe7, 0x0c, 0xbc, 0x85, 0x4b,
        0x9b, 0xab, 0xd8, 0xe3, 0x85, 0x94, 0xcb, 0xb3, 0xea, 0x42, 0x16, 0x49, 0xb2, 0x48, 0x49,
        0x30, 0x4b, 0xe3, 0xd3, 0x56, 0x44,
    ];

    #[test]
    fn verify_rsa_good() {
        let cert = Certificate::from_pem(&CA).expect("error parsing CA");
        let crl = CertificateList::from_der(&CRL).expect("error parsing CRL");
        crl.verify(&cert).expect("error verifying");
    }

    #[test]
    fn verify_rsa_bad() {
        let cert = Certificate::from_pem(&RSA_SHA256).expect("error parsing certificate");
        let crl = CertificateList::from_der(&CRL).expect("error parsing CRL");
        match crl.verify(&cert) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }
}
