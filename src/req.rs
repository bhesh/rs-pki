//! X.509 Certificate Requests

use crate::{
    error::{Error, Result},
    verify::verify,
};
use der::{asn1::BitString, pem::PemLabel, Encode, Sequence};
use x509_cert::{request::CertReqInfo, spki::AlgorithmIdentifierOwned};

/// CertReq
///
/// Similar to x509_cert::request::CertReq but has additional cryptographic functionality
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct CertReq {
    /// Certification request information.
    pub info: CertReqInfo,

    /// Signature algorithm identifier.
    pub algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl PemLabel for CertReq {
    const PEM_LABEL: &'static str = "CERTIFICATE REQUEST";
}

impl CertReq {
    /// Verifies the CSR signature
    pub fn verify(&self) -> Result<()> {
        let public_key = self.info.public_key.to_der()?;
        let msg = self.info.to_der()?;
        let sig = match self.signature.as_bytes() {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        let oid = &self.algorithm.oid;
        Ok(verify(oid, &public_key, &msg, &sig)?)
    }
}

#[cfg(test)]
mod tests {

    use crate::{error::Error, req::CertReq};
    use alloc::vec::Vec;
    use der::{asn1::BitString, DecodePem};

    const RSA_SHA256_REQ: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIICXjCCAUYCAQAwGTEXMBUGA1UEAwwOcnNhMjA0OC1zaGEyNTYwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCIev99i+5Z0nE4V7MZ7m/gE5i+B0cSJWnf
/4ZcHq8S816WCr4pPLSDG94GIsvN7FNTzV3QlXoKDMYuPg4tHXlfQl9VQFBXhkgG
UaeSG+WbbH4KMrqhB3OFP1s1+leV3cSX8D+rKSP61LIwRGNoPpbUVll0Bkq/74jo
jSsIcda61yLKgmhW9/cyBmJcov26UMMJn5F4CBIZHs2w3T1sqkU/V7LVhJTmlXJc
TBaDy5lnz3kCRdudHOhsQCGSjeQfqlbxgv0x8vdvPkRmabK4jn9CM5HXdoohf5JJ
nJkQHvUxXRDj4Czh3Y4cggtq1Y1+ub0JEVHlp/ppHtTK7WSnj7GPAgMBAAGgADAN
BgkqhkiG9w0BAQsFAAOCAQEAHr8VQVg8esnXyzoBHfxc1UmjN4oUrU1jyusc+wB+
AracV4nAZz+LzvJH4daIGPiCV8cOmVk0k78QCO3jMI2bwK702upa1CHZJcKCEyYY
g1gMCUAPi57A2FfkKy2C1CsAQr6zn5V5bDrZGjRGQVRE+YVhF+JZU8rYzK5QeOlC
LSVm6J7eJgVLOgBi7u+NAt9wK/IYeRbGP/2DghH74Av23gnsmbW4QpxJ5X1U3TLj
3Ys5APgbSYr6vFQSN4WEVIgltdofFnq5sbq3G+aWlfLHyYt28OLgaWBMsoPtaGjo
yaCjWF5x/E5PDMugRgp7eJM7P1EpVhhJAE1DCv5utVL26Q==
-----END CERTIFICATE REQUEST-----";

    #[test]
    fn verify_rsa_good() {
        let req = CertReq::from_pem(&RSA_SHA256_REQ).expect("error parsing certificate request");
        req.verify().expect("error verifying");
    }

    #[test]
    fn verify_rsa_bad() {
        let mut req =
            CertReq::from_pem(&RSA_SHA256_REQ).expect("error parsing certificate request");

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
}
