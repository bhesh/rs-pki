//! X.509 Certificates

use crate::{
    error::{Error, Result},
    verify::verify_by_oid,
};
use der::{asn1::BitString, pem::PemLabel, Encode, Sequence, ValueOrd};
use x509_cert::{spki::AlgorithmIdentifierOwned, TbsCertificate};

/// Certificate
///
/// Similar to x509_cert::Certificate but has additional cryptographic functionality
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Certificate {
    /// TBS Certificate
    pub tbs_certificate: TbsCertificate,

    /// Signature algorithm identifier.
    pub signature_algorithm: AlgorithmIdentifierOwned,

    /// Signature.
    pub signature: BitString,
}

impl PemLabel for Certificate {
    const PEM_LABEL: &'static str = "CERTIFICATE";
}

impl Certificate {
    /// Verifies the certificate given the issuer
    pub fn verify(&self, issuer: &Certificate) -> Result<()> {
        let public_key = issuer.tbs_certificate.subject_public_key_info.to_der()?;
        let msg = self.tbs_certificate.to_der()?;
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

    use crate::{cert::Certificate, error::Error};
    use der::DecodePem;

    const RSA_SHA1: &str = "-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUS5G6A2pfVuXRi9zRiLIJl9PEOJAwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMB4XDTIzMDQxNDE1MDc0M1oXDTI2
MDQxMzE1MDc0M1owFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuDGPjLy87Wudfow3gl95q6VuimpPcc0hJRy9
7OrMr8MB7eHsrZA3Y5iLvgKSKJ6+G8x2laAyZZlRJvKggJZWYVodPJNy9EWTrdWN
YuerwcI0tkp3y3g0m6++QwICk3b+Q3HML3YAI5nl/rcZ+yVGb8s8Se8qeh8+dRsH
48ML41E9q64pP8MUSzk+5yg3RRVPP0RdCvhW7vff11mPrZdmxfoSbW5NMQAkq3OO
nW9KSw461FaJPolUQPYO4EAwqJkfFMDqE2EJ9dcf0EPfB1RWV1dGsOa8VvCxj6CB
ER8XJ/kiingEuKVQn9A2wHilTmQtpAS6MJZvNHJCYeEyA+TCZwIDAQABo1MwUTAd
BgNVHQ4EFgQUAxIT+Y3nargbP5uXqALw9d2CwegwHwYDVR0jBBgwFoAUAxIT+Y3n
argbP5uXqALw9d2CwegwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC
AQEAlFwpgA48FqgAvH94XANVjgbUW9ZFWKk9CElJBpLT/OwG/hotk5ILIhkLzzKV
+fjLlRZOYSBU/TpspWcPJ3PJLA5Qgg3Bw1aXXLzNSFqhg/q9SJjam5LDK/dc4gt+
HRGNn5NJdhHP4otHInAT6aE6vxSx/09szjPgm4KKg0vf1qefEHOKbttdE6nY9oiY
Eo/okLk/cPKBzSVLzxNG5bpR9pPCoC+FAIn8ABIh6Ue8BzvamR8vE+phge/gurQM
s2r9E6jZqQUTJ3IFY/EXX6h8SDTLFI9aHNf3ROnWTIne2BbJzlBt8+9XGlgkgvEY
MGZEHd38Z/K1nOxOEjUS5xGdkQ==
-----END CERTIFICATE-----";

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

    #[test]
    fn verify_rsa_sha1_good() {
        let cert = Certificate::from_pem(&RSA_SHA1).expect("error parsing certificate");
        cert.verify(&cert).expect("error verifying");
    }

    #[test]
    fn verify_rsa_sha1_bad() {
        let cert1 = Certificate::from_pem(&RSA_SHA1).expect("error parsing certificate");
        let cert2 = Certificate::from_pem(&RSA_SHA256).expect("error parsing certificate");
        match cert1.verify(&cert2) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn verify_rsa_sha256_good() {
        let cert = Certificate::from_pem(&RSA_SHA256).expect("error parsing certificate");
        cert.verify(&cert).expect("error verifying");
    }

    #[test]
    fn verify_rsa_sha256_bad() {
        let cert1 = Certificate::from_pem(&RSA_SHA1).expect("error parsing certificate");
        let cert2 = Certificate::from_pem(&RSA_SHA256).expect("error parsing certificate");
        match cert2.verify(&cert1) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }
}
