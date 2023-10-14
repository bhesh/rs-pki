//! Signature Verification

use crate::error::{Error, Result};
use alloc::format;
use const_oid::db::rfc5912::{
    DSA_WITH_SHA_1, ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
    SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::asn1::ObjectIdentifier;
use dsa;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, PublicKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use signature::{digest::Digest, DigestVerifier};

/// Validates the signature given an OID, public key, message, and signature
pub(crate) fn verify_by_oid(
    oid: &ObjectIdentifier,
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    match oid {
        &SHA_1_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(&msg), &sig)?)
        }
        &SHA_224_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha224>(), &Sha224::digest(&msg), &sig)?)
        }
        &SHA_256_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&msg), &sig)?)
        }
        &SHA_384_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(&msg), &sig)?)
        }
        &SHA_512_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(&msg), &sig)?)
        }
        &DSA_WITH_SHA_1 => {
            let pk = dsa::VerifyingKey::from_public_key_der(&public_key)?;
            let sig = dsa::Signature::try_from(sig).or(Err(Error::InvalidSignature))?;
            Ok(pk
                .verify_digest(Sha1::new_with_prefix(&msg), &sig)
                .or(Err(Error::Verification))?)
        }
        &ECDSA_WITH_SHA_224 => unimplemented!(),
        &ECDSA_WITH_SHA_256 => unimplemented!(),
        &ECDSA_WITH_SHA_384 => unimplemented!(),
        &ECDSA_WITH_SHA_512 => unimplemented!(),
        _ => Err(Error::InvalidOid),
    }
}

#[cfg(test)]
mod tests {

    use crate::{error::Error, verify::verify_by_oid};
    use der::{DecodePem, Encode};
    use x509_cert::Certificate;

    const PUBLIC_RSA_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    const PUBLIC_DSA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC3zCCAo+gAwIBAgIUScfg9Juor91XL05UwxHY1VUg3WMwCQYHKoZIzjgEAzAX
MRUwEwYDVQQDDAxkc2ExMDI0LXNoYTEwHhcNMjMxMDEzMTc1MDQ5WhcNMjYxMDEy
MTc1MDQ5WjAXMRUwEwYDVQQDDAxkc2ExMDI0LXNoYTEwggG+MIIBMwYHKoZIzjgE
ATCCASYCgYEApj9FbCbGtUJmmPItS1pb/d7YlOF/03+sYoW6LP1GijQNkCFd/oJd
eE/p6edmVq+SVo0wxp95ciT0YOFvQIrBtxzTEReysBNPHlcKRAq7LjL4kp5qQ7uC
NrJEQ2XGOXN49A/AyGgdYIpjDv+F40X6U2wWsuSwXfI7x3GtEc8/u1cCHQCEcpAa
kdpHwCygwJbswxIUV3/S16Bo5InpND97AoGAY6mXOI9wYst/ptZo0NtJCdTRz/0d
EQ67TRITn8pXco0F8q1ZMCu/SvZOb/EHlIphQJsbIe/rxQVQCWGKtEoVAXlJYo9c
k/OQ3utGKV+S/ZI3ZANXVoK60eFbgGdRoSPNY6V5lguGAJlhI7Bm04u03wYwZpoI
Vldfo/tQOWRXmn4DgYQAAoGAGeTWi4hw30/o0rhb3RKaBDFVnvVVOrX3YJibJ501
Wph5wTJwsVHR+/uvysp//C7cMVEMvpahwTCOWRrAUOv1kiAVn/LqkHeJBhYFwXiK
wy0R26eBzAUT1b46vTLfdpcSh4cPlRNKZEQ0uDFwldsEd9q/dOWya6qEFC4VuNlJ
5f+jUzBRMB0GA1UdDgQWBBRhaS16sliQ2KwwNDUZdX4uLnd3bzAfBgNVHSMEGDAW
gBRhaS16sliQ2KwwNDUZdX4uLnd3bzAPBgNVHRMBAf8EBTADAQH/MAkGByqGSM44
BAMDPwAwPAIcUA9Z1qttjWiUVMy+yD2qrswW0tSVgLJbUHldLgIcDHBC1pmrCucH
5DDxQ6OQ7sx+b4NDAkBHg4R4aQ==
-----END CERTIFICATE-----";

    const PUBLIC_ECDSA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS6gAwIBAgIUNiMsVY3N8JSgKz9AC2MJ1zIBZ2wwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQc2VjcDI1NmsxLXNoYTI1NjAeFw0yMzEwMTMxNzUwNDlaFw0y
NjEwMTIxNzUwNDlaMBsxGTAXBgNVBAMMEHNlY3AyNTZrMS1zaGEyNTYwVjAQBgcq
hkjOPQIBBgUrgQQACgNCAAS8cvVDW8lH87eRMtq3lGFZsovlGQaJYM+xAwDHEkd2
2Yq1y3Ain5nhScPGlcMB1gS60V6E7h7Qq7uMW46Xgv2wo1MwUTAdBgNVHQ4EFgQU
Q5hTAlql2smm4GAurVD/sPANumQwHwYDVR0jBBgwFoAUQ5hTAlql2smm4GAurVD/
sPANumQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAU2+3FJOFL
EeSunFPkrKQj8xjzIIxAWqbG0GzsWnCHmQIgRZsWYDaCnCT5el0Dd4tYWwQw6Jl2
z1ZJeNatu6tCqXw=
-----END CERTIFICATE-----";

    fn verify_good(pem: &str) {
        let cert = Certificate::from_pem(&pem).expect("error parsing certificate");
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("error encoding public key");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        verify_by_oid(oid, &public_key, &msg, &sig).expect("error verifying");
    }

    fn verify_bad(pem: &str) {
        let cert = Certificate::from_pem(&pem).expect("error parsing certificate");
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("error encoding public key");
        let msg = cert.to_der().expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        match verify_by_oid(oid, &public_key, &msg, &sig) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn verify_rsa_good_from_oid() {
        verify_good(&PUBLIC_RSA_PEM);
    }

    #[test]
    fn verify_rsa_bad_from_oid() {
        verify_bad(&PUBLIC_RSA_PEM);
    }

    #[test]
    fn verify_dsa_good_from_oid() {
        verify_good(&PUBLIC_DSA_PEM);
    }

    #[test]
    fn verify_dsa_bad_from_oid() {
        verify_bad(&PUBLIC_DSA_PEM);
    }
}
