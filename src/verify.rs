//! Signature Verification

use crate::error::{Error, Result};
use der::{
    asn1::{BitString, ObjectIdentifier},
    Any, Encode,
};
use sha1::Sha1;
use signature::{digest::Digest, hazmat::PrehashVerifier};
use spki::{DecodePublicKey, SubjectPublicKeyInfo};

#[cfg(feature = "dsa")]
use const_oid::db::rfc5912::DSA_WITH_SHA_1;

#[cfg(feature = "dsa")]
use dsa;

#[cfg(feature = "ecdsa")]
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
    ID_EC_PUBLIC_KEY, SECP_224_R_1, SECP_256_R_1, SECP_384_R_1,
};

#[cfg(feature = "ecdsa")]
const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[cfg(feature = "ecdsa")]
const SECP_192_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1");

#[cfg(feature = "ecdsa")]
use ecdsa;

#[cfg(feature = "ecdsa")]
use k256;

#[cfg(feature = "ecdsa")]
use p192;

#[cfg(feature = "ecdsa")]
use p224;

#[cfg(feature = "ecdsa")]
use p256;

#[cfg(feature = "ecdsa")]
use p384;

#[cfg(feature = "rsa")]
use const_oid::db::rfc5912::{
    SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};

#[cfg(feature = "rsa")]
use rsa::{Pkcs1v15Sign, PublicKey, RsaPublicKey};

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(feature = "ecdsa")]
fn verify_ecdsa<D: Digest>(
    public_key: &SubjectPublicKeyInfo<Any, BitString>,
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    if &public_key.algorithm.oid != &ID_EC_PUBLIC_KEY {
        return Err(Error::InvalidKey);
    }
    let oid = ObjectIdentifier::from_bytes(
        public_key
            .algorithm
            .parameters
            .as_ref()
            .ok_or(Error::InvalidKey)?
            .value(),
    )
    .or(Err(Error::InvalidAsn1))?;
    match &oid {
        &SECP_256_K_1 => {
            let pk = ecdsa::VerifyingKey::<k256::Secp256k1>::from_sec1_bytes(
                public_key.subject_public_key.raw_bytes(),
            )
            .or(Err(Error::InvalidKey))?;
            let sig = ecdsa::Signature::<k256::Secp256k1>::from_der(&sig)
                .or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&D::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        &SECP_192_R_1 => {
            let pk = ecdsa::VerifyingKey::<p192::NistP192>::from_sec1_bytes(
                public_key.subject_public_key.raw_bytes(),
            )
            .or(Err(Error::InvalidKey))?;
            let sig = ecdsa::Signature::<p192::NistP192>::from_der(&sig)
                .or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&D::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        &SECP_224_R_1 => {
            let pk = ecdsa::VerifyingKey::<p224::NistP224>::from_sec1_bytes(
                public_key.subject_public_key.raw_bytes(),
            )
            .or(Err(Error::InvalidKey))?;
            let sig = ecdsa::Signature::<p224::NistP224>::from_der(&sig)
                .or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&D::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        &SECP_256_R_1 => {
            let pk = ecdsa::VerifyingKey::<p256::NistP256>::from_sec1_bytes(
                public_key.subject_public_key.raw_bytes(),
            )
            .or(Err(Error::InvalidKey))?;
            let sig = ecdsa::Signature::<p256::NistP256>::from_der(&sig)
                .or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&D::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        &SECP_384_R_1 => {
            let pk = ecdsa::VerifyingKey::<p384::NistP384>::from_sec1_bytes(
                public_key.subject_public_key.raw_bytes(),
            )
            .or(Err(Error::InvalidKey))?;
            let sig = ecdsa::Signature::<p384::NistP384>::from_der(&sig)
                .or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&D::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        _ => Err(Error::OidUnknown(oid.clone())),
    }
}

/// Validates the signature given an OID, public key, message, and signature
pub(crate) fn verify_by_oid(
    oid: &ObjectIdentifier,
    public_key: &SubjectPublicKeyInfo<Any, BitString>,
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    match oid {
        #[cfg(feature = "rsa")]
        &SHA_1_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key.to_der()?)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(&msg), &sig)?)
        }
        #[cfg(all(feature = "rsa", feature = "sha2"))]
        &SHA_224_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key.to_der()?)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha224>(), &Sha224::digest(&msg), &sig)?)
        }
        #[cfg(all(feature = "rsa", feature = "sha2"))]
        &SHA_256_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key.to_der()?)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&msg), &sig)?)
        }
        #[cfg(all(feature = "rsa", feature = "sha2"))]
        &SHA_384_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key.to_der()?)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(&msg), &sig)?)
        }
        #[cfg(all(feature = "rsa", feature = "sha2"))]
        &SHA_512_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key.to_der()?)?;
            Ok(pk.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(&msg), &sig)?)
        }
        #[cfg(feature = "dsa")]
        &DSA_WITH_SHA_1 => {
            let pk = dsa::VerifyingKey::from_public_key_der(&public_key.to_der()?)?;
            let sig = dsa::Signature::try_from(sig).or(Err(Error::InvalidSignature))?;
            pk.verify_prehash(&Sha1::digest(&msg), &sig)
                .or(Err(Error::Verification))
        }
        #[cfg(feature = "ecdsa")]
        &ECDSA_WITH_SHA_224 => verify_ecdsa::<Sha224>(public_key, msg, sig),
        #[cfg(feature = "ecdsa")]
        &ECDSA_WITH_SHA_256 => verify_ecdsa::<Sha256>(public_key, msg, sig),
        #[cfg(feature = "ecdsa")]
        &ECDSA_WITH_SHA_384 => verify_ecdsa::<Sha384>(public_key, msg, sig),
        #[cfg(feature = "ecdsa")]
        &ECDSA_WITH_SHA_512 => verify_ecdsa::<Sha512>(public_key, msg, sig),
        _ => Err(Error::OidUnknown(oid.clone())),
    }
}

#[cfg(test)]
mod tests {

    use crate::{error::Error, verify::verify_by_oid};
    use der::{DecodePem, Encode};
    use x509_cert::Certificate;

    const PUBLIC_RSA2048_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    const PUBLIC_P192_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBazCCASGgAwIBAgIUYBWAmn56bTCzDjmEmS1YTiycaCYwCgYIKoZIzj0EAwEw
GzEZMBcGA1UEAwwQc2VjcDE5MnIxLXNoYTIyNDAeFw0yMzEwMTYxNjMwMDJaFw0y
NjEwMTUxNjMwMDJaMBsxGTAXBgNVBAMMEHNlY3AxOTJyMS1zaGEyMjQwSTATBgcq
hkjOPQIBBggqhkjOPQMBAQMyAATSf20qxObw85wz7aqRXCwr+V9lzngYzOkljfoQ
M63519mfSSAwHK6GjaAkEMFh9T2jUzBRMB0GA1UdDgQWBBSz3F5dRzXwuzPER2Ar
6XV+GUC5DTAfBgNVHSMEGDAWgBSz3F5dRzXwuzPER2Ar6XV+GUC5DTAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMBAzgAMDUCGCDVZDpoSdF4ALpWix0RTQRIypLR
cuL6xwIZANAX9XIK9UkLOjUw4MpYWb67tuOMNRTmaA==
-----END CERTIFICATE-----";

    const PUBLIC_P256_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIUYCOlE5IXQA3Pm81y/ztQp9RwQ6YwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRcHJpbWUyNTZ2MS1zaGEyNTYwHhcNMjMxMDEzMTc1MDQ5WhcN
MjYxMDEyMTc1MDQ5WjAcMRowGAYDVQQDDBFwcmltZTI1NnYxLXNoYTI1NjBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLglB6XI74Zgw5oGbj9ZruTyi1QDX0IoLOfs
VGU9HEK+3HhedD/OotoW+gK/TGTsFSd8gs6i7DJ6prLWT6flK++jUzBRMB0GA1Ud
DgQWBBTMS7AELri6/SOCLM6j+7F5+rRCfjAfBgNVHSMEGDAWgBTMS7AELri6/SOC
LM6j+7F5+rRCfjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCZ
m1STOY98Ac9eiNkciws5iT07qLV9xm2lT2os06tFygIgNoIawfR+MAMVcxpWVDpL
1mMyecyuP5PWqLOJX68V0X8=
-----END CERTIFICATE-----";

    const PUBLIC_SECP256_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    const PUBLIC_SECP384_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIByTCCAU6gAwIBAgIUC0n/qC9e8eBDn26HMHSCpDCUMEswCgYIKoZIzj0EAwMw
GzEZMBcGA1UEAwwQc2VjcDM4NHIxLXNoYTM4NDAeFw0yMzEwMTMxNzUwNDlaFw0y
NjEwMTIxNzUwNDlaMBsxGTAXBgNVBAMMEHNlY3AzODRyMS1zaGEzODQwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQzu64YQGBuu09dY+62Skfa3FTT7mmirIRJOJxM6zHi
dbbNRNLgymDZB1Iabs6qmj7GoH5MTxVreXWdtCE8Mv+ilXbPZ+6OZievEpL+MM3b
PPbzOyBClnI8OYGFaRzAo+ajUzBRMB0GA1UdDgQWBBTiPayVyjuWoO+kQSgn1n0H
mZe62DAfBgNVHSMEGDAWgBTiPayVyjuWoO+kQSgn1n0HmZe62DAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMDA2kAMGYCMQCGyfbKoxFPZdCeMX19d2hxJ1aBkabe
uqgkVU8b2qH1K2dD1Yo0oZeEMokCi4wT3GICMQC9LyxUDCTIdWf7aiItb4IAhD62
feJ1lBQG6TVQjHNympur2T0aXwEMPD8MpicY2H8=
-----END CERTIFICATE-----";

    fn verify_good(pem: &str) {
        let cert = Certificate::from_pem(&pem).expect("error parsing certificate");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        verify_by_oid(
            oid,
            &cert.tbs_certificate.subject_public_key_info,
            &msg,
            &sig,
        )
        .expect("error verifying");
    }

    fn verify_bad(pem: &str) {
        let cert = Certificate::from_pem(&pem).expect("error parsing certificate");
        let msg = cert.to_der().expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        match verify_by_oid(
            oid,
            &cert.tbs_certificate.subject_public_key_info,
            &msg,
            &sig,
        ) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn verify_rsa2048_good_from_oid() {
        verify_good(&PUBLIC_RSA2048_PEM);
    }

    #[cfg(all(feature = "rsa", feature = "sha2"))]
    #[test]
    fn verify_rsa2048_bad_from_oid() {
        verify_bad(&PUBLIC_RSA2048_PEM);
    }

    #[cfg(feature = "dsa")]
    #[test]
    fn verify_dsa_good_from_oid() {
        verify_good(&PUBLIC_DSA_PEM);
    }

    #[cfg(feature = "dsa")]
    #[test]
    fn verify_dsa_bad_from_oid() {
        verify_bad(&PUBLIC_DSA_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_p192_good_from_oid() {
        verify_good(&PUBLIC_P192_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_p192_bad_from_oid() {
        verify_bad(&PUBLIC_P192_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_p256_good_from_oid() {
        verify_good(&PUBLIC_P256_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_p256_bad_from_oid() {
        verify_bad(&PUBLIC_P256_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_secp256_good_from_oid() {
        verify_good(&PUBLIC_SECP256_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_secp256_bad_from_oid() {
        verify_bad(&PUBLIC_SECP256_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_secp384_good_from_oid() {
        verify_good(&PUBLIC_SECP384_PEM);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn verify_secp384_bad_from_oid() {
        verify_bad(&PUBLIC_SECP384_PEM);
    }
}
