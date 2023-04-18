//! Signature Verification

use crate::error::{Error, Result};
use const_oid::db::rfc5912::{
    DSA_WITH_SHA_1, ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
    SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::asn1::ObjectIdentifier;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, PublicKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use signature::digest::Digest;

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
        &DSA_WITH_SHA_1 => unimplemented!(),
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

    const PUBLIC_PEM: &str = "-----BEGIN CERTIFICATE-----
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
    fn verify_rsa_good_from_oid() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
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

    #[test]
    fn verify_rsa_bad_from_oid() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
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
}
