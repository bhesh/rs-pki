#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

pub mod cert;
pub mod crl;
pub mod error;
pub mod ocsp;
pub mod req;
mod verify;

pub use const_oid;
pub use der;
pub use rand_core;
pub use signature;
pub use spki;
pub use x509_cert::{anchor, attr, ext, name, serial_number, time};

#[cfg(feature = "rsa")]
pub use rsa;

#[cfg(feature = "ecc")]
pub mod ecc {
    pub use ecdsa;
    pub use k256;
    pub use p192;
    pub use p224;
    pub use p256;
    pub use p384;
}

#[cfg(feature = "sha1")]
pub use sha1;

#[cfg(feature = "sha2")]
pub use sha2;
