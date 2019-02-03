#![deny(// missing_docs,
        missing_debug_implementations,
        unsafe_code,
        unstable_features,
        /*unused_import_braces, */unused_qualifications)]

extern crate nom;
#[macro_use] extern crate rusticata_macros;

pub mod openvpn;
pub use openvpn::*;
