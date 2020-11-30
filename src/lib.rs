//! # openvpn-parser
//!
//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Build Status](https://travis-ci.org/rusticata/openvpn-parser.svg?branch=master)](https://travis-ci.org/rusticata/openvpn-parser)
//! [![Crates.io Version](https://img.shields.io/crates/v/openvpn-parser.svg)](https://crates.io/crates/openvpn-parser)
//!
//! ## Overview
//!
//! openvpn-parser is a parser for the ([OpenVPN](https://openvpn.net/)) protocol.
//!
//! It can be used to decode the packet structures, access fields and verify some properties.
//! The content of the `Control` packets uses the TLS protocol, so
//! [tls-parser](https://github.com/rusticata/tls-parser) can be used to decode the messages.
//!
//! *The parser does not decrypt messages.*
//!
//! This crate mostly serves as a demo/example crate for network protocol parsers written using nom, and nom-derive.
//!
//! ## Notes
//!
//! Writen in great pain, due to lack of specifications, and a number of fields
//! defined in a very useless way, like "usually 16 or 20 bytes".
//!
//! Closest thing to specifications:
//!
//! - <https://openvpn.net/index.php/open-source/documentation/security-overview.html>
//! - <http://ipseclab.eit.lth.se/tiki-index.php?page=6.+OpenVPN>
//! - OpenVPN source code
//! - OpenVPN wireshark parser

#![deny(// missing_docs,
        missing_debug_implementations,
        unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

mod openvpn;
pub use openvpn::*;

pub use nom;
