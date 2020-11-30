<!-- cargo-sync-readme start -->

# openvpn-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/openvpn-parser.svg?branch=master)](https://travis-ci.org/rusticata/openvpn-parser)
[![Crates.io Version](https://img.shields.io/crates/v/openvpn-parser.svg)](https://crates.io/crates/openvpn-parser)

## Overview

openvpn-parser is a parser for the ([OpenVPN](https://openvpn.net/)) protocol.

It can be used to decode the packet structures, access fields and verify some properties.
The content of the `Control` packets uses the TLS protocol, so
[tls-parser](https://github.com/rusticata/tls-parser) can be used to decode the messages.

*The parser does not decrypt messages.*

This crate mostly serves as a demo/example crate for network protocol parsers written using nom, and nom-derive.

## Notes

Writen in great pain, due to lack of specifications, and a number of fields
defined in a very useless way, like "usually 16 or 20 bytes".

Closest thing to specifications:

- <https://openvpn.net/index.php/open-source/documentation/security-overview.html>
- <http://ipseclab.eit.lth.se/tiki-index.php?page=6.+OpenVPN>
- OpenVPN source code
- OpenVPN wireshark parser
<!-- cargo-sync-readme end -->

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
