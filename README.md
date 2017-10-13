# openvpn-parser

[![LICENSE](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/rusticata/openvpn-parser.svg?branch=master)](https://travis-ci.org/rusticata/openvpn-parser)

## Overview

openvpn-parser is a parser for the ([OpenVPN](https://openvpn.net/)) protocol.

It can be used to decode the packet structures, access fields and verify some properties.
The content of the `Control` packets uses the TLS protocol, so [tls-parser](https://github.com/rusticata/tls-parser) can
be used to decode the messages.

*The parser does not decrypt messages.*

## License

This library is licensed under the GNU Lesser General Public License version 2.1, or (at your option) any later version.
