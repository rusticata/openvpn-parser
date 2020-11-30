//! OpenVPN parser
//!
//! Writen in great pain, due to lack of specifications, and a number of fields
//! defined in a very useless way, like "usually 16 or 20 bytes".
//!
//! Closest thing to specifications:
//!
//! - https://openvpn.net/index.php/open-source/documentation/security-overview.html
//! - http://ipseclab.eit.lth.se/tiki-index.php?page=6.+OpenVPN
//! - OpenVPN source code
//! - OpenVPN wireshark parser

use nom::bytes::streaming::take;
use nom::combinator::{cond, map, map_parser, rest};
use nom::error::{make_error, ErrorKind};
use nom::multi::count;
use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom::*;

/// OpenVPN packet
#[derive(Debug, PartialEq)]
pub struct OpenVPNPacket<'a> {
    pub hdr: OpenVPNHdr,
    pub msg: Payload<'a>,
}

/// OpenVPN packet header
///
/// TCP and UDP differ only by the presence of the `plen` field.
#[derive(Debug, PartialEq)]
pub struct OpenVPNHdr {
    /// Packet length, TCP only
    pub plen: Option<u16>,
    pub opcode: Opcode,
    pub key: u8,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Opcode(pub u8);

newtype_enum! {
impl debug Opcode {
    P_CONTROL_HARD_RESET_CLIENT_V1 = 0x1,
    P_CONTROL_HARD_RESET_SERVER_V1 = 0x2,
    P_CONTROL_SOFT_RESET_V1 = 0x3,
    P_CONTROL_V1 = 0x4,
    P_ACK_V1 = 0x5,
    P_DATA_V1 = 0x6,
    P_CONTROL_HARD_RESET_CLIENT_V2 = 0x7,
    P_CONTROL_HARD_RESET_SERVER_V2 = 0x8,
    P_DATA_V2 = 0x9,
}
}

/// Payload for OpenVPN data
#[derive(Debug, PartialEq)]
pub enum Payload<'a> {
    Control(PControl<'a>),
    Ack(PAck<'a>),
    Data(PData<'a>),
}

/// Payload for P_CONTROL messages
#[derive(Debug, PartialEq)]
pub struct PControl<'a> {
    pub session_id: u64,
    /// 16 or 20 bytes
    pub hmac: &'a [u8],
    /// replay protection, 4 or 8 bytes (see `net_time`)
    pub packet_id: u32,
    /// Optional part of replay protection
    pub net_time: u32,
    pub msg_ar_len: u8,
    pub msg_ar: Option<Vec<u32>>,
    pub msg_packet_id: u32,
    pub remote_session_id: Option<u64>,
    pub payload: &'a [u8],
}

/// Payload for P_ACK messages
#[derive(Debug, PartialEq)]
pub struct PAck<'a> {
    pub session_id: u64,
    /// 16 or 20 bytes
    pub hmac: &'a [u8],
    /// replay protection, 4 or 8 bytes (see `net_time`)
    pub packet_id: u32,
    /// Optional part of replay protection
    pub net_time: u32,
    pub msg_ar_len: u8,
    pub msg_ar: Option<Vec<u32>>,
    pub remote_session_id: Option<u64>,
}

/// Payload for P_DATA messages
///
/// Since the payload can be encrypted, do not parse data
#[derive(Debug, PartialEq)]
pub struct PData<'a> {
    pub contents: &'a [u8],
}

/// Parse an OpenVPN packet in TCP
pub fn parse_openvpn_tcp(i: &[u8]) -> IResult<&[u8], OpenVPNPacket> {
    let (i, hdr) = parse_openvpn_header_tcp(i)?;
    // length includes header (minus plen field)
    // substract 1 (opcode + key)
    let plen = match hdr.plen {
        Some(plen) if plen >= 2 => plen,
        _ => return Err(Err::Error(make_error(i, ErrorKind::LengthValue))),
    };
    let (i, msg) = map_parser(take(plen - 1), parse_openvpn_msg_payload(hdr.opcode))(i)?;
    Ok((i, OpenVPNPacket { hdr, msg }))
}

/// Parse an OpenVPN packet in UDP
///
/// Note that this will consume the entire buffer
pub fn parse_openvpn_udp(i: &[u8]) -> IResult<&[u8], OpenVPNPacket> {
    let (i, hdr) = parse_openvpn_header_udp(i)?;
    let (i, msg) = parse_openvpn_msg_payload(hdr.opcode)(i)?;
    Ok((i, OpenVPNPacket { hdr, msg }))
}

pub fn parse_openvpn_header_tcp(i: &[u8]) -> IResult<&[u8], OpenVPNHdr> {
    let (i, plen) = be_u16(i)?;
    let (i, opcode_and_key) = be_u8(i)?;
    // take 5 bits for opcode and 3 for key
    let opcode = Opcode(opcode_and_key >> 3);
    let key = opcode_and_key & 0b111;
    let hdr = OpenVPNHdr {
        plen: Some(plen),
        opcode,
        key,
    };
    Ok((i, hdr))
}

pub fn parse_openvpn_header_udp(i: &[u8]) -> IResult<&[u8], OpenVPNHdr> {
    let (i, opcode_and_key) = be_u8(i)?;
    // take 5 bits for opcode and 3 for key
    let opcode = Opcode(opcode_and_key >> 3);
    let key = opcode_and_key & 0b111;
    let hdr = OpenVPNHdr {
        plen: None,
        opcode,
        key,
    };
    Ok((i, hdr))
}

pub fn parse_openvpn_msg_payload(msg_type: Opcode) -> impl FnMut(&[u8]) -> IResult<&[u8], Payload> {
    move |i| match msg_type {
        Opcode::P_CONTROL_HARD_RESET_CLIENT_V1
        | Opcode::P_CONTROL_HARD_RESET_SERVER_V1
        | Opcode::P_CONTROL_SOFT_RESET_V1
        | Opcode::P_CONTROL_V1
        | Opcode::P_CONTROL_HARD_RESET_CLIENT_V2
        | Opcode::P_CONTROL_HARD_RESET_SERVER_V2 => {
            map(parse_openvpn_msg_pcontrol, Payload::Control)(i)
        }
        Opcode::P_ACK_V1 => map(parse_openvpn_msg_pack, Payload::Ack)(i),
        Opcode::P_DATA_V1 | Opcode::P_DATA_V2 => {
            map(rest, |x| Payload::Data(PData { contents: x }))(i)
        }
        _ => Err(::nom::Err::Error(error_position!(i, ErrorKind::Tag))),
    }
}

pub fn parse_openvpn_msg_pcontrol(i: &[u8]) -> IResult<&[u8], PControl> {
    let (i, session_id) = be_u64(i)?;
    let (i, hmac) = take(20usize)(i)?;
    let (i, packet_id) = be_u32(i)?;
    let (i, net_time) = be_u32(i)?;
    let (i, msg_ar_len) = be_u8(i)?;
    let (i, msg_ar) = cond(msg_ar_len > 0, count(be_u32, msg_ar_len as usize))(i)?;
    let (i, remote_session_id) = cond(msg_ar_len > 0, be_u64)(i)?;
    let (i, msg_packet_id) = be_u32(i)?;
    let (i, payload) = rest(i)?;
    let pcontrol = PControl {
        session_id,
        hmac,
        packet_id,
        net_time,
        msg_ar_len,
        msg_ar,
        remote_session_id,
        msg_packet_id,
        payload,
    };
    Ok((i, pcontrol))
}

pub fn parse_openvpn_msg_pack(i: &[u8]) -> IResult<&[u8], PAck> {
    let (i, session_id) = be_u64(i)?;
    let (i, hmac) = take(20usize)(i)?;
    let (i, packet_id) = be_u32(i)?;
    let (i, net_time) = be_u32(i)?;
    let (i, msg_ar_len) = be_u8(i)?;
    let (i, msg_ar) = cond(msg_ar_len > 0, count(be_u32, msg_ar_len as usize))(i)?;
    let (i, remote_session_id) = cond(msg_ar_len > 0, be_u64)(i)?;
    let pack = PAck {
        session_id,
        hmac,
        packet_id,
        net_time,
        msg_ar_len,
        msg_ar,
        remote_session_id,
    };
    Ok((i, pack))
}
