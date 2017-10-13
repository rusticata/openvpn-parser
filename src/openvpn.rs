//! OpenVPN parser
//!
//! Writen in great pain, due to lack of specifications, and a number of fields
//! defined in a very useless way, like "usually 16 or 20 bytes".
//!
//! Closest thing to specifications:
//!
//! - https://openvpn.net/index.php/open-source/documentation/security-overview.html
//! - OpenVPN source code
//! - OpenVPN wireshark parser

use nom::*;

/// OpenVPN packet
#[derive(Debug,PartialEq)]
pub struct OpenVPNPacket<'a> {
    pub hdr: OpenVPNHdr,
    pub msg: Payload<'a>,
}

/// OpenVPN packet header
///
/// TCP and UDP differ only by the presence of the `plen` field.
#[derive(Debug,PartialEq)]
pub struct OpenVPNHdr {
    /// Packet length, TCP only
    pub plen: Option<u16>,
    pub opcode: u8,
    pub key: u8,
}

pub const P_CONTROL_HARD_RESET_CLIENT_V1 : u8 = 0x1;
pub const P_CONTROL_HARD_RESET_SERVER_V1 : u8 = 0x2;
pub const P_CONTROL_SOFT_RESET_V1 : u8 = 0x3;
pub const P_CONTROL_V1 : u8 = 0x4;
pub const P_ACK_V1 : u8 = 0x5;
pub const P_DATA_V1 : u8 = 0x6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2 : u8 = 0x7;
pub const P_CONTROL_HARD_RESET_SERVER_V2 : u8 = 0x8;
pub const P_DATA_V2 : u8 = 0x9;


/// Payload for OpenVPN data
#[derive(Debug,PartialEq)]
pub enum Payload<'a> {
    Control(PControl<'a>),
    Ack(PAck<'a>),
    Data(PData<'a>),
}

/// Payload for P_CONTROL messages
#[derive(Debug,PartialEq)]
pub struct PControl<'a> {
    pub session_id: u64,
    /// 16 or 20 bytes
    pub hmac: &'a[u8],
    /// replay protection, 4 or 8 bytes (see `net_time`)
    pub packet_id: u32,
    /// Optional part of replay protection
    pub net_time: u32,
    pub msg_ar_len: u8,
    pub msg_ar: Option<Vec<u32>>,
    pub msg_packet_id: u32,
    pub remote_session_id: Option<u64>,
    pub payload: &'a[u8],
}

/// Payload for P_ACK messages
#[derive(Debug,PartialEq)]
pub struct PAck<'a> {
    pub session_id: u64,
    /// 16 or 20 bytes
    pub hmac: &'a[u8],
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
#[derive(Debug,PartialEq)]
pub struct PData<'a> {
    pub contents: &'a[u8],
}







/// Parse an OpnVPM packet in TCP
pub fn parse_openvpn_tcp(i:&[u8]) -> IResult<&[u8],OpenVPNPacket> {
    do_parse!(i,
        hdr: parse_openvpn_header_tcp >>
        // length includes header (minus plen field)
        // substract 1 (opcode + key)
        error_if!(hdr.plen == None, error_code!(ErrorKind::Custom(128))) >>
        plen: value!(hdr.plen.unwrap()) >>
        error_if!(plen < 2, error_code!(ErrorKind::Custom(128))) >>
        msg: flat_map!(take!(plen-1),call!(parse_openvpn_msg_payload,hdr.opcode)) >>
        (
            OpenVPNPacket{
                hdr:  hdr,
                msg: msg,
            }
        )
    )
}

/// Parse an OpnVPM packet in UDP
///
/// Note that this will consume the entire buffer
pub fn parse_openvpn_udp(i:&[u8]) -> IResult<&[u8],OpenVPNPacket> {
    do_parse!(i,
        hdr: parse_openvpn_header_udp >>
        msg: call!(parse_openvpn_msg_payload,hdr.opcode) >>
        (
            OpenVPNPacket{
                hdr:  hdr,
                msg: msg,
            }
        )
    )
}


pub fn parse_openvpn_header_tcp(i:&[u8]) -> IResult<&[u8],OpenVPNHdr> {
    do_parse!(i,
        plen: be_u16 >>
        opk: bits!(
            pair!(take_bits!(u8,5), take_bits!(u8,3))
        ) >>
        (
            OpenVPNHdr{
                plen: Some(plen),
                opcode: opk.0,
                key: opk.1,
            }
        )
    )
}

pub fn parse_openvpn_header_udp(i:&[u8]) -> IResult<&[u8],OpenVPNHdr> {
    do_parse!(i,
        opk: bits!(
            pair!(take_bits!(u8,5), take_bits!(u8,3))
        ) >>
        (
            OpenVPNHdr{
                plen: None,
                opcode: opk.0,
                key: opk.1,
            }
        )
    )
}

pub fn parse_openvpn_msg_payload(i:&[u8], msg_type:u8) -> IResult<&[u8],Payload> {
    match msg_type {
        P_CONTROL_V1 |
        P_CONTROL_HARD_RESET_CLIENT_V2 |
        P_CONTROL_HARD_RESET_SERVER_V2 => {
            map!(i, parse_openvpn_msg_pcontrol, |x| Payload::Control(x))
        },
        P_ACK_V1 => {
            map!(i, parse_openvpn_msg_pack, |x| Payload::Ack(x))
        }
        _ => map!(i, rest,|x| Payload::Data(PData{contents:x})),
    }
}

pub fn parse_openvpn_msg_pcontrol(i:&[u8]) -> IResult<&[u8],PControl> {
    do_parse!(i,
        sid:  be_u64 >>
        hmac: take!(20) >>
        pid:  be_u32 >>
        tm:   be_u32 >>
        arl:  be_u8 >>
        ar:   cond!(arl > 0, count!(be_u32,arl as usize)) >>
        rsid: cond!(arl > 0, be_u64) >>
        mid:  be_u32 >>
        p:    rest >>
        (
            PControl{
                session_id: sid,
                hmac: hmac,
                packet_id: pid,
                net_time: tm,
                msg_ar_len: arl,
                msg_ar: ar,
                remote_session_id: rsid,
                msg_packet_id: mid,
                payload: p,
            }
        )
    )
}

pub fn parse_openvpn_msg_pack(i:&[u8]) -> IResult<&[u8],PAck> {
    do_parse!(i,
        sid:  be_u64 >>
        hmac: take!(20) >>
        pid:  be_u32 >>
        tm:   be_u32 >>
        arl:  be_u8 >>
        ar:   cond!(arl > 0, count!(be_u32,arl as usize)) >>
        rsid: cond!(arl > 0, be_u64) >>
        (
            PAck{
                session_id: sid,
                hmac: hmac,
                packet_id: pid,
                net_time: tm,
                msg_ar_len: arl,
                msg_ar: ar,
                remote_session_id: rsid,
            }
        )
    )
}
