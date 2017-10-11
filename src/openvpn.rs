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

#[derive(Debug,PartialEq)]
pub struct OpenVPNHdr {
    /// Packet length, TCP only
    pub plen: Option<u16>,
    pub opcode: u8,
    pub key: u8,
}

pub const P_CONTROL_V1 : u8 = 0x4;
pub const P_ACK_V1 : u8 = 0x5;

pub const P_CONTROL_HARD_RESET_CLIENT_V2 : u8 = 0x7;
pub const P_CONTROL_HARD_RESET_SERVER_V2 : u8 = 0x8;


#[derive(Debug,PartialEq)]
pub struct PControl<'a> {
    pub session_id: u64,
    /// 16 or 20 bytes
    pub hmac: &'a[u8],
    /// replay protection, 4 or 8 bytes (see `net_time`)
    pub packet_id: u32,
    /// Optional part of replay protection
    pub net_time: u32,
    pub msg_packet_id: u32,
    pub payload: &'a[u8],
}

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
    pub msg_ar: Option<&'a[u8]>,
    pub remote_id: Option<u64>,
    pub msg_packet_id: u32,
    pub payload: &'a[u8],
}

#[derive(Debug,PartialEq)]
pub struct PData<'a> {
    pub contents: &'a[u8],
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

pub fn parse_openvpn_msg_pcontrol(i:&[u8]) -> IResult<&[u8],PControl> {
    do_parse!(i,
        sid:  be_u64 >>
        hmac: take!(20) >>
        pid:  be_u32 >>
        tm:   be_u32 >>
        mid:  be_u32 >>
        p:    rest >>
        (
            PControl{
                session_id: sid,
                hmac: hmac,
                packet_id: pid,
                net_time: tm,
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
        ar:   cond!(arl > 0, take!(4 * arl)) >>
        mid:  be_u32 >>
        p:    rest >>
        (
            PAck{
                session_id: sid,
                hmac: hmac,
                packet_id: pid,
                net_time: tm,
                msg_ar_len: arl,
                msg_ar: ar,
                remote_id: None,
                msg_packet_id: mid,
                payload: p,
            }
        )
    )
}
