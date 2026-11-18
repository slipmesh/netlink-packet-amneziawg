// SPDX-License-Identifier: MIT

//! Messages parsed from and emitted to the bytes the kernel modules send and
//! take, without a module.

// The captured and built bytes are in little-endian order.
#![cfg(target_endian = "little")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use hex_literal::hex;
use netlink_packet_core::{Emitable, Parseable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;
use pretty_assertions::assert_eq;

use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardDeviceFlags,
    AmneziaWireguardMessage, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
    AmneziaWireguardPeerFlags, AmneziaWireguardRange, AmneziaWireguardTimeSpec,
};

// nlmon capture of kernel netlink packet reply of `sudo wg` command with
// netlink header purged(generic netlink command is first byte).
//  * private key is masked to vec![01..31]
//  * ip address is masked to 1.1.1.1:1111
#[test]
fn test_query_reply() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x2c, 0x80, 0x00, 0x00, 0x08, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x00,
        0x02, 0x00, 0x63, 0x6e, 0x00, 0x00, 0x24, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x24, 0x00, 0x04,
        0x00, 0xcc, 0xaf, 0x10, 0xe1, 0xa9, 0xd7, 0xd0, 0x5f, 0xf2, 0xbd, 0xd2, 0xa0, 0xf1, 0x78,
        0x2d, 0x97, 0x46, 0x9a, 0x1c, 0xf7, 0xbe, 0x88, 0x0f, 0x68, 0x75, 0xa7, 0x79, 0x93, 0x5d,
        0x1d, 0x21, 0x75, 0xc0, 0x00, 0x08, 0x80, 0xbc, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00,
        0x77, 0xdc, 0x9a, 0xc0, 0xb3, 0xf0, 0xc5, 0xe7, 0x5b, 0xb8, 0xd3, 0x42, 0x2d, 0x88, 0xec,
        0x92, 0xd1, 0x3a, 0x34, 0x23, 0x22, 0x90, 0x87, 0x82, 0x15, 0x51, 0x57, 0x19, 0x69, 0xde,
        0xa0, 0x44, 0x24, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00, 0x9a, 0x24, 0x77,
        0x69, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xa8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x05, 0x00, 0x19, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x80, 0x40, 0x1d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x07, 0x00, 0x98, 0x44, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
        0x57, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x09, 0x80, 0x1c, 0x00, 0x00, 0x80, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let attributes = vec![
        AmneziaWireguardAttribute::ListenPort(32812),
        AmneziaWireguardAttribute::Fwmark(0),
        AmneziaWireguardAttribute::IfIndex(3),
        AmneziaWireguardAttribute::IfName("cn".to_string()),
        AmneziaWireguardAttribute::PrivateKey([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        AmneziaWireguardAttribute::PublicKey([
            204, 175, 16, 225, 169, 215, 208, 95, 242, 189, 210, 160, 241, 120, 45, 151, 70, 154,
            28, 247, 190, 136, 15, 104, 117, 167, 121, 147, 93, 29, 33, 117,
        ]),
        AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
            AmneziaWireguardPeerAttribute::PublicKey([
                119, 220, 154, 192, 179, 240, 197, 231, 91, 184, 211, 66, 45, 136, 236, 146, 209,
                58, 52, 35, 34, 144, 135, 130, 21, 81, 87, 25, 105, 222, 160, 68,
            ]),
            AmneziaWireguardPeerAttribute::PresharedKey([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            AmneziaWireguardPeerAttribute::LastHandshake(AmneziaWireguardTimeSpec {
                seconds: 1769415834,
                nano_seconds: 262671874,
            }),
            AmneziaWireguardPeerAttribute::PersistentKeepalive(25.into()),
            AmneziaWireguardPeerAttribute::TxBytes(1917056),
            AmneziaWireguardPeerAttribute::RxBytes(30426264),
            AmneziaWireguardPeerAttribute::ProtocolVersion(1),
            AmneziaWireguardPeerAttribute::Endpoint(
                std::net::SocketAddr::from_str("1.1.1.1:1111").unwrap(),
            ),
            AmneziaWireguardPeerAttribute::AllowedIps(vec![AmneziaWireguardAllowedIp(vec![
                AmneziaWireguardAllowedIpAttr::Cidr(0),
                AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv4),
                AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ])]),
        ])]),
    ];

    let expected: AmneziaWireguardMessage = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes,
    };

    let header = GenlHeader::parse(&raw[..]).unwrap();

    assert_eq!(
        expected,
        AmneziaWireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    // The keepalive in this capture is the 2-byte form of a module older than AmneziaWG 3.0 and
    // is emitted in the 4-byte one, so what is emitted is compared after reading it back.
    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(
        expected,
        AmneziaWireguardMessage::parse_with_param(&buffer, header).unwrap(),
    );
}

// nlmon capture of kernel netlink packet reply of `sudo wg setconf` command
// against existing wireguard interface
#[test]
fn test_setconf_against_existing_wg() {
    let raw: Vec<u8> = vec![
        0x01, 0x01, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x77, 0x67, 0x30, 0x00, 0x24, 0x00, 0x03,
        0x00, 0x08, 0xf8, 0x74, 0x0f, 0xc2, 0x87, 0xda, 0x7a, 0x1c, 0x44, 0xfc, 0x1a, 0x73, 0x5c,
        0xec, 0xf3, 0xb0, 0x9e, 0x33, 0x81, 0x18, 0x22, 0x08, 0x75, 0x34, 0x8b, 0x88, 0xac, 0x75,
        0x5b, 0xfe, 0x59, 0x06, 0x00, 0x06, 0x00, 0x03, 0xd9, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x08,
        0x80, 0x78, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00, 0x7b, 0xff, 0x32, 0x8c, 0x65, 0x6b,
        0x0d, 0xa2, 0x38, 0x58, 0x16, 0xee, 0x0b, 0x47, 0xe9, 0xdc, 0x5b, 0xba, 0x3b, 0xf7, 0x79,
        0x82, 0xd8, 0xdc, 0x99, 0x34, 0x73, 0xed, 0xe5, 0x72, 0xb4, 0x0f, 0x08, 0x00, 0x03, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x48, 0x00, 0x09, 0x80, 0x1c, 0x00, 0x00, 0x80, 0x06, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0xc0, 0x00, 0x02, 0x02, 0x05, 0x00,
        0x03, 0x00, 0x20, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x80, 0x06, 0x00, 0x01, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x03, 0x00, 0x80, 0x00, 0x00,
        0x00,
    ];

    let expected = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName("wg0".to_string()),
            AmneziaWireguardAttribute::PrivateKey([
                8, 248, 116, 15, 194, 135, 218, 122, 28, 68, 252, 26, 115, 92, 236, 243, 176, 158,
                51, 129, 24, 34, 8, 117, 52, 139, 136, 172, 117, 91, 254, 89,
            ]),
            AmneziaWireguardAttribute::ListenPort(55555),
            AmneziaWireguardAttribute::Fwmark(0),
            AmneziaWireguardAttribute::Flags(AmneziaWireguardDeviceFlags::ReplacePeers),
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey([
                    123, 255, 50, 140, 101, 107, 13, 162, 56, 88, 22, 238, 11, 71, 233, 220, 91,
                    186, 59, 247, 121, 130, 216, 220, 153, 52, 115, 237, 229, 114, 180, 15,
                ]),
                AmneziaWireguardPeerAttribute::Flags(AmneziaWireguardPeerFlags::ReplaceAllowedIps),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv4),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::new(
                            192, 0, 2, 2,
                        ))),
                        AmneziaWireguardAllowedIpAttr::Cidr(32),
                    ]),
                    AmneziaWireguardAllowedIp(vec![
                        AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv6),
                        AmneziaWireguardAllowedIpAttr::IpAddr(IpAddr::V6(
                            Ipv6Addr::from_str("2001:db8:1::2").unwrap(),
                        )),
                        AmneziaWireguardAllowedIpAttr::Cidr(128),
                    ]),
                ]),
            ])]),
        ],
    };

    let header = GenlHeader::parse(&raw[..]).unwrap();

    assert_eq!(
        expected,
        AmneziaWireguardMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

/// One netlink attribute as it goes on the wire: length, kind, payload, padding to 4 bytes.
fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(&((4 + payload.len()) as u16).to_le_bytes());
    wire.extend_from_slice(&kind.to_le_bytes());
    wire.extend_from_slice(payload);
    wire.resize(wire.len().next_multiple_of(4), 0);
    wire
}

fn parse_msg(attributes: &[u8], version: u8) -> Vec<AmneziaWireguardAttribute> {
    parse_msg_checked(attributes, version).unwrap()
}

fn parse_msg_checked(
    attributes: &[u8],
    version: u8,
) -> Result<Vec<AmneziaWireguardAttribute>, netlink_packet_core::DecodeError> {
    let header = GenlHeader {
        cmd: AmneziaWireguardCmd::GetDevice.into(),
        version,
    };
    AmneziaWireguardMessage::parse_with_param(attributes, header).map(|msg| msg.attributes)
}

#[test]
fn test_empty_peers_roundtrip() {
    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            AmneziaWireguardAttribute::IfName("awg0".into()),
            AmneziaWireguardAttribute::Peers(vec![]),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);
    assert_eq!(parse_msg(&buffer, 2), msg.attributes);
}

// Every attribute AmneziaWG adds, pinned to the bytes the AmneziaWG 3.0 kernel module expects
// and read back from them. Values differ per attribute so that two swapped kinds cannot pass.
#[test]
fn test_amnezia_attribute_wire_format() {
    use netlink_packet_core::NlaBuffer;

    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardPeerAttribute as P;
    use AmneziaWireguardRange as R;

    let peer_key = [hex!("2400 0100").as_slice(), &[0x07; 32]].concat();
    let peers = |attr| A::Peers(vec![AmneziaWireguardPeer(vec![attr])]);
    let rows: Vec<(A, Vec<u8>)> = vec![
        (A::Jc(1), hex!("0600 0900 0100 0000").into()),
        (A::Jmin(2), hex!("0600 0a00 0200 0000").into()),
        (A::Jmax(3), hex!("0600 0b00 0300 0000").into()),
        (A::S1(4), hex!("0600 0c00 0400 0000").into()),
        (A::S2(5), hex!("0600 0d00 0500 0000").into()),
        (A::S3(6), hex!("0600 1300 0600 0000").into()),
        (A::S4(7), hex!("0600 1400 0700 0000").into()),
        // Two u32 ends in a u64, low end first.
        (
            A::H1(R { lo: 1, hi: 2 }),
            hex!("0c00 0e00 0100 0000 0200 0000").into(),
        ),
        (
            A::H2(R { lo: 3, hi: 4 }),
            hex!("0c00 0f00 0300 0000 0400 0000").into(),
        ),
        (
            A::H3(R { lo: 5, hi: 6 }),
            hex!("0c00 1000 0500 0000 0600 0000").into(),
        ),
        (
            A::H4(R { lo: 7, hi: 8 }),
            hex!("0c00 1100 0700 0000 0800 0000").into(),
        ),
        (A::I1("a".into()), hex!("0600 1500 6100 0000").into()),
        (A::I2("b".into()), hex!("0600 1600 6200 0000").into()),
        (A::I3("c".into()), hex!("0600 1700 6300 0000").into()),
        (A::I4("d".into()), hex!("0600 1800 6400 0000").into()),
        (A::I5("e".into()), hex!("0600 1900 6500 0000").into()),
        (
            A::HeaderProtectionKey([0x11; 32]),
            [hex!("2400 1a00").as_slice(), &[0x11; 32]].concat(),
        ),
        // Two u16 ends in a u32, low end first.
        (
            A::ContentPaddingAddition(R { lo: 9, hi: 25 }),
            hex!("0800 1b00 0900 1900").into(),
        ),
        (
            A::RekeyAfterTime(R { lo: 10, hi: 26 }),
            hex!("0800 1c00 0a00 1a00").into(),
        ),
        (
            A::RekeyTimeout(R { lo: 11, hi: 27 }),
            hex!("0800 1d00 0b00 1b00").into(),
        ),
        (
            A::RejectAfterTime(R { lo: 12, hi: 28 }),
            hex!("0800 1e00 0c00 1c00").into(),
        ),
        (
            A::KeepaliveTimeout(R { lo: 13, hi: 29 }),
            hex!("0800 1f00 0d00 1d00").into(),
        ),
        (
            A::MaxHandshakeAttempts(R { lo: 14, hi: 30 }),
            hex!("0800 2000 0e00 1e00").into(),
        ),
        (A::RandomTrailers(true), hex!("0500 2100 0100 0000").into()),
        (A::DisableCookies(true), hex!("0500 2200 0100 0000").into()),
        // WG_CMD_UNKNOWN_PEER nests the peer attributes directly under WGDEVICE_A_PEER, with no
        // per-peer header as in WGDEVICE_A_PEERS.
        (
            A::Peer(AmneziaWireguardPeer(vec![P::PublicKey([0x07; 32])])),
            [hex!("2800 1280").as_slice(), &peer_key].concat(),
        ),
        (
            peers(P::PersistentKeepalive(R { lo: 25, hi: 30 })),
            hex!("1000 0880 0c00 0080 0800 0500 1900 1e00").into(),
        ),
        // The ends are kept in the order they arrive.
        (
            peers(P::PersistentKeepalive(R { lo: 25, hi: 0 })),
            hex!("1000 0880 0c00 0080 0800 0500 1900 0000").into(),
        ),
    ];

    for (attr, wire) in rows {
        let mut buf = vec![0; attr.buffer_len()];
        attr.emit(&mut buf);
        assert_eq!(buf, wire, "emitting {attr:?}");
        assert_eq!(
            A::parse(&NlaBuffer::new_checked(&wire).unwrap()).unwrap(),
            attr,
            "parsing {attr:?}"
        );
    }
}

// A module older than AmneziaWG 3.0 sends the keepalive as the 2 bytes WireGuard does.
#[test]
fn test_keepalive_of_an_older_module_is_the_range_of_one_value() {
    use AmneziaWireguardPeerAttribute::PersistentKeepalive;

    let peers = nla(8 | 0x8000, &nla(0x8000, &nla(5, &hex!("1900"))));
    assert_eq!(
        parse_msg(&peers, 2),
        vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![PersistentKeepalive(25.into())])
        ])]
    );
}

// Kinds neither crate knows, such as the zero-length WGPEER_A_ADVANCED_SECURITY flag (11) the
// AmneziaWG module puts into WG_CMD_UNKNOWN_PEER, must survive parsing and emit unchanged.
#[test]
fn test_unknown_attributes_roundtrip_as_other() {
    use netlink_packet_core::NlaBuffer;

    let advanced_security = nla(11, &[]);
    let unknown = nla(99, &hex!("dead beef"));
    let peer = nla(18 | 0x8000, &[advanced_security, unknown.clone()].concat());

    for wire in [&peer, &unknown] {
        let attr =
            AmneziaWireguardAttribute::parse(&NlaBuffer::new_checked(wire).unwrap()).unwrap();
        let mut buf = vec![0; attr.buffer_len()];
        attr.emit(&mut buf);
        assert_eq!(&buf, wire);
    }

    let parsed = AmneziaWireguardAttribute::parse(&NlaBuffer::new_checked(&peer).unwrap()).unwrap();
    let AmneziaWireguardAttribute::Peer(peer) = parsed else {
        panic!("expected WGDEVICE_A_PEER, got {parsed:?}");
    };
    assert_eq!(peer.len(), 2);
    assert!(
        peer.iter()
            .all(|attr| matches!(attr, AmneziaWireguardPeerAttribute::Other(_)))
    );
}

// The genl header carries the family version, which fixes the magic header wire type: an 8-byte
// u64 range from a version 3 module stays a range even when its bytes read as a digit string,
// a version 2 string is read as a number or as `lo-hi`, and a version 1 u32 stays a number.
#[test]
fn test_magic_header_decoded_by_family_version() {
    use AmneziaWireguardAttribute::H1;
    use AmneziaWireguardRange as R;

    let digits = nla(14, b"1234567\0");
    let as_u64 = R {
        lo: 875770417,
        hi: 3618357,
    };
    assert_eq!(parse_msg(&digits, 3), vec![H1(as_u64)]);
    assert_eq!(parse_msg(&digits, 2), vec![H1(1234567.into())]);
    let spec = nla(14, b"61220074-118999195\0");
    let range = R {
        lo: 61220074,
        hi: 118999195,
    };
    assert_eq!(parse_msg(&spec, 2), vec![H1(range)]);
    assert_eq!(parse_msg(&nla(14, b"123\0"), 1), vec![H1(3355185.into())]);
}

// A reply has to be readable whatever the module holds, so the ends are not put in order; a
// string that is no number and no two numbers around a dash is refused.
#[test]
fn test_magic_header_string_is_read_as_it_is_or_refused() {
    use AmneziaWireguardAttribute::H1;

    let parse = |spec: &[u8]| {
        let header = GenlHeader {
            cmd: AmneziaWireguardCmd::GetDevice.into(),
            version: 2,
        };
        AmneziaWireguardMessage::parse_with_param(&nla(14, spec), header).map(|msg| msg.attributes)
    };

    assert_eq!(
        parse(b"9-5\0").unwrap(),
        vec![H1(AmneziaWireguardRange { lo: 9, hi: 5 })]
    );
    for spec in [
        &b"\0"[..],
        b"-\0",
        b"5-\0",
        b"-5\0",
        b"1-2-3\0",
        b"4294967296\0",
        b"12\0junk",
        b"12\0\0",
        b"12",
        b"+12\0",
        b" 12\0",
    ] {
        assert!(parse(spec).is_err(), "{spec:?}");
    }
}

// An attribute parsed on its own has no genl header. It is read in the form this crate emits,
// so that what is emitted is read back: the bytes of a range can spell a string of digits.
#[test]
fn test_magic_header_without_family_version_is_read_in_the_emitted_form() {
    use netlink_packet_core::NlaBuffer;

    use AmneziaWireguardAttribute::H1;
    use AmneziaWireguardRange as R;

    let parse = |payload: &[u8]| {
        let wire = nla(14, payload);
        AmneziaWireguardAttribute::parse(&NlaBuffer::new_checked(&wire).unwrap())
    };

    assert_eq!(
        parse(&hex!("0500 0000 0900 0000")).unwrap(),
        H1(R { lo: 5, hi: 9 })
    );
    let digits = R {
        lo: 875770417,
        hi: 3618357,
    };
    assert_eq!(parse(b"1234567\0").unwrap(), H1(digits));
    assert!(parse(&hex!("7b00 0000")).is_err());
    assert!(parse(b"5-9\0").is_err());
    assert!(parse(&hex!("0102")).is_err());
}

// Whatever the module holds is read and sent again as it is: a range with its ends out of
// order, the zero range, the widest one.
#[test]
fn test_every_range_attribute_is_read_back_as_emitted() {
    use netlink_packet_core::NlaBuffer;

    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardPeerAttribute as P;
    use AmneziaWireguardRange as R;

    let mut attrs = Vec::new();
    for range in [
        R {
            lo: 875770417,
            hi: 3618357,
        },
        R::default(),
        R {
            lo: 0,
            hi: u32::MAX,
        },
    ] {
        attrs.extend([A::H1(range), A::H2(range), A::H3(range), A::H4(range)]);
    }
    for range in [
        R { lo: 30, hi: 25 },
        R::default(),
        R {
            lo: 0,
            hi: u16::MAX,
        },
    ] {
        attrs.extend([
            A::ContentPaddingAddition(range),
            A::RekeyAfterTime(range),
            A::RekeyTimeout(range),
            A::RejectAfterTime(range),
            A::KeepaliveTimeout(range),
            A::MaxHandshakeAttempts(range),
            A::Peers(vec![AmneziaWireguardPeer(vec![P::PersistentKeepalive(
                range,
            )])]),
        ]);
    }

    for attr in attrs {
        let mut wire = vec![0; attr.buffer_len()];
        attr.emit(&mut wire);
        assert_eq!(
            A::parse(&NlaBuffer::new_checked(&wire).unwrap()).unwrap(),
            attr
        );
    }
}

// A payload of a length other than the range's is refused rather than read as part of one.
#[test]
fn test_range_attribute_of_a_wrong_length_is_refused() {
    use netlink_packet_core::NlaBuffer;

    let parse = |kind, payload: &[u8]| {
        let wire = nla(kind, payload);
        AmneziaWireguardAttribute::parse(&NlaBuffer::new_checked(&wire).unwrap())
    };
    for kind in 27..=32 {
        for payload in [&hex!("0900")[..], &hex!("0900 0000 0000 0000")] {
            let parsed = parse(kind, payload);
            assert!(parsed.is_err(), "kind {kind}, {payload:?}: {parsed:?}");
        }
    }
    let keepalive = nla(8 | 0x8000, &nla(0x8000, &nla(5, &hex!("1900 00"))));
    assert!(parse_msg_checked(&keepalive, 3).is_err());
}

// A magic header of the wrong length for the version that sent it is refused rather than read
// as another form.
#[test]
fn test_magic_header_of_a_wrong_length_for_its_version_is_refused() {
    for (payload, version) in [
        (&hex!("0500 0000 0900 0000")[..], 1),
        (&hex!("0500 0000")[..], 3),
        (&hex!("0500 0000 0900 0000 0000 0000")[..], 3),
    ] {
        let parsed = parse_msg_checked(&nla(14, payload), version);
        assert!(
            parsed.is_err(),
            "version {version}, {payload:?}: {parsed:?}"
        );
    }
}

// What this crate emits is what it reads back under the version its own header carries.
#[test]
fn test_message_is_read_back_under_its_own_version() {
    use netlink_packet_generic::GenlFamily;

    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardRange as R;

    let msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            A::IfName("awg0".into()),
            A::H1(R {
                lo: 875770417,
                hi: 3618357,
            }),
            A::H2(R { lo: 5, hi: 9 }),
            A::H3(7.into()),
            A::H4(R::default()),
            A::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PersistentKeepalive(R { lo: 25, hi: 30 }),
            ])]),
        ],
    };
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);
    assert_eq!(parse_msg(&buffer, msg.version()), msg.attributes);
}

#[test]
fn test_genl_family() {
    use netlink_packet_generic::GenlFamily;

    let message = |cmd| AmneziaWireguardMessage {
        cmd,
        attributes: vec![],
    };

    assert_eq!(AmneziaWireguardMessage::family_name(), "amneziawg");
    assert_eq!(message(AmneziaWireguardCmd::GetDevice).version(), 3);
    assert_eq!(message(AmneziaWireguardCmd::GetDevice).command(), 0);
    assert_eq!(message(AmneziaWireguardCmd::SetDevice).command(), 1);
}
