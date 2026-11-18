// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the AmneziaWG module
//! loaded and root privileges: CAP_NET_ADMIN, and CAP_NET_RAW for the link
//! tests, which read their tunnel with a packet socket.
//!
//! These tests are compiled only on Linux. They skip themselves when the
//! AmneziaWG family is not available or the process lacks the privileges they
//! need; the ones that set ranges also skip on a module older than AmneziaWG
//! 3.0. `AWG_INTEGRATION=1` says the run is meant to reach the module: then a
//! test that cannot run here fails.

#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, OwnedFd},
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

use futures::{FutureExt, StreamExt, TryStreamExt, lock::Mutex};
use genetlink::GenetlinkHandle;
use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAllowedIpFlags, AmneziaWireguardAttribute, AmneziaWireguardCmd,
    AmneziaWireguardDeviceFlags, AmneziaWireguardMessage, AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute, AmneziaWireguardPeerFlags, AmneziaWireguardRange,
    AmneziaWireguardTimeSpec,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs},
};
use nix::{
    errno::Errno,
    libc::PACKET_OUTGOING,
    sys::{
        socket::{
            AddressFamily, LinkAddr, SockFlag, SockProtocol, SockType, recvfrom, setsockopt,
            socket, sockopt,
        },
        time::TimeVal,
    },
};
use rtnetlink::{
    LinkMessageBuilder, LinkUnspec,
    packet_route::link::{InfoKind, LinkAttribute},
};

use AmneziaWireguardAttribute as A;
use AmneziaWireguardPeerAttribute as P;
use AmneziaWireguardRange as R;

/// Serializes access to netlink interface creation/deletion across tests.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// `None` for a test that cannot run here, so that it passes having asserted
/// nothing; a failure instead when `AWG_INTEGRATION=1` asks for the module.
fn skip<T>(reason: &str) -> Option<T> {
    if std::env::var("AWG_INTEGRATION").as_deref() == Ok("1") {
        panic!("AWG_INTEGRATION=1 and the test cannot run: {reason}");
    }
    eprintln!("Skipping integration test: {reason}");
    None
}

/// A genetlink handle and the amneziawg family version, or `None` when the
/// tests cannot run here.
async fn setup() -> Option<(GenetlinkHandle, u32)> {
    if !nix::unistd::geteuid().is_root() {
        return skip("not running as root");
    }
    let (connection, mut handle, _) = genetlink::new_connection().unwrap();
    tokio::spawn(connection);
    let Some(version) = family_version(&mut handle).await else {
        return skip("amneziawg family not available");
    };
    Some((handle, version))
}

/// As [`setup`], for a test that sets ranges: they are emitted in the form
/// of genl family version 3, which an older module does not take.
async fn setup_for_ranges() -> Option<GenetlinkHandle> {
    let (handle, version) = setup().await?;
    if version < 3 {
        return skip("the module is older than AmneziaWG 3.0");
    }
    Some(handle)
}

/// As [`setup_for_ranges`], for a test that reads its tunnel.
async fn setup_for_link() -> Option<GenetlinkHandle> {
    let handle = setup_for_ranges().await?;
    match tunnel_tap() {
        Ok(_) => Some(handle),
        Err(Errno::EPERM) => skip("no CAP_NET_RAW for the packet socket that reads the tunnel"),
        Err(e) => panic!("opening a packet socket: {e}"),
    }
}

/// Queries the genl family version of the amneziawg module: 2 for the
/// v1.0 module, 3 for AmneziaWG 3.0. `None` when the family is not
/// registered.
async fn family_version(handle: &mut GenetlinkHandle) -> Option<u32> {
    let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName("amneziawg".to_string())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut stream = handle.request(nlmsg).await.ok()?;
    while let Some(result) = stream.next().await {
        if let Ok(rx) = result
            && let NetlinkPayload::InnerMessage(genl) = rx.payload
        {
            for nla in &genl.payload.nlas {
                if let GenlCtrlAttrs::Version(v) = nla {
                    return Some(*v);
                }
            }
        }
    }
    None
}

/// An amneziawg interface created over rtnetlink for the duration of a test.
struct TestInterface {
    name: String,
    index: u32,
    handle: rtnetlink::Handle,
}

impl TestInterface {
    async fn create(prefix: &str) -> Self {
        let name = format!("{prefix}_{}", std::process::id());
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        let link = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(InfoKind::Other(
            "amneziawg".into(),
        ))
        .name(name.clone())
        .build();
        handle.link().add(link).execute().await.unwrap();
        let index = handle
            .link()
            .get()
            .match_name(name.clone())
            .execute()
            .try_next()
            .await
            .unwrap()
            .expect("created interface is listed")
            .header
            .index;
        Self {
            name,
            index,
            handle,
        }
    }

    async fn bring_up(&self, address: Ipv4Addr, prefix_len: u8) {
        self.handle
            .address()
            .add(self.index, address.into(), prefix_len)
            .execute()
            .await
            .unwrap();
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(self.index).up().build())
            .execute()
            .await
            .unwrap();
    }

    async fn mtu(&self) -> u32 {
        let link = self
            .handle
            .link()
            .get()
            .match_index(self.index)
            .execute()
            .try_next()
            .await
            .unwrap()
            .expect("interface is listed");
        link.attributes
            .iter()
            .find_map(|attr| match attr {
                LinkAttribute::Mtu(mtu) => Some(*mtu),
                _ => None,
            })
            .expect("interface has an MTU")
    }

    async fn delete(self) {
        self.handle.link().del(self.index).execute().await.unwrap();
    }
}

/// Runs `body` on interfaces created for it, then deletes every one that was
/// created, whether `body`, a creation or a deletion failed; the first
/// failure is the one raised.
async fn with_interfaces<const N: usize>(
    prefixes: [&str; N],
    body: impl AsyncFnOnce(&[TestInterface; N]),
) {
    let mut interfaces = Vec::new();
    let outcome = AssertUnwindSafe(async {
        for prefix in prefixes {
            interfaces.push(TestInterface::create(prefix).await);
        }
        body(interfaces.as_slice().try_into().unwrap()).await;
    })
    .catch_unwind()
    .await;
    let mut failure = outcome.err();
    for interface in interfaces {
        if let Err(panic) = AssertUnwindSafe(interface.delete()).catch_unwind().await {
            failure.get_or_insert(panic);
        }
    }
    if let Some(panic) = failure {
        std::panic::resume_unwind(panic);
    }
}

fn allowed_ip(address: IpAddr, cidr: u8) -> AmneziaWireguardAllowedIp {
    let family = match address {
        IpAddr::V4(_) => AmneziaWireguardAddressFamily::Ipv4,
        IpAddr::V6(_) => AmneziaWireguardAddressFamily::Ipv6,
    };
    AmneziaWireguardAllowedIp(vec![
        AmneziaWireguardAllowedIpAttr::Family(family),
        AmneziaWireguardAllowedIpAttr::IpAddr(address),
        AmneziaWireguardAllowedIpAttr::Cidr(cidr),
    ])
}

/// A peer's allowed IPs as address and prefix length, in order: the kernel
/// reports an allowed IP's attributes in an order of its own.
fn allowed_ips(peer: &[P]) -> Vec<(IpAddr, u8)> {
    let mut ips: Vec<_> = peer
        .iter()
        .filter_map(|attr| match attr {
            P::AllowedIps(ips) => Some(ips),
            _ => None,
        })
        .flatten()
        .map(|ip| {
            let address = ip.iter().find_map(|attr| match attr {
                AmneziaWireguardAllowedIpAttr::IpAddr(address) => Some(*address),
                _ => None,
            });
            let cidr = ip.iter().find_map(|attr| match attr {
                AmneziaWireguardAllowedIpAttr::Cidr(cidr) => Some(*cidr),
                _ => None,
            });
            (
                address.unwrap_or_else(|| panic!("allowed IP {ip:?} without an address")),
                cidr.unwrap_or_else(|| panic!("allowed IP {ip:?} without a prefix length")),
            )
        })
        .collect();
    ips.sort();
    ips
}

async fn send_request(
    handle: &mut GenetlinkHandle,
    msg: AmneziaWireguardMessage,
    flags: u16,
) -> std::io::Result<Vec<AmneziaWireguardMessage>> {
    let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = flags;

    let mut responses = Vec::new();
    let mut stream = handle.request(nlmsg).await.map_err(std::io::Error::other)?;
    while let Some(result) = stream.next().await {
        let rx = result.map_err(std::io::Error::other)?;
        match rx.payload {
            NetlinkPayload::InnerMessage(genl) => {
                responses.push(genl.payload);
            }
            NetlinkPayload::Error(e) => return Err(e.to_io()),
            _ => {}
        }
    }
    Ok(responses)
}

async fn get_device(
    handle: &mut GenetlinkHandle,
    ifname: &str,
) -> std::io::Result<Vec<AmneziaWireguardMessage>> {
    let get_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::GetDevice,
        attributes: vec![A::IfName(ifname.into())],
    };
    send_request(handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await
}

/// The device's attributes, for a device that fits in one message.
async fn device(handle: &mut GenetlinkHandle, ifname: &str) -> Vec<A> {
    let mut responses = get_device(handle, ifname)
        .await
        .unwrap_or_else(|e| panic!("{ifname}: GetDevice: {e}"));
    assert_eq!(responses.len(), 1, "{ifname}: expected one message");
    responses.remove(0).attributes
}

async fn try_set_device(
    handle: &mut GenetlinkHandle,
    ifname: &str,
    attributes: Vec<A>,
) -> std::io::Result<()> {
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: [vec![A::IfName(ifname.into())], attributes].concat(),
    };
    let replies = send_request(handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await?;
    assert!(
        replies.is_empty(),
        "{ifname}: SetDevice answered {replies:?} besides its ack"
    );
    Ok(())
}

async fn set_device(handle: &mut GenetlinkHandle, ifname: &str, attributes: Vec<A>) {
    try_set_device(handle, ifname, attributes)
        .await
        .unwrap_or_else(|e| panic!("{ifname}: SetDevice: {e}"));
}

fn peers(attrs: &[A]) -> Vec<Vec<P>> {
    attrs
        .iter()
        .filter_map(|attr| match attr {
            A::Peers(peers) => Some(peers),
            _ => None,
        })
        .flatten()
        .map(|peer| peer.0.clone())
        .collect()
}

async fn only_peer(handle: &mut GenetlinkHandle, ifname: &str) -> Vec<P> {
    let peers = peers(&device(handle, ifname).await);
    let [peer] = <[_; 1]>::try_from(peers)
        .unwrap_or_else(|peers| panic!("{ifname}: expected one peer, got {peers:?}"));
    peer
}

fn assert_read_back<T: PartialEq + std::fmt::Debug>(what: &str, read: &[T], expected: &[T]) {
    for attr in expected {
        assert!(read.contains(attr), "{what}: {attr:?} not read back");
    }
}

/// Decoys that use between them every tag the module parses.
fn decoys() -> [A; 5] {
    [
        A::I1("<b 0xc0ffee01><r 149>".into()),
        A::I2("<c><t>".into()),
        A::I3("<rc 24>".into()),
        A::I4("<rd 12>".into()),
        A::I5("<b 0x5a5a><c><t><r 8><rc 8><rd 8>".into()),
    ]
}

/// Decoys the module takes in other shapes: upper-case hex, text outside the
/// tags, which it skips, a tag of no bytes, and a long one.
fn decoy_variants() -> [A; 5] {
    [
        A::I1("<b 0xDEADBEEF>".into()),
        A::I2("before<r 4>after".into()),
        A::I3("<r 0>".into()),
        A::I4(format!("<b 0x{}>", "a5".repeat(256))),
        A::I5("<rc 1><rd 1><t><c><b 0x00>".into()),
    ]
}

fn empty_decoys() -> [A; 5] {
    [
        A::I1(String::new()),
        A::I2(String::new()),
        A::I3(String::new()),
        A::I4(String::new()),
        A::I5(String::new()),
    ]
}

/// Every obfuscation and timing parameter, and the mark, each off its default
/// and every range with its low end below its high end, but the content
/// padding. Header protection needs every S1..S4 padding to hold its 12-byte
/// nonce. The decoy tags `rc` and `rd` and the last two attributes need a 3.1
/// module; the genl family version does not tell 3.0 and 3.1 apart.
fn device_parameters(header_protection_key: [u8; 32], content_padding: R<u16>) -> Vec<A> {
    [
        A::Fwmark(0x51),
        A::Jc(4),
        A::Jmin(40),
        A::Jmax(70),
        A::S1(92),
        A::S2(115),
        A::S3(44),
        A::S4(29),
        A::H1(R {
            lo: 61220074,
            hi: 118999195,
        }),
        A::H2(R {
            lo: 605047389,
            hi: 945520346,
        }),
        A::H3(R {
            lo: 1477291385,
            hi: 1814368140,
        }),
        A::H4(R {
            lo: 1951993942,
            hi: 1997499713,
        }),
        A::HeaderProtectionKey(header_protection_key),
        A::ContentPaddingAddition(content_padding),
        A::RekeyAfterTime(R { lo: 140, hi: 160 }),
        A::RekeyTimeout(R { lo: 6, hi: 8 }),
        A::RejectAfterTime(R { lo: 200, hi: 220 }),
        A::KeepaliveTimeout(R { lo: 11, hi: 13 }),
        A::MaxHandshakeAttempts(R { lo: 20, hi: 24 }),
        A::RandomTrailers(true),
        A::DisableCookies(true),
    ]
    .into_iter()
    .chain(decoys())
    .collect()
}

const CONTENT_PADDING: R<u16> = R { lo: 8, hi: 16 };

// The one test that runs on a module older than AmneziaWG 3.0, whose device
// the crate still reads.
#[tokio::test]
async fn test_get_device_on_amneziawg_interface() {
    let _guard = TEST_MUTEX.lock().await;
    let Some((mut handle, _)) = setup().await else {
        return;
    };

    with_interfaces(["awg_get"], async |[interface]| {
        let attrs = device(&mut handle, &interface.name).await;
        assert!(
            attrs.contains(&A::IfName(interface.name.clone())),
            "expected IfName attribute in get response"
        );
    })
    .await;
}

#[tokio::test]
async fn test_set_and_get_amnezia_parameters() {
    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_ranges().await else {
        return;
    };

    with_interfaces(["awg_set"], async |[interface]| {
        let ifname = &interface.name;
        let device_attrs = [
            vec![A::ListenPort(51820)],
            device_parameters([0x11; 32], CONTENT_PADDING),
        ]
        .concat();
        let peer = vec![
            P::PublicKey([0x5a; 32]),
            P::PresharedKey([0x6b; 32]),
            P::Endpoint(SocketAddr::from((
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                51820,
            ))),
            P::PersistentKeepalive(R { lo: 25, hi: 30 }),
            P::AllowedIps(vec![
                allowed_ip(Ipv4Addr::new(198, 51, 100, 0).into(), 24),
                allowed_ip(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0).into(), 48),
            ]),
        ];
        set_device(
            &mut handle,
            ifname,
            [
                device_attrs.clone(),
                vec![A::Peers(vec![AmneziaWireguardPeer(peer.clone())])],
            ]
            .concat(),
        )
        .await;

        let attrs = device(&mut handle, ifname).await;
        assert_read_back(ifname, &attrs, &device_attrs);
        let [read_peer] = <[_; 1]>::try_from(peers(&attrs))
            .unwrap_or_else(|peers| panic!("expected one peer, got {peers:?}"));
        assert_read_back("peer", &read_peer, &peer[..4]);
        assert_eq!(allowed_ips(&read_peer), allowed_ips(&peer));

        // Each text is read back as written; the empty one reads back empty.
        for change in [
            decoy_variants().to_vec(),
            [
                empty_decoys().to_vec(),
                vec![A::RandomTrailers(false), A::DisableCookies(false)],
            ]
            .concat(),
        ] {
            set_device(&mut handle, ifname, change.clone()).await;
            assert_read_back(ifname, &device(&mut handle, ifname).await, &change);
        }
    })
    .await;
}

// The module returns a range as it was given, so reading one back cannot show
// its two ends swapped on the wire. Its overlap check can: with the ends
// swapped these two ranges are both reversed, share nothing, and are taken.
#[tokio::test]
async fn test_overlapping_header_ranges_are_refused() {
    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_ranges().await else {
        return;
    };

    with_interfaces(["awg_ovl"], async |[interface]| {
        let refused = try_set_device(
            &mut handle,
            &interface.name,
            vec![A::H1(R { lo: 10, hi: 20 }), A::H2(R { lo: 15, hi: 30 })],
        )
        .await;
        let error = refused.expect_err("overlapping header ranges are taken");
        assert_eq!(error.raw_os_error(), Some(Errno::EINVAL as i32), "{error}");
    })
    .await;
}

// More allowed IPs than one message holds: the module splits the dump, and
// each part names the peer it continues.
#[tokio::test]
async fn test_device_dump_split_over_messages_is_read_whole() {
    let _guard = TEST_MUTEX.lock().await;
    let Some((mut handle, _)) = setup().await else {
        return;
    };

    with_interfaces(["awg_dmp"], async |[interface]| {
        let ifname = &interface.name;
        let peer_key = [0x5a; 32];
        let first = u32::from(Ipv4Addr::new(198, 18, 0, 0));
        let ips: Vec<(IpAddr, u8)> = (first..first + 4096)
            .map(|ip| (Ipv4Addr::from(ip).into(), 32))
            .collect();
        for chunk in ips.chunks(1024) {
            let peer = AmneziaWireguardPeer(vec![
                P::PublicKey(peer_key),
                P::AllowedIps(
                    chunk
                        .iter()
                        .map(|&(ip, cidr)| allowed_ip(ip, cidr))
                        .collect(),
                ),
            ]);
            set_device(&mut handle, ifname, vec![A::Peers(vec![peer])]).await;
        }

        let responses = get_device(&mut handle, ifname).await.expect("get device");
        assert!(
            responses.len() > 1,
            "{} allowed IPs came in one message",
            ips.len()
        );
        let parts: Vec<_> = responses
            .iter()
            .flat_map(|response| peers(&response.attributes))
            .collect();
        for part in &parts {
            assert!(
                part.contains(&P::PublicKey(peer_key)),
                "a part of the dump without the peer's key: {part:?}"
            );
        }
        let mut read: Vec<_> = parts.iter().flat_map(|part| allowed_ips(part)).collect();
        read.sort();
        assert_eq!(read, ips);
    })
    .await;
}

#[tokio::test]
async fn test_peer_and_allowed_ip_flags_take_effect() {
    let _guard = TEST_MUTEX.lock().await;
    let Some((mut handle, _)) = setup().await else {
        return;
    };

    with_interfaces(["awg_flg"], async |[interface]| {
        let ifname = &interface.name;
        let ip = |last| allowed_ip(Ipv4Addr::new(198, 51, 100, last).into(), 32);
        let peer = |key: u8, flags: Option<AmneziaWireguardPeerFlags>, ips| {
            AmneziaWireguardPeer(
                [P::PublicKey([key; 32])]
                    .into_iter()
                    .chain(flags.map(P::Flags))
                    .chain([P::AllowedIps(ips)])
                    .collect(),
            )
        };
        // Each step's change, and the peers and allowed IPs the device then has.
        let steps = [
            (
                vec![A::Peers(vec![
                    peer(1, None, vec![ip(1), ip(2)]),
                    peer(2, None, vec![ip(3)]),
                ])],
                vec![(1, vec![1, 2]), (2, vec![3])],
            ),
            (
                vec![A::Peers(vec![peer(
                    1,
                    Some(AmneziaWireguardPeerFlags::ReplaceAllowedIps),
                    vec![ip(9), ip(10)],
                )])],
                vec![(1, vec![9, 10]), (2, vec![3])],
            ),
            (
                vec![A::Peers(vec![peer(1, None, {
                    let mut removed = ip(9);
                    removed.0.push(AmneziaWireguardAllowedIpAttr::Flags(
                        AmneziaWireguardAllowedIpFlags::RemoveMe,
                    ));
                    vec![removed]
                })])],
                vec![(1, vec![10]), (2, vec![3])],
            ),
            (
                vec![A::Peers(vec![peer(
                    2,
                    Some(AmneziaWireguardPeerFlags::RemoveMe),
                    vec![],
                )])],
                vec![(1, vec![10])],
            ),
            (
                vec![A::Peers(vec![peer(
                    3,
                    Some(AmneziaWireguardPeerFlags::UpdateOnly),
                    vec![ip(4)],
                )])],
                vec![(1, vec![10])],
            ),
            (
                vec![
                    A::Flags(AmneziaWireguardDeviceFlags::ReplacePeers),
                    A::Peers(vec![peer(4, None, vec![ip(5)])]),
                ],
                vec![(4, vec![5])],
            ),
        ];
        for (step, (change, expected)) in steps.into_iter().enumerate() {
            set_device(&mut handle, ifname, change).await;
            let mut read: Vec<_> = peers(&device(&mut handle, ifname).await)
                .iter()
                .map(|peer| {
                    let key = peer.iter().find_map(|attr| match attr {
                        P::PublicKey(key) => Some(key[0]),
                        _ => None,
                    });
                    (key.expect("peer without a key"), allowed_ips(peer))
                })
                .collect();
            read.sort();
            let expected: Vec<_> = expected
                .into_iter()
                .map(|(key, lasts)| {
                    let ips: Vec<_> = lasts.into_iter().map(&ip).collect();
                    (key, allowed_ips(&[P::AllowedIps(ips)]))
                })
                .collect();
            assert_eq!(read, expected, "after step {step}");
        }
    })
    .await;
}

/// One end of a link: its interface, its address in the tunnel, and its peer
/// attributes as they are set, to be read back.
struct LinkEnd<'a> {
    interface: &'a TestInterface,
    address: Ipv4Addr,
    peer: Vec<P>,
}

fn random_key() -> [u8; 32] {
    let mut key = [0; 32];
    getrandom::fill(&mut key).unwrap();
    key
}

/// Makes the two interfaces each other's peer over loopback endpoints, the
/// first with the first key, the second with the second, and everything else
/// on both the same. Each listens on a port the module picks.
async fn set_up_link<'a>(
    handle: &mut GenetlinkHandle,
    interfaces: &'a [TestInterface; 2],
    header_protection_keys: [[u8; 32]; 2],
    content_padding: R<u16>,
) -> [LinkEnd<'a>; 2] {
    let addresses = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
    let preshared_key = random_key();
    let mut identities = Vec::new();
    for ((interface, address), key) in interfaces.iter().zip(addresses).zip(header_protection_keys)
    {
        let ifname = &interface.name;
        let device_attrs = [
            vec![A::PrivateKey(random_key()), A::ListenPort(0)],
            device_parameters(key, content_padding),
        ]
        .concat();
        set_device(handle, ifname, device_attrs).await;
        interface.bring_up(address, 24).await;
        let attrs = device(handle, ifname).await;
        let public_key = attrs.iter().find_map(|attr| match attr {
            A::PublicKey(key) => Some(*key),
            _ => None,
        });
        let port = attrs.iter().find_map(|attr| match attr {
            A::ListenPort(port) => Some(*port),
            _ => None,
        });
        identities.push((
            public_key.unwrap_or_else(|| panic!("{ifname}: no public key read back")),
            port.filter(|&port| port != 0)
                .unwrap_or_else(|| panic!("{ifname}: no bound port read back, {port:?}")),
        ));
    }

    // No peer gets the advanced-security flag.
    let mut ends = Vec::new();
    for (index, interface) in interfaces.iter().enumerate() {
        let other = 1 - index;
        let (other_key, other_port) = identities[other];
        let peer = vec![
            P::PublicKey(other_key),
            P::PresharedKey(preshared_key),
            P::Endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, other_port))),
            P::PersistentKeepalive(R { lo: 1, hi: 2 }),
            P::AllowedIps(vec![allowed_ip(addresses[other].into(), 32)]),
        ];
        set_device(
            handle,
            &interface.name,
            vec![A::Peers(vec![AmneziaWireguardPeer(peer.clone())])],
        )
        .await;
        ends.push(LinkEnd {
            interface,
            address: addresses[index],
            peer,
        });
    }
    ends.try_into()
        .unwrap_or_else(|_| unreachable!("two interfaces make two ends"))
}

/// A packet socket that reads every packet on every interface, decrypted
/// tunnel traffic included: the tunnel's far end has the near end's address
/// too, so the IP layer drops what arrives as a martian.
fn tunnel_tap() -> nix::Result<OwnedFd> {
    let tap = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )?;
    setsockopt(&tap, sockopt::ReceiveTimeout, &TimeVal::new(0, 100_000))?;
    Ok(tap)
}

fn udp_payload(packet: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<&[u8]> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let is_ipv4_udp = packet[0] >> 4 == 4 && packet.get(9) == Some(&17);
    let addresses = packet.get(12..20)?;
    (is_ipv4_udp && addresses[..4] == src.octets() && addresses[4..] == dst.octets())
        .then(|| packet.get(header_len + 8..))
        .flatten()
}

/// Whether `payload` arrives on `to`'s interface before `until`.
fn arrives(
    tap: &OwnedFd,
    from: &LinkEnd<'_>,
    to: &LinkEnd<'_>,
    payload: &[u8],
    until: Instant,
) -> bool {
    let mut buffer = vec![0; 65536];
    while Instant::now() < until {
        let (len, origin) = match recvfrom::<LinkAddr>(tap.as_raw_fd(), &mut buffer) {
            Ok(received) => received,
            Err(Errno::EAGAIN) => continue,
            Err(e) => panic!("reading the packet socket: {e}"),
        };
        if origin.is_some_and(|origin| {
            origin.ifindex() == to.interface.index as usize && origin.pkttype() != PACKET_OUTGOING
        }) && udp_payload(&buffer[..len], from.address, to.address) == Some(payload)
        {
            return true;
        }
    }
    false
}

/// Sends `payload` into the tunnel at `from` once a second until it arrives
/// intact at `to`: the bytes sent, or `None` if it has not arrived `within`.
fn pass_through_tunnel(
    from: &LinkEnd<'_>,
    to: &LinkEnd<'_>,
    payload: &[u8],
    within: Duration,
) -> Option<u64> {
    let tap = tunnel_tap().expect("packet socket");
    let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    // Bound to the device, the route to `to.address` goes into the tunnel
    // rather than to the local address it also is.
    setsockopt(
        &sender,
        sockopt::BindToDevice,
        &OsString::from(&from.interface.name),
    )
    .unwrap();
    let deadline = Instant::now() + within;
    let mut sent = 0;
    while Instant::now() < deadline {
        sent += sender
            .send_to(payload, (to.address, 9))
            .expect("send into the tunnel") as u64;
        let resend = (Instant::now() + Duration::from_secs(1)).min(deadline);
        if arrives(&tap, from, to, payload, resend) {
            return Some(sent);
        }
    }
    None
}

fn random_payload(size: usize) -> Vec<u8> {
    let mut payload = vec![0; size];
    getrandom::fill(&mut payload).unwrap();
    payload
}

fn last_handshake(peer: &[P]) -> Option<&AmneziaWireguardTimeSpec> {
    peer.iter()
        .find_map(|attr| match attr {
            P::LastHandshake(time) => Some(time),
            _ => None,
        })
        .filter(|time| time.seconds != 0 || time.nano_seconds != 0)
}

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// Passes a small payload and one at the tunnel MTU each way over a link with
/// every device parameter set, and reads back what the link shows. Cookie
/// replies, and so `S3` and `H3`, never go out on it, and no timer fires in a
/// run this short.
async fn link_passes_traffic(content_padding: R<u16>) {
    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_link().await else {
        return;
    };

    with_interfaces(["awg_la", "awg_lb"], async |interfaces| {
        let key = random_key();
        let [a, b] = set_up_link(&mut handle, interfaces, [key, key], content_padding).await;

        // Bytes sent each way, resent copies included, and bytes that arrived,
        // one copy of each payload: a copy the module drops counts on the
        // sending end only.
        let mut sent = [0, 0];
        let mut arrived = [0, 0];
        for (direction, (from, to)) in [(&a, &b), (&b, &a)].into_iter().enumerate() {
            let mtu = from.interface.mtu().await as usize;
            for size in [32, mtu - IPV4_HEADER_LEN - UDP_HEADER_LEN] {
                arrived[direction] += size as u64;
                sent[direction] +=
                    pass_through_tunnel(from, to, &random_payload(size), Duration::from_secs(30))
                        .unwrap_or_else(|| {
                            panic!(
                                "{size} bytes from {} did not arrive intact at {}",
                                from.interface.name, to.interface.name
                            )
                        });
            }
        }

        for (end, (sent_out, arrived_in)) in
            [(&a, (sent[0], arrived[1])), (&b, (sent[1], arrived[0]))]
        {
            let ifname = &end.interface.name;
            let peer = only_peer(&mut handle, ifname).await;
            assert_read_back(ifname, &peer, &end.peer[1..4]);
            assert!(last_handshake(&peer).is_some(), "{ifname}: no handshake");
            let counter = |name, kind: fn(&P) -> Option<u64>| {
                peer.iter()
                    .find_map(kind)
                    .unwrap_or_else(|| panic!("{ifname}: no {name} read back"))
            };
            let tx = counter("TxBytes", |attr| match attr {
                P::TxBytes(n) => Some(*n),
                _ => None,
            });
            let rx = counter("RxBytes", |attr| match attr {
                P::RxBytes(n) => Some(*n),
                _ => None,
            });
            assert!(
                tx >= sent_out,
                "{ifname}: {tx} bytes sent to the peer, under the {sent_out} of payload"
            );
            assert!(
                rx >= arrived_in,
                "{ifname}: {rx} bytes received from the peer, under the {arrived_in} of payload"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_link_with_content_padding_passes_traffic() {
    link_passes_traffic(CONTENT_PADDING).await;
}

// With no content padding, the random trailer pads data packets too.
#[tokio::test]
async fn test_link_with_random_trailers_passes_traffic() {
    link_passes_traffic(R::from(0)).await;
}

// No peer is flagged for advanced security: the device's key alone turns
// header protection on, so two different keys keep the link down.
#[tokio::test]
async fn test_link_with_different_header_protection_keys_carries_nothing() {
    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_link().await else {
        return;
    };

    with_interfaces(["awg_la", "awg_lb"], async |interfaces| {
        let keys = [random_key(), random_key()];
        let [a, b] = set_up_link(&mut handle, interfaces, keys, CONTENT_PADDING).await;
        let arrived = pass_through_tunnel(&a, &b, &random_payload(32), Duration::from_secs(5));
        assert!(arrived.is_none(), "a payload passed between different keys");
        for end in [&a, &b] {
            let ifname = &end.interface.name;
            let peer = only_peer(&mut handle, ifname).await;
            assert!(
                last_handshake(&peer).is_none(),
                "{ifname}: a handshake between different keys, {:?}",
                last_handshake(&peer)
            );
        }
    })
    .await;
}
