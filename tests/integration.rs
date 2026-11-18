// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the AmneziaWG module
//! loaded and root privileges: CAP_NET_ADMIN, and CAP_NET_RAW for the link
//! test, which reads its tunnel with a packet socket.
//!
//! These tests are compiled only on Linux. They skip themselves when the
//! AmneziaWG family is not available or the process lacks the privileges to
//! create network interfaces; the ones that set ranges also skip on a module
//! older than AmneziaWG 3.0. `AWG_INTEGRATION=1` says the run is meant to
//! reach the module: then a test that cannot run here fails.

#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, OwnedFd},
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

use futures::{FutureExt, StreamExt, TryStreamExt, lock::Mutex};
use genetlink::GenetlinkHandle;
use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage, AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute, AmneziaWireguardRange,
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

fn allowed_ipv4(address: Ipv4Addr, cidr: u8) -> AmneziaWireguardAllowedIp {
    AmneziaWireguardAllowedIp(vec![
        AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv4),
        AmneziaWireguardAllowedIpAttr::IpAddr(address.into()),
        AmneziaWireguardAllowedIpAttr::Cidr(cidr),
    ])
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
        attributes: vec![AmneziaWireguardAttribute::IfName(ifname.into())],
    };
    send_request(handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await
}

#[tokio::test]
async fn test_get_device_on_amneziawg_interface() {
    let _guard = TEST_MUTEX.lock().await;
    let Some((mut handle, _)) = setup().await else {
        return;
    };

    let interface = TestInterface::create("awg_get").await;
    let responses = get_device(&mut handle, &interface.name).await;
    let ifname = interface.name.clone();
    // Deleted before asserting, so a failed assertion leaves no interface behind.
    interface.delete().await;

    let responses = responses.expect("get device");
    assert_eq!(responses.len(), 1, "expected one response for get device");
    assert!(
        responses[0]
            .attributes
            .contains(&AmneziaWireguardAttribute::IfName(ifname)),
        "expected IfName attribute in get response"
    );
}

#[tokio::test]
async fn test_set_and_get_amnezia_parameters() {
    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardRange as R;

    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_ranges().await else {
        return;
    };

    let header = |lo, hi| R::<u32> { lo, hi };
    let peer_key = [0x5a; 32];
    let keepalive = AmneziaWireguardPeerAttribute::PersistentKeepalive(R { lo: 25, hi: 30 });

    // Read back as set. Header protection needs every S1..S4 padding to hold
    // its 12-byte nonce. The decoy tags `rc` and `rd` and the last two
    // attributes need a 3.1 module; the genl family version does not tell 3.0
    // and 3.1 apart.
    let mut device = vec![
        A::ListenPort(51820),
        A::Fwmark(0x51),
        A::Jc(4),
        A::Jmin(40),
        A::Jmax(70),
        A::S1(92),
        A::S2(115),
        A::S3(44),
        A::S4(29),
        A::H1(header(61220074, 118999195)),
        A::H2(header(605047389, 945520346)),
        A::H3(header(1477291385, 1814368140)),
        A::H4(header(1951993942, 1997499713)),
        A::HeaderProtectionKey([0x11; 32]),
        A::ContentPaddingAddition(R { lo: 0, hi: 16 }),
        A::RekeyAfterTime(R::from(150)),
        A::RekeyTimeout(R::from(6)),
        A::RejectAfterTime(R { lo: 200, hi: 220 }),
        A::KeepaliveTimeout(R::from(12)),
        A::MaxHandshakeAttempts(R::from(20)),
        A::RandomTrailers(true),
        A::DisableCookies(true),
    ];
    device.extend(decoys());
    let allowed_ip = allowed_ipv4(Ipv4Addr::new(198, 51, 100, 0), 24);

    let interface = TestInterface::create("awg_set").await;
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: [
            vec![A::IfName(interface.name.clone())],
            device.clone(),
            vec![A::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(peer_key),
                keepalive.clone(),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![allowed_ip.clone()]),
            ])])],
        ]
        .concat(),
    };
    let ack_responses = send_request(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await;
    let responses = get_device(&mut handle, &interface.name).await;
    let cleared = clear_decoys(&mut handle, &interface.name).await;
    // Deleted before asserting, so a failed assertion leaves no interface behind.
    interface.delete().await;

    assert!(
        ack_responses.expect("set device").is_empty(),
        "set device with NLM_F_ACK should return no payload on success"
    );
    let responses = responses.expect("get device");
    assert_eq!(responses.len(), 1, "expected one response for get device");
    let attrs = &responses[0].attributes;
    for expected in &device {
        assert!(attrs.contains(expected), "{expected:?} not read back");
    }

    let peers: Vec<_> = attrs
        .iter()
        .filter_map(|attr| match attr {
            A::Peers(peers) => Some(peers),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(peers.len(), 1, "expected one peer");
    for expected in [
        AmneziaWireguardPeerAttribute::PublicKey(peer_key),
        keepalive,
    ] {
        assert!(
            peers[0].contains(&expected),
            "peer {expected:?} not read back"
        );
    }
    // The kernel reports an allowed IP's attributes in its own order.
    let allowed_ips = peers[0].iter().find_map(|attr| match attr {
        AmneziaWireguardPeerAttribute::AllowedIps(ips) => Some(ips),
        _ => None,
    });
    let [read_ip] = allowed_ips.expect("allowed IPs read back").as_slice() else {
        panic!("expected one allowed IP, got {allowed_ips:?}");
    };
    assert_eq!(read_ip.len(), allowed_ip.len(), "allowed IP {read_ip:?}");
    assert!(
        allowed_ip.iter().all(|attr| read_ip.contains(attr)),
        "allowed IP {read_ip:?} instead of {allowed_ip:?}"
    );

    // The module sends a decoy only when its text yields a packet, so the
    // empty text clears it; the text is still read back, empty.
    let cleared = cleared.expect("clear decoys");
    let attrs = &cleared[0].attributes;
    for expected in empty_decoys() {
        assert!(attrs.contains(&expected), "{expected:?} not read back");
    }
}

/// Decoys that use between them every tag the module parses.
fn decoys() -> [AmneziaWireguardAttribute; 5] {
    use AmneziaWireguardAttribute as A;
    [
        A::I1("<b 0xc0ffee01><r 149>".into()),
        A::I2("<c><t>".into()),
        A::I3("<rc 24>".into()),
        A::I4("<rd 12>".into()),
        A::I5("<b 0x5a5a><c><t><r 8><rc 8><rd 8>".into()),
    ]
}

fn empty_decoys() -> [AmneziaWireguardAttribute; 5] {
    use AmneziaWireguardAttribute as A;
    [
        A::I1(String::new()),
        A::I2(String::new()),
        A::I3(String::new()),
        A::I4(String::new()),
        A::I5(String::new()),
    ]
}

async fn clear_decoys(
    handle: &mut GenetlinkHandle,
    ifname: &str,
) -> std::io::Result<Vec<AmneziaWireguardMessage>> {
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: [
            vec![AmneziaWireguardAttribute::IfName(ifname.into())],
            empty_decoys().into(),
        ]
        .concat(),
    };
    send_request(handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await?;
    get_device(handle, ifname).await
}

// The module returns a range as it was given, so reading one back cannot show
// its two ends swapped on the wire. Its overlap check can: with the ends
// swapped these two ranges are both reversed, share nothing, and are taken.
#[tokio::test]
async fn test_overlapping_header_ranges_are_refused() {
    use AmneziaWireguardAttribute as A;

    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_ranges().await else {
        return;
    };

    let interface = TestInterface::create("awg_ovl").await;
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: vec![
            A::IfName(interface.name.clone()),
            A::H1(AmneziaWireguardRange { lo: 10, hi: 20 }),
            A::H2(AmneziaWireguardRange { lo: 15, hi: 30 }),
        ],
    };
    let refused = send_request(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await;
    // Deleted before asserting, so a failed assertion leaves no interface behind.
    interface.delete().await;

    let error = refused.expect_err("overlapping header ranges are taken");
    assert_eq!(
        error.raw_os_error(),
        Some(nix::errno::Errno::EINVAL as i32),
        "{error}"
    );
}

/// The device parameters both ends of the link get: every one the module
/// takes, each off its default, in the single values the config format
/// gives. The header protection key is one both ends share.
fn link_obfuscation(header_protection_key: [u8; 32]) -> Vec<AmneziaWireguardAttribute> {
    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardRange as R;
    vec![
        A::Fwmark(0x51),
        A::Jc(4),
        A::Jmin(40),
        A::Jmax(70),
        A::S1(92),
        A::S2(115),
        A::S3(44),
        A::S4(29),
        A::H1(R::from(61220074)),
        A::H2(R::from(605047389)),
        A::H3(R::from(1477291385)),
        A::H4(R::from(1951993942)),
        A::HeaderProtectionKey(header_protection_key),
        A::ContentPaddingAddition(R::from(16)),
        A::RekeyAfterTime(R::from(150)),
        A::RekeyTimeout(R::from(6)),
        A::RejectAfterTime(R::from(210)),
        A::KeepaliveTimeout(R::from(12)),
        A::MaxHandshakeAttempts(R::from(20)),
        A::RandomTrailers(true),
        A::DisableCookies(true),
    ]
    .into_iter()
    .chain(decoys())
    .collect()
}

/// One end of the link: its interface, its address in the tunnel and the
/// port its UDP socket listens on, an endpoint on loopback.
struct LinkEnd<'a> {
    interface: &'a TestInterface,
    address: Ipv4Addr,
    port: u16,
}

fn random_key() -> [u8; 32] {
    let mut key = [0; 32];
    getrandom::fill(&mut key).unwrap();
    key
}

async fn set_device(
    handle: &mut GenetlinkHandle,
    ifname: &str,
    attributes: Vec<AmneziaWireguardAttribute>,
) {
    let set_msg = AmneziaWireguardMessage {
        cmd: AmneziaWireguardCmd::SetDevice,
        attributes: [
            vec![AmneziaWireguardAttribute::IfName(ifname.into())],
            attributes,
        ]
        .concat(),
    };
    send_request(handle, set_msg, NLM_F_REQUEST | NLM_F_ACK)
        .await
        .unwrap_or_else(|e| panic!("set device {ifname}: {e}"));
}

async fn device_and_peer(
    handle: &mut GenetlinkHandle,
    ifname: &str,
) -> (
    Vec<AmneziaWireguardAttribute>,
    Vec<AmneziaWireguardPeerAttribute>,
) {
    let mut responses = get_device(handle, ifname).await.expect("get device");
    assert_eq!(responses.len(), 1, "expected one response for get device");
    let attrs = responses.remove(0).attributes;
    let mut peers: Vec<_> = attrs
        .iter()
        .filter_map(|attr| match attr {
            AmneziaWireguardAttribute::Peers(peers) => Some(peers.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(peers.len(), 1, "expected one peer on {ifname}");
    (attrs, peers.remove(0).0)
}

/// A packet socket that reads every packet on every interface, decrypted
/// tunnel traffic included: the tunnel's far end has the near end's address
/// too, so the IP layer drops what arrives as a martian.
fn tunnel_tap() -> OwnedFd {
    let tap = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthAll,
    )
    .expect("packet socket");
    setsockopt(&tap, sockopt::ReceiveTimeout, &TimeVal::new(1, 0)).unwrap();
    tap
}

fn udp_payload(packet: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<&[u8]> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let is_ipv4_udp = packet[0] >> 4 == 4 && packet.get(9) == Some(&17);
    let addresses = packet.get(12..20)?;
    (is_ipv4_udp && addresses[..4] == src.octets() && addresses[4..] == dst.octets())
        .then(|| packet.get(header_len + 8..))
        .flatten()
}

/// Whether `payload` arrives on `to`'s interface before the tap times out.
fn arrives(tap: &OwnedFd, from: &LinkEnd<'_>, to: &LinkEnd<'_>, payload: &[u8]) -> bool {
    let mut buffer = vec![0; 65536];
    loop {
        let (len, origin) = match recvfrom::<LinkAddr>(tap.as_raw_fd(), &mut buffer) {
            Ok(received) => received,
            Err(Errno::EAGAIN) => return false,
            Err(e) => panic!("reading the packet socket: {e}"),
        };
        let Some(origin) = origin else { continue };
        if origin.ifindex() == to.interface.index as usize
            && origin.pkttype() != PACKET_OUTGOING
            && udp_payload(&buffer[..len], from.address, to.address) == Some(payload)
        {
            return true;
        }
    }
}

/// Sends `payload` into the tunnel at `from` until it arrives intact at
/// `to`; the first send starts the handshake. Returns the bytes sent.
fn pass_through_tunnel(from: &LinkEnd<'_>, to: &LinkEnd<'_>, payload: &[u8]) -> u64 {
    let tap = tunnel_tap();
    let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    // Bound to the device, the route to `to.address` goes into the tunnel
    // rather than to the local address it also is.
    setsockopt(
        &sender,
        sockopt::BindToDevice,
        &OsString::from(&from.interface.name),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut sent = 0;
    loop {
        sent += sender
            .send_to(payload, (to.address, 9))
            .expect("send into the tunnel") as u64;
        if arrives(&tap, from, to, payload) {
            return sent;
        }
        assert!(
            Instant::now() < deadline,
            "{} bytes from {} did not arrive intact at {}",
            payload.len(),
            from.interface.name,
            to.interface.name
        );
    }
}

/// Brings up two interfaces that are each other's peer, with every device
/// parameter set on both, and passes traffic both ways.
async fn exercise_link(handle: &mut GenetlinkHandle, a: &LinkEnd<'_>, b: &LinkEnd<'_>) {
    use AmneziaWireguardAttribute as A;
    use AmneziaWireguardPeerAttribute as P;

    let header_protection_key = random_key();
    let preshared_key = random_key();
    let obfuscation = link_obfuscation(header_protection_key);

    let mut public_keys = Vec::new();
    for end in [a, b] {
        let ifname = &end.interface.name;
        let device = [
            vec![A::PrivateKey(random_key()), A::ListenPort(end.port)],
            obfuscation.clone(),
        ]
        .concat();
        set_device(handle, ifname, device).await;
        let responses = get_device(handle, ifname).await.expect("get device");
        let attrs = &responses[0].attributes;
        for expected in &obfuscation {
            assert!(
                attrs.contains(expected),
                "{ifname}: {expected:?} not read back"
            );
        }
        public_keys.push(
            attrs
                .iter()
                .find_map(|attr| match attr {
                    A::PublicKey(key) => Some(*key),
                    _ => None,
                })
                .expect("public key read back"),
        );
    }

    // No peer gets the advanced-security flag: the device's key alone turns
    // header protection on.
    for (end, (peer, peer_key)) in [(a, (b, public_keys[1])), (b, (a, public_keys[0]))] {
        let peer = AmneziaWireguardPeer(vec![
            P::PublicKey(peer_key),
            P::PresharedKey(preshared_key),
            P::Endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, peer.port))),
            P::PersistentKeepalive(AmneziaWireguardRange::from(25)),
            P::AllowedIps(vec![allowed_ipv4(peer.address, 32)]),
        ]);
        set_device(handle, &end.interface.name, vec![A::Peers(vec![peer])]).await;
        end.interface.bring_up(end.address, 24).await;
    }

    let mut sent = [0, 0];
    for (direction, (from, to)) in [(a, b), (b, a)].into_iter().enumerate() {
        let mtu = from.interface.mtu().await;
        for size in [32, mtu as usize - 20 - 8] {
            let mut payload = vec![0; size];
            getrandom::fill(&mut payload).unwrap();
            sent[direction] += pass_through_tunnel(from, to, &payload);
        }
    }

    for (end, (sent_out, sent_in)) in [(a, (sent[0], sent[1])), (b, (sent[1], sent[0]))] {
        let ifname = &end.interface.name;
        let (_, peer) = device_and_peer(handle, ifname).await;
        let handshake = peer.iter().find_map(|attr| match attr {
            P::LastHandshake(time) => Some(time),
            _ => None,
        });
        assert!(
            handshake.is_some_and(|time| time.seconds != 0 || time.nano_seconds != 0),
            "{ifname}: no handshake, {handshake:?}"
        );
        let counter = |kind: fn(&P) -> Option<u64>| peer.iter().find_map(kind).unwrap_or(0);
        let tx = counter(|attr| match attr {
            P::TxBytes(n) => Some(*n),
            _ => None,
        });
        let rx = counter(|attr| match attr {
            P::RxBytes(n) => Some(*n),
            _ => None,
        });
        assert!(
            tx >= sent_out,
            "{ifname}: {tx} bytes sent to the peer, under the {sent_out} of payload"
        );
        assert!(
            rx >= sent_in,
            "{ifname}: {rx} bytes received from the peer, under the {sent_in} of payload"
        );
    }
}

#[tokio::test]
async fn test_link_with_every_parameter_passes_traffic() {
    let _guard = TEST_MUTEX.lock().await;
    let Some(mut handle) = setup_for_ranges().await else {
        return;
    };

    let interface_a = TestInterface::create("awg_la").await;
    let interface_b = TestInterface::create("awg_lb").await;
    let a = LinkEnd {
        interface: &interface_a,
        address: Ipv4Addr::new(192, 0, 2, 1),
        port: 51821,
    };
    let b = LinkEnd {
        interface: &interface_b,
        address: Ipv4Addr::new(192, 0, 2, 2),
        port: 51822,
    };
    let outcome = AssertUnwindSafe(exercise_link(&mut handle, &a, &b))
        .catch_unwind()
        .await;
    // Deleted before the outcome is raised, so a failure leaves no interface behind.
    interface_a.delete().await;
    interface_b.delete().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
