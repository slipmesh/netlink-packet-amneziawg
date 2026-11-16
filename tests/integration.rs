// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the AmneziaWG module
//! loaded and root privileges (CAP_NET_ADMIN).
//!
//! These tests are compiled only on Linux. They skip themselves when the
//! AmneziaWG family is not available, is older than AmneziaWG 3.0, or the
//! process lacks the privileges to create network interfaces, unless
//! `AWG_INTEGRATION=1` says the run is meant to reach the module: then a test
//! that cannot run here fails.

#![cfg(target_os = "linux")]

use futures::{StreamExt, TryStreamExt, lock::Mutex};
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
use rtnetlink::{LinkMessageBuilder, LinkUnspec, packet_route::link::InfoKind};

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

    async fn delete(self) {
        self.handle.link().del(self.index).execute().await.unwrap();
    }
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
    // its 12-byte nonce. The last two attributes need a 3.1 module; the genl
    // family version does not tell 3.0 and 3.1 apart.
    let device = vec![
        A::ListenPort(51820),
        A::Jc(4),
        A::Jmin(40),
        A::Jmax(70),
        A::S1(92),
        A::S2(115),
        A::S3(44),
        A::S4(29),
        A::I1("<r 149>".into()),
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
    let allowed_ip = AmneziaWireguardAllowedIp(vec![
        AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv4),
        AmneziaWireguardAllowedIpAttr::IpAddr([10, 99, 0, 0].into()),
        AmneziaWireguardAllowedIpAttr::Cidr(24),
    ]);

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
