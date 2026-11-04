// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the AmneziaWG module
//! loaded and root privileges (CAP_NET_ADMIN).
//!
//! These tests are compiled only on Linux. They will soft-skip themselves
//! when the AmneziaWG family is not available or the process lacks the
//! privileges to create network interfaces.

#![cfg(target_os = "linux")]

use futures::{StreamExt, TryStreamExt, lock::Mutex};
use genetlink::GenetlinkHandle;
use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage, AmneziaWireguardPeer,
    AmneziaWireguardPeerAttribute, range::u32_range_from_string,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs},
};
use rtnetlink::{LinkMessageBuilder, LinkUnspec, packet_route::link::InfoKind};

/// Serializes access to netlink interface creation/deletion across tests.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// A genetlink handle and the amneziawg family version, or `None` when the
/// tests cannot run here.
async fn setup() -> Option<(GenetlinkHandle, u32)> {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("Skipping integration test: not running as root");
        return None;
    }
    let (connection, mut handle, _) = genetlink::new_connection().unwrap();
    tokio::spawn(connection);
    let Some(version) = family_version(&mut handle).await else {
        eprintln!("Skipping integration test: amneziawg family not available");
        return None;
    };
    Some((handle, version))
}

/// Queries the genl family version of the amneziawg module: 2 for the
/// v1.0 module, 3 for AmneziaWG 3.0. The magic header and keepalive wire
/// formats depend on it. `None` when the family is not registered.
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
    let mut stream = handle.request(nlmsg).await.unwrap();
    while let Some(result) = stream.next().await {
        let rx = result.unwrap();
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

    let _guard = TEST_MUTEX.lock().await;
    let Some((mut handle, version)) = setup().await else {
        return;
    };

    let headers = [
        "61220074-118999195",
        "605047389-945520346",
        "1477291385-1814368140",
        "1951993942-1997499713",
    ];
    let peer_key = [0x5a; 32];

    // Read back in the form the kernel reports, which is what SetDevice sends
    // except where the module version picks the wire type.
    // Header protection needs every S1..S4 padding to hold its 12-byte nonce.
    let mut common = vec![
        A::ListenPort(51820),
        A::JC(4),
        A::Jmin(40),
        A::Jmax(70),
        A::S1(92),
        A::S2(115),
        A::S3(44),
        A::S4(29),
        A::I1("<r 149>".into()),
    ];
    let read_headers = vec![
        A::H1(headers[0].into()),
        A::H2(headers[1].into()),
        A::H3(headers[2].into()),
        A::H4(headers[3].into()),
    ];
    let (set_headers, keepalive) = if version >= 3 {
        let range = |i: usize| u32_range_from_string(headers[i]).unwrap();
        // The AmneziaWG 3.1 attributes below need a 3.1 module; the genl family version
        // does not tell 3.0 and 3.1 apart.
        common.extend([
            A::HeaderProtectionKey([0x11; 32]),
            A::ContentPaddingAddition(16),
            A::RekeyAfterTime(150),
            A::RekeyTimeout(6),
            A::RejectAfterTime(200),
            A::KeepaliveTimeout(12),
            A::MaxHandshakeAttempts(20),
            A::RandomTrailers(true),
            A::DisableCookies(true),
        ]);
        (
            vec![
                A::H1Range(range(0)),
                A::H2Range(range(1)),
                A::H3Range(range(2)),
                A::H4Range(range(3)),
            ],
            AmneziaWireguardPeerAttribute::PersistentKeepaliveRange(25 | (25 << 16)),
        )
    } else {
        (
            read_headers.clone(),
            AmneziaWireguardPeerAttribute::PersistentKeepalive(25),
        )
    };
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
            common.clone(),
            set_headers,
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
    for expected in common.iter().chain(&read_headers) {
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
