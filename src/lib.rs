// SPDX-License-Identifier: MIT

//! AmneziaWG generic netlink packets, built on `netlink-packet-wireguard`.
//!
//! The attributes AmneziaWG shares with WireGuard are parsed and emitted by
//! the upstream crate; this crate adds the `amneziawg` family, the device
//! attributes AmneziaWG appends, and the peer keepalive, which AmneziaWG 3.0
//! made a range.

mod attribute;
mod message;
mod peer;
mod range;

pub use netlink_packet_wireguard::{
    WireguardAddressFamily as AmneziaWireguardAddressFamily,
    WireguardAllowedIp as AmneziaWireguardAllowedIp,
    WireguardAllowedIpAttr as AmneziaWireguardAllowedIpAttr,
    WireguardAllowedIpFlags as AmneziaWireguardAllowedIpFlags, WireguardCmd as AmneziaWireguardCmd,
    WireguardDeviceFlags as AmneziaWireguardDeviceFlags,
    WireguardPeerFlags as AmneziaWireguardPeerFlags, WireguardTimeSpec as AmneziaWireguardTimeSpec,
};

pub use self::{
    attribute::AmneziaWireguardAttribute,
    message::AmneziaWireguardMessage,
    peer::{AmneziaWireguardPeer, AmneziaWireguardPeerAttribute},
    range::AmneziaWireguardRange,
};
