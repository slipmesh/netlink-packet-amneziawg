// SPDX-License-Identifier: MIT

//! AmneziaWG generic netlink packets, built on `netlink-packet-wireguard`.
//!
//! The attributes AmneziaWG shares with WireGuard are parsed and emitted by
//! the upstream crate; this crate adds the `amneziawg` family, the device
//! attributes AmneziaWG appends, and the peer keepalive whose wire type
//! AmneziaWG 3.0 widened to `u32`.

pub mod range;

mod attribute;
mod message;
mod peer;

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod test;

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
};
