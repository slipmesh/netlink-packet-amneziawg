// SPDX-License-Identifier: MIT

use std::net::SocketAddr;

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, NLA_F_NESTED, Nla, NlaBuffer, NlasIterator,
    Parseable, emit_u32, parse_u32,
};
use netlink_packet_wireguard::WireguardPeerAttribute;

use crate::{AmneziaWireguardAllowedIp, AmneziaWireguardPeerFlags, AmneziaWireguardTimeSpec};

const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;

pub(crate) struct AmneziaWireguardPeers(pub(crate) Vec<AmneziaWireguardPeer>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AmneziaWireguardPeers {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        NlasIterator::new(buf.value())
            .map(|nla| AmneziaWireguardPeer::parse(&nla?))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardPeer(pub Vec<AmneziaWireguardPeerAttribute>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AmneziaWireguardPeer {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        NlasIterator::new(buf.value())
            .map(|nla| AmneziaWireguardPeerAttribute::parse(&nla?))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl Nla for AmneziaWireguardPeer {
    fn kind(&self) -> u16 {
        // linux kernel always set it to 0
        NLA_F_NESTED
    }

    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }
}

impl std::ops::Deref for AmneziaWireguardPeer {
    type Target = Vec<AmneziaWireguardPeerAttribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardPeerAttribute {
    PublicKey([u8; 32]),
    PresharedKey([u8; 32]),
    Endpoint(SocketAddr),
    /// Persistent keepalive interval in seconds.
    ///
    /// Emitted as `u16`, understood by kernel modules up to genl family
    /// version 2 (v1.0.20260725). When parsing, a 2-byte payload produces
    /// this variant.
    PersistentKeepalive(u16),
    /// Persistent keepalive as `u32` packing a `u16` range
    /// (`lo | hi << 16`), the wire format of the AmneziaWG 3.0 kernel
    /// module (genl family version 3). Produced by parsing 4-byte
    /// payloads; a plain interval `v` sent by new tools arrives as
    /// `v | v << 16`.
    PersistentKeepaliveRange(u32),
    LastHandshake(AmneziaWireguardTimeSpec),
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<AmneziaWireguardAllowedIp>),
    ProtocolVersion(u32),
    Flags(AmneziaWireguardPeerFlags),
    Other(DefaultNla),
}

impl AmneziaWireguardPeerAttribute {
    /// The same attribute as the upstream crate represents it, for the
    /// attributes whose wire format AmneziaWG did not change.
    fn to_wireguard(&self) -> Option<WireguardPeerAttribute> {
        Some(match self {
            Self::PublicKey(v) => WireguardPeerAttribute::PublicKey(*v),
            Self::PresharedKey(v) => WireguardPeerAttribute::PresharedKey(*v),
            Self::Endpoint(v) => WireguardPeerAttribute::Endpoint(*v),
            Self::PersistentKeepalive(v) => WireguardPeerAttribute::PersistentKeepalive(*v),
            Self::LastHandshake(v) => WireguardPeerAttribute::LastHandshake(*v),
            Self::RxBytes(v) => WireguardPeerAttribute::RxBytes(*v),
            Self::TxBytes(v) => WireguardPeerAttribute::TxBytes(*v),
            Self::ProtocolVersion(v) => WireguardPeerAttribute::ProtocolVersion(*v),
            Self::Flags(v) => WireguardPeerAttribute::Flags(*v),
            // Allowed IPs are emitted through their upstream `Nla` impl directly, which spares
            // cloning the whole list for every length and kind lookup.
            Self::AllowedIps(_) | Self::PersistentKeepaliveRange(_) | Self::Other(_) => {
                return None;
            }
        })
    }

    fn from_wireguard(attr: WireguardPeerAttribute) -> Option<Self> {
        Some(match attr {
            WireguardPeerAttribute::PublicKey(v) => Self::PublicKey(v),
            WireguardPeerAttribute::PresharedKey(v) => Self::PresharedKey(v),
            WireguardPeerAttribute::Endpoint(v) => Self::Endpoint(v),
            WireguardPeerAttribute::PersistentKeepalive(v) => Self::PersistentKeepalive(v),
            WireguardPeerAttribute::LastHandshake(v) => Self::LastHandshake(v),
            WireguardPeerAttribute::RxBytes(v) => Self::RxBytes(v),
            WireguardPeerAttribute::TxBytes(v) => Self::TxBytes(v),
            WireguardPeerAttribute::AllowedIps(v) => Self::AllowedIps(v),
            WireguardPeerAttribute::ProtocolVersion(v) => Self::ProtocolVersion(v),
            WireguardPeerAttribute::Flags(v) => Self::Flags(v),
            _ => return None,
        })
    }
}

impl AmneziaWireguardPeerAttribute {
    fn upstream(&self) -> WireguardPeerAttribute {
        self.to_wireguard()
            .expect("every peer attribute not encoded here is mapped by to_wireguard")
    }
}

impl Nla for AmneziaWireguardPeerAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::PersistentKeepaliveRange(v) => size_of_val(v),
            Self::AllowedIps(v) => v.as_slice().buffer_len(),
            Self::Other(v) => v.value_len(),
            _ => self.upstream().value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::PersistentKeepaliveRange(_) => WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
            Self::AllowedIps(_) => WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            Self::Other(v) => v.kind(),
            _ => self.upstream().kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::PersistentKeepaliveRange(v) => emit_u32(buffer, *v).unwrap(),
            Self::AllowedIps(v) => v.as_slice().emit(buffer),
            Self::Other(v) => v.emit_value(buffer),
            _ => self.upstream().emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AmneziaWireguardPeerAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        if buf.kind() == WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL && payload.len() == 4 {
            return Ok(Self::PersistentKeepaliveRange(parse_u32(payload).context(
                "invalid WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL value",
            )?));
        }
        let attr = WireguardPeerAttribute::parse(buf)?;
        match Self::from_wireguard(attr) {
            Some(v) => Ok(v),
            None => Ok(Self::Other(DefaultNla::parse(buf)?)),
        }
    }
}
