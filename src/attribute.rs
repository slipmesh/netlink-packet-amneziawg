// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, NLA_F_NESTED, Nla, NlaBuffer, Parseable,
    emit_u16, emit_u32, emit_u64, parse_string, parse_u8, parse_u16, parse_u32, parse_u64,
};
use netlink_packet_wireguard::WireguardAttribute;

use crate::{
    AmneziaWireguardDeviceFlags, AmneziaWireguardPeer, AmneziaWireguardRange,
    peer::AmneziaWireguardPeers,
};

const WG_KEY_LEN: usize = 32;
const HEADER_PROTECTION_KEY_LEN: usize = 32;

const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_A_JC: u16 = 9;
const WGDEVICE_A_JMIN: u16 = 10;
const WGDEVICE_A_JMAX: u16 = 11;
const WGDEVICE_A_S1: u16 = 12;
const WGDEVICE_A_S2: u16 = 13;
const WGDEVICE_A_H1: u16 = 14;
const WGDEVICE_A_H2: u16 = 15;
const WGDEVICE_A_H3: u16 = 16;
const WGDEVICE_A_H4: u16 = 17;
const WGDEVICE_A_PEER: u16 = 18;
const WGDEVICE_A_S3: u16 = 19;
const WGDEVICE_A_S4: u16 = 20;
const WGDEVICE_A_I1: u16 = 21;
const WGDEVICE_A_I2: u16 = 22;
const WGDEVICE_A_I3: u16 = 23;
const WGDEVICE_A_I4: u16 = 24;
const WGDEVICE_A_I5: u16 = 25;
// AmneziaWG 3.0 attributes
const WGDEVICE_A_HEADER_PROTECTION_KEY: u16 = 26;
const WGDEVICE_A_CONTENT_PADDING_ADDITION: u16 = 27;
const WGDEVICE_A_REKEY_AFTER_TIME: u16 = 28;
const WGDEVICE_A_REKEY_TIMEOUT: u16 = 29;
const WGDEVICE_A_REJECT_AFTER_TIME: u16 = 30;
const WGDEVICE_A_KEEPALIVE_TIMEOUT: u16 = 31;
const WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS: u16 = 32;
// AmneziaWG 3.1 attributes
const WGDEVICE_A_RANDOM_TRAILERS: u16 = 33;
const WGDEVICE_A_DISABLE_COOKIES: u16 = 34;

/// A magic header has been a `u32` (genl family version 1), a string holding
/// `v` or `lo-hi` (version 2) and a `u64` range (version 3). The family
/// version says which. Without one the payload is read in the form this
/// crate emits: guessing from its bytes takes a range for a string of digits.
fn parse_magic_header(
    payload: &[u8],
    family_version: Option<u8>,
) -> Result<AmneziaWireguardRange<u32>, DecodeError> {
    match family_version {
        Some(1) => Ok(parse_u32(payload)
            .context("invalid u32 magic header value")?
            .into()),
        Some(2) => magic_header_spec(payload).ok_or_else(|| {
            DecodeError::from(format!(
                "invalid magic header string {:?}",
                String::from_utf8_lossy(payload)
            ))
        }),
        _ => Ok(AmneziaWireguardRange::<u32>::from_wire(
            parse_u64(payload).context("invalid u64 magic header value")?,
        )),
    }
}

/// Decimal digits holding `v` or `lo-hi`, then one NUL and nothing after it.
fn magic_header_spec(payload: &[u8]) -> Option<AmneziaWireguardRange<u32>> {
    let (0, spec) = payload.split_last()? else {
        return None;
    };
    if !spec.iter().all(|b| b.is_ascii_digit() || *b == b'-') {
        return None;
    }
    let spec = std::str::from_utf8(spec).ok()?;
    let end = |digits: &str| digits.parse().ok();
    match spec.split_once('-') {
        Some((lo, hi)) => Some(AmneziaWireguardRange {
            lo: end(lo)?,
            hi: end(hi)?,
        }),
        None => end(spec).map(AmneziaWireguardRange::from),
    }
}

fn parse_key<const N: usize>(payload: &[u8], name: &'static str) -> Result<[u8; N], DecodeError> {
    payload
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| DecodeError::from(e.to_string()))
        .context(format!("invalid {name} value"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmneziaWireguardAttribute {
    IfIndex(u32),
    IfName(String),
    PrivateKey([u8; WG_KEY_LEN]),
    PublicKey([u8; WG_KEY_LEN]),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<AmneziaWireguardPeer>),
    Flags(AmneziaWireguardDeviceFlags),
    // Amnezia attributes
    Peer(AmneziaWireguardPeer),
    Jc(u16),   // JunkCount
    Jmin(u16), // JunkPacketMinSize
    Jmax(u16), // JunkPacketMaxSize
    S1(u16),
    S2(u16),
    /// Magic header: the type a packet of its kind is sent with, drawn out
    /// of the range, and the only ones matched on receiving. Here the zero
    /// range is the value 0, not "unset". Emitted in the form of the
    /// AmneziaWG 3.0 kernel module (genl family version 3); the number and
    /// the string older modules send are read into the same range.
    H1(AmneziaWireguardRange<u32>),
    H2(AmneziaWireguardRange<u32>),
    H3(AmneziaWireguardRange<u32>),
    H4(AmneziaWireguardRange<u32>),
    S3(u16),
    S4(u16),
    /// Intermediate header descriptor string.
    I1(String),
    I2(String),
    I3(String),
    I4(String),
    I5(String),
    // AmneziaWG 3.0 attributes
    HeaderProtectionKey([u8; HEADER_PROTECTION_KEY_LEN]),
    /// Bytes of padding a data packet gets in place of its usual padding,
    /// as far as the packet has room for them.
    ContentPaddingAddition(AmneziaWireguardRange<u16>),
    /// Seconds after which the initiator of a session renews its key on
    /// sending. Also how long, three times it, a peer's keys are kept once
    /// its handshake was given up; with the zero range that wait is three
    /// times the module's constant of 180 seconds.
    RekeyAfterTime(AmneziaWireguardRange<u16>),
    /// Seconds after which an unanswered handshake is sent again.
    RekeyTimeout(AmneziaWireguardRange<u16>),
    /// Seconds that set two things: a peer's keys are wiped three times as
    /// long after a handshake, and the initiator renews a key on receiving
    /// once it is older than this less the low ends of the keepalive and
    /// rekey timeouts. A key stops being used after the module's constant of
    /// 180 seconds whatever is set here.
    RejectAfterTime(AmneziaWireguardRange<u16>),
    /// Seconds of receiving without sending after which a keepalive goes
    /// out. Its high end also times a new handshake when sent data goes
    /// unanswered: one starts after it plus a drawn rekey timeout.
    KeepaliveTimeout(AmneziaWireguardRange<u16>),
    /// Retries of a handshake: the module gives up once the count of retries
    /// is above this value, so after this value plus one retries.
    MaxHandshakeAttempts(AmneziaWireguardRange<u16>),
    // AmneziaWG 3.1 attributes (genl family version is still 3; only the
    // 3.1+ kernel module accepts them).
    RandomTrailers(bool),
    DisableCookies(bool),
    Other(DefaultNla),
}

impl AmneziaWireguardAttribute {
    pub const WG_KEY_LEN: usize = WG_KEY_LEN;

    /// The same attribute as the upstream crate represents it, for the
    /// attributes AmneziaWG shares with WireGuard. Peers are excluded: their
    /// keepalive has a different wire type.
    fn to_wireguard(&self) -> Option<WireguardAttribute> {
        Some(match self {
            Self::IfIndex(v) => WireguardAttribute::IfIndex(*v),
            Self::IfName(v) => WireguardAttribute::IfName(v.clone()),
            Self::PrivateKey(v) => WireguardAttribute::PrivateKey(*v),
            Self::PublicKey(v) => WireguardAttribute::PublicKey(*v),
            Self::ListenPort(v) => WireguardAttribute::ListenPort(*v),
            Self::Fwmark(v) => WireguardAttribute::Fwmark(*v),
            Self::Flags(v) => WireguardAttribute::Flags(*v),
            _ => return None,
        })
    }

    fn from_wireguard(attr: WireguardAttribute) -> Option<Self> {
        Some(match attr {
            WireguardAttribute::IfIndex(v) => Self::IfIndex(v),
            WireguardAttribute::IfName(v) => Self::IfName(v),
            WireguardAttribute::PrivateKey(v) => Self::PrivateKey(v),
            WireguardAttribute::PublicKey(v) => Self::PublicKey(v),
            WireguardAttribute::ListenPort(v) => Self::ListenPort(v),
            WireguardAttribute::Fwmark(v) => Self::Fwmark(v),
            WireguardAttribute::Flags(v) => Self::Flags(v),
            _ => return None,
        })
    }
}

impl Nla for AmneziaWireguardAttribute {
    fn value_len(&self) -> usize {
        if let Some(v) = self.to_wireguard() {
            return v.value_len();
        }
        match self {
            Self::I1(v) | Self::I2(v) | Self::I3(v) | Self::I4(v) | Self::I5(v) => v.len() + 1,
            Self::HeaderProtectionKey(_) => HEADER_PROTECTION_KEY_LEN,
            Self::Peers(v) => v.as_slice().buffer_len(),
            Self::Peer(v) => v.value_len(),
            Self::ContentPaddingAddition(_)
            | Self::RekeyAfterTime(_)
            | Self::RekeyTimeout(_)
            | Self::RejectAfterTime(_)
            | Self::KeepaliveTimeout(_)
            | Self::MaxHandshakeAttempts(_) => 4,
            Self::H1(_) | Self::H2(_) | Self::H3(_) | Self::H4(_) => 8,
            Self::RandomTrailers(_) | Self::DisableCookies(_) => 1,
            Self::Jc(_)
            | Self::Jmax(_)
            | Self::Jmin(_)
            | Self::S1(_)
            | Self::S2(_)
            | Self::S3(_)
            | Self::S4(_) => 2,
            Self::Other(v) => v.value_len(),
            Self::IfIndex(_)
            | Self::IfName(_)
            | Self::PrivateKey(_)
            | Self::PublicKey(_)
            | Self::ListenPort(_)
            | Self::Fwmark(_)
            | Self::Flags(_) => unreachable!("emitted by the upstream crate"),
        }
    }

    fn kind(&self) -> u16 {
        if let Some(v) = self.to_wireguard() {
            return v.kind();
        }
        match self {
            Self::Peers(_) => WGDEVICE_A_PEERS | NLA_F_NESTED,
            Self::Peer(_) => WGDEVICE_A_PEER | NLA_F_NESTED,
            Self::Jc(_) => WGDEVICE_A_JC,
            Self::Jmin(_) => WGDEVICE_A_JMIN,
            Self::Jmax(_) => WGDEVICE_A_JMAX,
            Self::S1(_) => WGDEVICE_A_S1,
            Self::S2(_) => WGDEVICE_A_S2,
            Self::H1(_) => WGDEVICE_A_H1,
            Self::H2(_) => WGDEVICE_A_H2,
            Self::H3(_) => WGDEVICE_A_H3,
            Self::H4(_) => WGDEVICE_A_H4,
            Self::S3(_) => WGDEVICE_A_S3,
            Self::S4(_) => WGDEVICE_A_S4,
            Self::I1(_) => WGDEVICE_A_I1,
            Self::I2(_) => WGDEVICE_A_I2,
            Self::I3(_) => WGDEVICE_A_I3,
            Self::I4(_) => WGDEVICE_A_I4,
            Self::I5(_) => WGDEVICE_A_I5,
            Self::HeaderProtectionKey(_) => WGDEVICE_A_HEADER_PROTECTION_KEY,
            Self::ContentPaddingAddition(_) => WGDEVICE_A_CONTENT_PADDING_ADDITION,
            Self::RekeyAfterTime(_) => WGDEVICE_A_REKEY_AFTER_TIME,
            Self::RekeyTimeout(_) => WGDEVICE_A_REKEY_TIMEOUT,
            Self::RejectAfterTime(_) => WGDEVICE_A_REJECT_AFTER_TIME,
            Self::KeepaliveTimeout(_) => WGDEVICE_A_KEEPALIVE_TIMEOUT,
            Self::MaxHandshakeAttempts(_) => WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS,
            Self::RandomTrailers(_) => WGDEVICE_A_RANDOM_TRAILERS,
            Self::DisableCookies(_) => WGDEVICE_A_DISABLE_COOKIES,
            Self::Other(attr) => attr.kind(),
            Self::IfIndex(_)
            | Self::IfName(_)
            | Self::PrivateKey(_)
            | Self::PublicKey(_)
            | Self::ListenPort(_)
            | Self::Fwmark(_)
            | Self::Flags(_) => unreachable!("emitted by the upstream crate"),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        if let Some(v) = self.to_wireguard() {
            return v.emit_value(buffer);
        }
        match self {
            Self::I1(s) | Self::I2(s) | Self::I3(s) | Self::I4(s) | Self::I5(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::HeaderProtectionKey(v) => buffer.copy_from_slice(v),
            Self::Peers(v) => v.as_slice().emit(buffer),
            Self::Peer(v) => v.emit_value(buffer),
            Self::H1(v) | Self::H2(v) | Self::H3(v) | Self::H4(v) => {
                emit_u64(buffer, v.to_wire()).unwrap()
            }
            Self::ContentPaddingAddition(v)
            | Self::RekeyAfterTime(v)
            | Self::RekeyTimeout(v)
            | Self::RejectAfterTime(v)
            | Self::KeepaliveTimeout(v)
            | Self::MaxHandshakeAttempts(v) => emit_u32(buffer, v.to_wire()).unwrap(),
            Self::Jc(v)
            | Self::Jmin(v)
            | Self::Jmax(v)
            | Self::S1(v)
            | Self::S2(v)
            | Self::S3(v)
            | Self::S4(v) => emit_u16(buffer, *v).unwrap(),
            Self::RandomTrailers(v) | Self::DisableCookies(v) => buffer[0] = u8::from(*v),
            Self::Other(attr) => attr.emit_value(buffer),
            Self::IfIndex(_)
            | Self::IfName(_)
            | Self::PrivateKey(_)
            | Self::PublicKey(_)
            | Self::ListenPort(_)
            | Self::Fwmark(_)
            | Self::Flags(_) => unreachable!("emitted by the upstream crate"),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AmneziaWireguardAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Self::parse_for_family_version(buf, None)
    }
}

impl AmneziaWireguardAttribute {
    /// Parses with the genl family version from the message header, which
    /// decides the magic header wire type.
    pub(crate) fn parse_for_family_version<T: AsRef<[u8]> + ?Sized>(
        buf: &NlaBuffer<&T>,
        family_version: Option<u8>,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let u16_attr =
            |name: &'static str| parse_u16(payload).context(format!("invalid {name} value"));
        let u16_range_attr = |name: &'static str| {
            parse_u32(payload)
                .context(format!("invalid {name} value"))
                .map(AmneziaWireguardRange::<u16>::from_wire)
        };
        let string_attr =
            |name: &'static str| parse_string(payload).context(format!("invalid {name} value"));
        let magic_header = |name: &'static str| {
            parse_magic_header(payload, family_version).context(format!("invalid {name} value"))
        };
        let flag_attr = |name: &'static str| {
            parse_u8(payload)
                .context(format!("invalid {name} value"))
                .map(|v| v != 0)
        };
        Ok(match buf.kind() {
            WGDEVICE_A_PEERS => Self::Peers(
                AmneziaWireguardPeers::parse(buf)
                    .context("invalid WGDEVICE_A_PEERS value")?
                    .0,
            ),
            WGDEVICE_A_PEER => Self::Peer(
                AmneziaWireguardPeer::parse(buf).context("invalid WGDEVICE_A_PEER value")?,
            ),
            WGDEVICE_A_JC => Self::Jc(u16_attr("WGDEVICE_A_JC")?),
            WGDEVICE_A_JMIN => Self::Jmin(u16_attr("WGDEVICE_A_JMIN")?),
            WGDEVICE_A_JMAX => Self::Jmax(u16_attr("WGDEVICE_A_JMAX")?),
            WGDEVICE_A_S1 => Self::S1(u16_attr("WGDEVICE_A_S1")?),
            WGDEVICE_A_S2 => Self::S2(u16_attr("WGDEVICE_A_S2")?),
            WGDEVICE_A_S3 => Self::S3(u16_attr("WGDEVICE_A_S3")?),
            WGDEVICE_A_S4 => Self::S4(u16_attr("WGDEVICE_A_S4")?),
            WGDEVICE_A_H1 => Self::H1(magic_header("WGDEVICE_A_H1")?),
            WGDEVICE_A_H2 => Self::H2(magic_header("WGDEVICE_A_H2")?),
            WGDEVICE_A_H3 => Self::H3(magic_header("WGDEVICE_A_H3")?),
            WGDEVICE_A_H4 => Self::H4(magic_header("WGDEVICE_A_H4")?),
            WGDEVICE_A_I1 => Self::I1(string_attr("WGDEVICE_A_I1")?),
            WGDEVICE_A_I2 => Self::I2(string_attr("WGDEVICE_A_I2")?),
            WGDEVICE_A_I3 => Self::I3(string_attr("WGDEVICE_A_I3")?),
            WGDEVICE_A_I4 => Self::I4(string_attr("WGDEVICE_A_I4")?),
            WGDEVICE_A_I5 => Self::I5(string_attr("WGDEVICE_A_I5")?),
            WGDEVICE_A_HEADER_PROTECTION_KEY => {
                Self::HeaderProtectionKey(parse_key(payload, "WGDEVICE_A_HEADER_PROTECTION_KEY")?)
            }
            WGDEVICE_A_CONTENT_PADDING_ADDITION => {
                Self::ContentPaddingAddition(u16_range_attr("WGDEVICE_A_CONTENT_PADDING_ADDITION")?)
            }
            WGDEVICE_A_REKEY_AFTER_TIME => {
                Self::RekeyAfterTime(u16_range_attr("WGDEVICE_A_REKEY_AFTER_TIME")?)
            }
            WGDEVICE_A_REKEY_TIMEOUT => {
                Self::RekeyTimeout(u16_range_attr("WGDEVICE_A_REKEY_TIMEOUT")?)
            }
            WGDEVICE_A_REJECT_AFTER_TIME => {
                Self::RejectAfterTime(u16_range_attr("WGDEVICE_A_REJECT_AFTER_TIME")?)
            }
            WGDEVICE_A_KEEPALIVE_TIMEOUT => {
                Self::KeepaliveTimeout(u16_range_attr("WGDEVICE_A_KEEPALIVE_TIMEOUT")?)
            }
            WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS => {
                Self::MaxHandshakeAttempts(u16_range_attr("WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS")?)
            }
            WGDEVICE_A_RANDOM_TRAILERS => {
                Self::RandomTrailers(flag_attr("WGDEVICE_A_RANDOM_TRAILERS")?)
            }
            WGDEVICE_A_DISABLE_COOKIES => {
                Self::DisableCookies(flag_attr("WGDEVICE_A_DISABLE_COOKIES")?)
            }
            _ => match Self::from_wireguard(WireguardAttribute::parse(buf)?) {
                Some(v) => v,
                None => Self::Other(DefaultNla::parse(buf)?),
            },
        })
    }
}
