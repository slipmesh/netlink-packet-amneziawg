// SPDX-License-Identifier: MIT

//! Helpers for the AmneziaWG 3.0 range wire formats.
//!
//! Since kernel module v3.0 the magic header attributes
//! (`WGDEVICE_A_H1`..`WGDEVICE_A_H4`) are transferred as a `u64` packing a
//! range of `u32` values: the low 32 bits hold the range start, the high 32
//! bits hold the range end. Older modules (genl family version 2) transfer
//! the same information as a NUL-terminated decimal string, either `"<v>"`
//! or `"<lo>-<hi>"`. The `u32_range_*` helpers convert between the two
//! representations.
//!
//! The same module transfers the device timing and padding attributes
//! (`WGDEVICE_A_CONTENT_PADDING_ADDITION`, `WGDEVICE_A_REKEY_AFTER_TIME`,
//! `WGDEVICE_A_REKEY_TIMEOUT`, `WGDEVICE_A_REJECT_AFTER_TIME`,
//! `WGDEVICE_A_KEEPALIVE_TIMEOUT`, `WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS`) and
//! the peer's `WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL` as a `u32` packing a
//! range of `u16` values the same way, and draws a value between the two ends
//! at every use. A single value `v` is the range `v..v`: a bare `v` on the
//! wire is the range `v..0`, from which the module draws an arbitrary value.
//! An all-zero range selects the module's own constant.

/// Packs a `[lo, hi]` `u32` range into the `u64` wire value used by the
/// AmneziaWG 3.0 kernel module.
pub fn u32_range_pack(lo: u32, hi: u32) -> u64 {
    ((hi as u64) << 32) | (lo as u64)
}

/// Unpacks the `u64` wire value into `(lo, hi)`.
pub fn u32_range_unpack(range: u64) -> (u32, u32) {
    (range as u32, (range >> 32) as u32)
}

/// Packs a `[lo, hi]` `u16` range into the `u32` wire value used by the
/// AmneziaWG 3.0 kernel module.
pub fn u16_range_pack(lo: u16, hi: u16) -> u32 {
    ((hi as u32) << 16) | (lo as u32)
}

/// Unpacks the `u32` wire value into `(lo, hi)`.
pub fn u16_range_unpack(range: u32) -> (u16, u16) {
    (range as u16, (range >> 16) as u16)
}

/// Formats a packed range the way `awg`(8) and the v1.0 kernel module do:
/// `"<lo>"` when `lo == hi`, `"<lo>-<hi>"` otherwise.
pub fn u32_range_to_string(range: u64) -> String {
    let (lo, hi) = u32_range_unpack(range);
    if lo == hi {
        lo.to_string()
    } else {
        format!("{lo}-{hi}")
    }
}

/// Parses a magic header spec string (`"<v>"` or `"<lo>-<hi>"`) into the
/// packed `u64` wire value. Returns `None` for malformed input or when
/// `lo > hi`.
pub fn u32_range_from_string(spec: &str) -> Option<u64> {
    let mut parts = spec.splitn(2, '-');
    let lo: u32 = parts.next()?.trim().parse().ok()?;
    let hi: u32 = match parts.next() {
        Some(s) => s.trim().parse().ok()?,
        None => lo,
    };
    if lo > hi {
        return None;
    }
    Some(u32_range_pack(lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_puts_lo_in_the_low_half() {
        assert_eq!(u32_range_pack(1, 2), 0x0000_0002_0000_0001);
        assert_eq!(u32_range_unpack(0x0000_0002_0000_0001), (1, 2));
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let v = u32_range_pack(61220074, 118999195);
        assert_eq!(u32_range_unpack(v), (61220074, 118999195));
        assert_eq!(u32_range_unpack(u32_range_pack(5, 5)), (5, 5));
    }

    #[test]
    fn test_u16_pack_puts_lo_in_the_low_half() {
        assert_eq!(u16_range_pack(1, 2), 0x0002_0001);
        assert_eq!(u16_range_unpack(0x0002_0001), (1, 2));
    }

    #[test]
    fn test_u16_pack_of_one_value_is_not_the_bare_value() {
        assert_eq!(u16_range_pack(25, 25), 0x0019_0019);
        assert_eq!(u16_range_unpack(25), (25, 0));
    }

    #[test]
    fn test_u16_pack_unpack_roundtrip() {
        for (lo, hi) in [(0, 0), (100, 140), (0, u16::MAX), (u16::MAX, u16::MAX)] {
            assert_eq!(u16_range_unpack(u16_range_pack(lo, hi)), (lo, hi));
        }
    }

    #[test]
    fn test_to_string_formats() {
        assert_eq!(u32_range_to_string(u32_range_pack(25, 25)), "25");
        assert_eq!(
            u32_range_to_string(u32_range_pack(61220074, 118999195)),
            "61220074-118999195"
        );
    }

    #[test]
    fn test_from_string_parses() {
        assert_eq!(u32_range_from_string("25"), Some(u32_range_pack(25, 25)));
        assert_eq!(
            u32_range_from_string("61220074-118999195"),
            Some(u32_range_pack(61220074, 118999195))
        );
        assert_eq!(u32_range_from_string("bad"), None);
        assert_eq!(u32_range_from_string("10-5"), None);
        assert_eq!(u32_range_from_string(""), None);
    }
}
