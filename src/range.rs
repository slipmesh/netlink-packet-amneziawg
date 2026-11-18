// SPDX-License-Identifier: MIT

/// A range of values the AmneziaWG 3.0 kernel module holds for an attribute,
/// both ends included. Most uses draw a value out of it, not every use: some
/// read one end, such as the low end of the rekey timeout and both ends of
/// the keepalive timeout. One value `v` is the range from `v` to `v`, which
/// [`From`] builds.
///
/// On the wire the two ends share one integer, the low end in the low half:
/// `u32` ends in a `u64` for the magic headers, `u16` ends in a `u32` for the
/// other range attributes.
///
/// The module does not check that `lo <= hi` and neither does this type, so
/// that a range read back from the module is the one it holds. A magic
/// header range with `lo > hi` contains no value, and no packet of its type
/// matches it.
///
/// For a `u16` attribute the zero range, which [`Default`] gives, is the
/// module's "not set": its own constant for a timing attribute and for the
/// attempt count, the padding a data packet gets without
/// `ContentPaddingAddition`, no persistent keepalive. Only the range from 0
/// to 0 is that: out of one from 0 to `n` the module can draw 0. For a magic
/// header it is the value 0.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardRange<T> {
    pub lo: T,
    pub hi: T,
}

impl<T: Copy> From<T> for AmneziaWireguardRange<T> {
    fn from(value: T) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }
}

impl AmneziaWireguardRange<u16> {
    pub(crate) fn to_wire(self) -> u32 {
        ((self.hi as u32) << 16) | (self.lo as u32)
    }

    pub(crate) fn from_wire(wire: u32) -> Self {
        Self {
            lo: wire as u16,
            hi: (wire >> 16) as u16,
        }
    }
}

impl AmneziaWireguardRange<u32> {
    pub(crate) fn to_wire(self) -> u64 {
        ((self.hi as u64) << 32) | (self.lo as u64)
    }

    pub(crate) fn from_wire(wire: u64) -> Self {
        Self {
            lo: wire as u32,
            hi: (wire >> 32) as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AmneziaWireguardRange as R;

    #[test]
    fn test_u16_ends_go_into_a_u32_low_end_in_the_low_half() {
        assert_eq!(R::<u16> { lo: 1, hi: 2 }.to_wire(), 0x0002_0001);
        assert_eq!(R::<u16>::from_wire(0x0002_0001), R { lo: 1, hi: 2 });
        assert_eq!(R::from(25u16).to_wire(), 0x0019_0019);
        assert_eq!(R::<u16>::from_wire(25), R { lo: 25, hi: 0 });
        for (lo, hi) in [(0, 0), (100, 140), (0, u16::MAX), (u16::MAX, u16::MAX)] {
            let range = R { lo, hi };
            assert_eq!(R::<u16>::from_wire(range.to_wire()), range);
        }
    }

    #[test]
    fn test_u32_ends_go_into_a_u64_low_end_in_the_low_half() {
        assert_eq!(R::<u32> { lo: 1, hi: 2 }.to_wire(), 0x0000_0002_0000_0001);
        assert_eq!(
            R::<u32>::from_wire(0x0000_0002_0000_0001),
            R { lo: 1, hi: 2 }
        );
        let range = R::<u32> {
            lo: 61220074,
            hi: 118999195,
        };
        assert_eq!(R::<u32>::from_wire(range.to_wire()), range);
        let widest = R {
            lo: u32::MAX,
            hi: u32::MAX,
        };
        assert_eq!(R::<u32>::from_wire(u64::MAX), widest);
    }
}
