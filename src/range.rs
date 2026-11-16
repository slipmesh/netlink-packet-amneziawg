// SPDX-License-Identifier: MIT

//! The ranges the AmneziaWG 3.0 kernel module takes, each as two ends in one
//! integer with the low end in the low half: `u32` ends in a `u64` for the
//! magic headers (`WGDEVICE_A_H1`..`WGDEVICE_A_H4`), `u16` ends in a `u32`
//! for the peer's `WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL` and the device's
//! timing and padding attributes.
//!
//! The zero range selects the module's own constant for a timing attribute,
//! adds no padding, and disables the keepalive.

use std::fmt;
use std::str::FromStr;

/// `lo..=hi`. One value `v` is the range from `v` to `v`, which [`From`]
/// builds.
///
/// The module does not check that `lo <= hi` and neither does this type, so
/// that a range read back from the module is the one it holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range<T> {
    pub lo: T,
    pub hi: T,
}

impl<T: Copy> From<T> for Range<T> {
    fn from(value: T) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }
}

impl Range<u16> {
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

impl Range<u32> {
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

/// The way `awg`(8) and the v1.0 kernel module write it: `"<lo>"` when the
/// ends are equal, `"<lo>-<hi>"` otherwise.
impl<T: fmt::Display + PartialEq> fmt::Display for Range<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseRangeError;

impl fmt::Display for ParseRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("neither a number nor a range written lo-hi with lo not above hi")
    }
}

impl std::error::Error for ParseRangeError {}

/// Reads `"<v>"` or `"<lo>-<hi>"`, and refuses `lo > hi`.
impl<T: FromStr + PartialOrd + Copy> FromStr for Range<T> {
    type Err = ParseRangeError;

    fn from_str(spec: &str) -> Result<Self, ParseRangeError> {
        let end = |text: &str| text.trim().parse::<T>().map_err(|_| ParseRangeError);
        match spec.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (end(lo)?, end(hi)?);
                if lo > hi {
                    return Err(ParseRangeError);
                }
                Ok(Self { lo, hi })
            }
            None => end(spec).map(Self::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_value_is_the_range_from_it_to_itself() {
        assert_eq!(Range::from(25u16), Range { lo: 25, hi: 25 });
    }

    #[test]
    fn test_u16_ends_go_into_a_u32_low_end_in_the_low_half() {
        assert_eq!(Range::<u16> { lo: 1, hi: 2 }.to_wire(), 0x0002_0001);
        assert_eq!(Range::<u16>::from_wire(0x0002_0001), Range { lo: 1, hi: 2 });
        assert_eq!(Range::from(25u16).to_wire(), 0x0019_0019);
        assert_eq!(Range::<u16>::from_wire(25), Range { lo: 25, hi: 0 });
        for range in [(0, 0), (100, 140), (0, u16::MAX), (u16::MAX, u16::MAX)] {
            let range = Range {
                lo: range.0,
                hi: range.1,
            };
            assert_eq!(Range::<u16>::from_wire(range.to_wire()), range);
        }
    }

    #[test]
    fn test_u32_ends_go_into_a_u64_low_end_in_the_low_half() {
        assert_eq!(
            Range::<u32> { lo: 1, hi: 2 }.to_wire(),
            0x0000_0002_0000_0001
        );
        assert_eq!(
            Range::<u32>::from_wire(0x0000_0002_0000_0001),
            Range { lo: 1, hi: 2 }
        );
        let range = Range::<u32> {
            lo: 61220074,
            hi: 118999195,
        };
        assert_eq!(Range::<u32>::from_wire(range.to_wire()), range);
        assert_eq!(
            Range::<u32>::from_wire(u64::MAX),
            Range {
                lo: u32::MAX,
                hi: u32::MAX
            }
        );
    }

    #[test]
    fn test_shown_as_a_number_when_the_ends_are_equal() {
        assert_eq!(Range::from(25u32).to_string(), "25");
        assert_eq!(
            Range::<u32> {
                lo: 61220074,
                hi: 118999195
            }
            .to_string(),
            "61220074-118999195"
        );
        assert_eq!(Range::<u16> { lo: 25, hi: 0 }.to_string(), "25-0");
    }

    #[test]
    fn test_parsed_from_a_number_or_two_around_a_dash() {
        assert_eq!("25".parse(), Ok(Range::from(25u32)));
        assert_eq!(
            "61220074-118999195".parse(),
            Ok(Range::<u32> {
                lo: 61220074,
                hi: 118999195
            })
        );
        assert_eq!("100-140".parse(), Ok(Range::<u16> { lo: 100, hi: 140 }));
        assert_eq!("7-7".parse(), Ok(Range::from(7u16)));
    }

    #[test]
    fn test_text_that_is_no_range_is_refused() {
        for text in ["", "bad", "10-5", "5-", "-5", "1-2-3", "65536", "1-65536"] {
            assert_eq!(text.parse::<Range<u16>>(), Err(ParseRangeError), "{text:?}");
        }
    }
}
