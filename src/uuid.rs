//! Loxone UUID helpers (wire `[u8; 16]` + Loxone string format).

use crate::error::{Error, Result};
use std::fmt;
use std::hash::{Hash, Hasher};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Length of the Loxone string form (`8-4-4-16`), in ASCII bytes.
pub const LOXONE_UUID_STR_LEN: usize = 35;

/// `[hi_nibble, lo_nibble]` pairs for every byte value, lowercase.
static HEX: [u8; 512] = build_hex_lut();

const fn build_hex_lut() -> [u8; 512] {
    let digits = *b"0123456789abcdef";
    let mut lut = [0u8; 512];
    let mut byte = 0usize;
    while byte < 256 {
        lut[byte * 2] = digits[byte >> 4];
        lut[byte * 2 + 1] = digits[byte & 0x0f];
        byte += 1;
    }
    lut
}

#[inline(always)]
fn put_hex(out: &mut [u8; LOXONE_UUID_STR_LEN], at: usize, byte: u8) {
    let i = (byte as usize) * 2;
    out[at] = HEX[i];
    out[at + 1] = HEX[i + 1];
}

/// The LUT only ever emits ASCII, so this conversion cannot fail.
#[inline]
fn as_ascii(buf: &[u8; LOXONE_UUID_STR_LEN]) -> &str {
    std::str::from_utf8(buf).unwrap_or("")
}

/// 16-byte Loxone UUID as transmitted on the wire (little-endian `PUUID` layout).
///
/// # Using UUIDs as map keys
///
/// [`Hash`] and [`Eq`] operate on the 16 raw wire bytes, never on the string
/// form. Consumers should therefore key their state maps by `LoxoneUuid`
/// directly and **never** format in the hot path:
///
/// ```
/// use loxwebsocket::LoxoneUuid;
/// use std::collections::HashMap;
///
/// let mut states: HashMap<LoxoneUuid, f64> = HashMap::new();
/// states.insert(LoxoneUuid::from_bytes([0u8; 16]), 21.5);
/// ```
///
/// The hash is computed from two `u64` reads. For lookup-dominated workloads a
/// non-cryptographic hasher such as [`rustc-hash`] or [`ahash`] removes the
/// remaining SipHash overhead:
///
/// ```ignore
/// type StateMap = rustc_hash::FxHashMap<LoxoneUuid, f64>;
/// ```
///
/// Formatting (via [`Display`](fmt::Display), [`format_loxone`](Self::format_loxone)
/// or [`format_loxone_into`](Self::format_loxone_into)) is only needed at the
/// boundary where a UUID is shown to a human or matched against `LoxAPP3.json`.
///
/// # Zero-copy
///
/// Transparent over `[u8; 16]`, so it has size 16 and alignment 1 and the
/// zerocopy traits below let a wire payload be reinterpreted as UUIDs in place.
/// The event-table walkers rely on that to hand out `&LoxoneUuid` borrowed
/// straight from the frame buffer.
///
/// [`rustc-hash`]: https://crates.io/crates/rustc-hash
/// [`ahash`]: https://crates.io/crates/ahash
#[derive(
    Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(transparent)]
pub struct LoxoneUuid(pub [u8; 16]);

impl LoxoneUuid {
    /// Create from a 16-byte wire buffer.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw wire bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Render the Loxone string form into a stack buffer, without allocating.
    ///
    /// Layout is `8-4-4-16`: dashes sit at index 8, 13 and 18, and unlike RFC
    /// 4122 there is no dash between clock_seq and node.
    #[inline]
    pub fn format_loxone_bytes(&self) -> [u8; LOXONE_UUID_STR_LEN] {
        let b = &self.0;
        let mut out = [b'-'; LOXONE_UUID_STR_LEN];
        put_hex(&mut out, 0, b[3]);
        put_hex(&mut out, 2, b[2]);
        put_hex(&mut out, 4, b[1]);
        put_hex(&mut out, 6, b[0]);
        put_hex(&mut out, 9, b[5]);
        put_hex(&mut out, 11, b[4]);
        put_hex(&mut out, 14, b[7]);
        put_hex(&mut out, 16, b[6]);
        let mut src = 8;
        let mut dst = 19;
        while src < 16 {
            put_hex(&mut out, dst, b[src]);
            src += 1;
            dst += 2;
        }
        out
    }

    /// Format as Loxone UUID string: `8-4-4-16` (no dash between clock_seq and node).
    ///
    /// Matches the Cython extractor: LE fields for data1/2/3, BE for data4.
    #[inline]
    pub fn format_loxone(&self) -> String {
        let mut s = String::with_capacity(LOXONE_UUID_STR_LEN);
        self.format_loxone_into(&mut s);
        s
    }

    /// Loxone string form as an inline, allocation-free map key.
    ///
    /// See [`LoxoneUuidStr`] for why this exists.
    #[inline]
    pub fn format_loxone_key(&self) -> LoxoneUuidStr {
        LoxoneUuidStr(self.format_loxone_bytes())
    }

    /// Append the Loxone string form to `buf`, reusing its allocation.
    ///
    /// ```
    /// use loxwebsocket::LoxoneUuid;
    ///
    /// let mut buf = String::with_capacity(64);
    /// for uuid in [LoxoneUuid::default(), LoxoneUuid::from_bytes([1u8; 16])] {
    ///     buf.clear();
    ///     uuid.format_loxone_into(&mut buf);
    ///     assert_eq!(buf.len(), 35);
    /// }
    /// ```
    #[inline]
    pub fn format_loxone_into(&self, buf: &mut String) {
        buf.push_str(as_ascii(&self.format_loxone_bytes()));
    }

    /// Parse a Loxone UUID string (`8-4-4-16` or standard `8-4-4-4-12`).
    pub fn parse(s: &str) -> Result<Self> {
        let mut raw = [0u8; 16];
        let mut nibbles = 0usize;
        for c in s.bytes() {
            if c == b'-' {
                continue;
            }
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => {
                    return Err(Error::InvalidUuid(format!(
                        "invalid hex digit {:?}",
                        c as char
                    )));
                }
            };
            if nibbles >= 32 {
                return Err(Error::InvalidUuid(
                    "expected 32 hex digits, got more".into(),
                ));
            }
            let i = nibbles / 2;
            raw[i] = if nibbles % 2 == 0 { v << 4 } else { raw[i] | v };
            nibbles += 1;
        }
        if nibbles != 32 {
            return Err(Error::InvalidUuid(format!(
                "expected 32 hex digits, got {nibbles}"
            )));
        }
        // Wire layout stores data1/2/3 little-endian.
        Ok(Self([
            raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9],
            raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]))
    }

    /// Read a UUID from a byte slice at `offset` without copying the whole buffer.
    #[inline]
    pub fn read_at(buf: &[u8], offset: usize) -> Option<Self> {
        let end = offset.checked_add(16)?;
        let slice = buf.get(offset..end)?;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    #[inline]
    fn as_u64_pair(&self) -> (u64, u64) {
        let b = &self.0;
        (
            u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        )
    }
}

impl Hash for LoxoneUuid {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        let (lo, hi) = self.as_u64_pair();
        state.write_u64(lo);
        state.write_u64(hi);
    }
}

/// The Loxone string form of a UUID, stored inline.
///
/// A [`String`] key costs a heap allocation per record, which on a full event
/// table dominates everything else the walker does. This type keeps the same 35
/// ASCII bytes inside the map bucket instead, so materialising a
/// string-keyed table allocates only for the table itself.
///
/// To look one up from a string, turn the string into a key first. Going
/// through [`LoxoneUuid::parse`] also normalises the RFC 4122 form, which a
/// direct `&str` comparison against the Loxone form would miss:
///
/// ```
/// use loxwebsocket::{LoxoneUuid, LoxoneUuidStr};
/// use std::collections::HashMap;
///
/// let uuid = LoxoneUuid::from_bytes([0u8; 16]);
/// let mut map: HashMap<LoxoneUuidStr, f64> = HashMap::new();
/// map.insert(uuid.format_loxone_key(), 21.5);
///
/// let from_structure_file = "00000000-0000-0000-0000000000000000";
/// let key = LoxoneUuid::parse(from_structure_file)?.format_loxone_key();
/// assert_eq!(map.get(&key), Some(&21.5));
/// assert_eq!(key.as_str(), uuid.format_loxone());
/// # Ok::<(), loxwebsocket::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct LoxoneUuidStr([u8; LOXONE_UUID_STR_LEN]);

impl LoxoneUuidStr {
    /// Borrow the 35 ASCII bytes as a string.
    ///
    /// Not used by [`Hash`]: the derive hashes the raw bytes, which is the same
    /// mapping without paying for a UTF-8 validation on every map operation.
    #[inline]
    pub fn as_str(&self) -> &str {
        as_ascii(&self.0)
    }

    /// Borrow the raw ASCII bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; LOXONE_UUID_STR_LEN] {
        &self.0
    }
}

impl AsRef<str> for LoxoneUuidStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for LoxoneUuidStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for LoxoneUuidStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LoxoneUuidStr({})", self.as_str())
    }
}

impl fmt::Display for LoxoneUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(as_ascii(&self.format_loxone_bytes()))
    }
}

impl fmt::Debug for LoxoneUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoxoneUuid(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl AsRef<[u8; 16]> for LoxoneUuid {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn reference_format(b: &[u8; 16]) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3],
            b[2],
            b[1],
            b[0],
            b[5],
            b[4],
            b[7],
            b[6],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }

    /// xorshift64*, so the property tests stay deterministic without a dev-dependency.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn uuid(&mut self) -> LoxoneUuid {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&self.next_u64().to_le_bytes());
            b[8..].copy_from_slice(&self.next_u64().to_le_bytes());
            LoxoneUuid(b)
        }
    }

    #[test]
    fn roundtrip_loxone_format() {
        // Wire bytes as produced by MS (LE data1/2/3).
        let wire = [
            0x9a, 0x5f, 0xfc, 0xed, 0x3f, 0xdf, 0xad, 0x4c, 0x9d, 0xdd, 0xcd, 0xc4, 0x2c, 0x73,
            0x2b, 0xe2,
        ];
        let uuid = LoxoneUuid::from_bytes(wire);
        let s = uuid.format_loxone();
        assert_eq!(s, "edfc5f9a-df3f-4cad-9dddcdc42c732be2");
        let parsed = LoxoneUuid::parse(&s).unwrap();
        assert_eq!(parsed, uuid);
    }

    #[test]
    fn hex_lut_matches_format_macro() {
        for byte in 0u8..=255 {
            let i = byte as usize * 2;
            assert_eq!(
                std::str::from_utf8(&HEX[i..i + 2]).unwrap(),
                format!("{byte:02x}")
            );
        }
    }

    #[test]
    fn lut_formatter_matches_format_macro() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let mut buf = String::new();
        for _ in 0..10_000 {
            let uuid = rng.uuid();
            let expected = reference_format(&uuid.0);
            assert_eq!(uuid.format_loxone(), expected);
            assert_eq!(uuid.to_string(), expected);
            assert_eq!(format!("{uuid:?}"), format!("LoxoneUuid({expected})"));

            buf.clear();
            uuid.format_loxone_into(&mut buf);
            assert_eq!(buf, expected);
        }
    }

    #[test]
    fn format_covers_edge_byte_values() {
        for bytes in [[0x00u8; 16], [0xffu8; 16], [0x0fu8; 16], [0xf0u8; 16]] {
            let uuid = LoxoneUuid(bytes);
            assert_eq!(uuid.format_loxone(), reference_format(&bytes));
        }
    }

    #[test]
    fn format_bytes_has_dashes_at_loxone_positions() {
        let out = LoxoneUuid([0u8; 16]).format_loxone_bytes();
        assert_eq!(out.len(), LOXONE_UUID_STR_LEN);
        assert_eq!(out.iter().filter(|c| **c == b'-').count(), 3);
        assert_eq!(out[8], b'-');
        assert_eq!(out[13], b'-');
        assert_eq!(out[18], b'-');
    }

    #[test]
    fn format_into_appends_without_clearing() {
        let mut buf = String::from("uuid=");
        LoxoneUuid([0u8; 16]).format_loxone_into(&mut buf);
        assert_eq!(buf, "uuid=00000000-0000-0000-0000000000000000");
    }

    #[test]
    fn parse_roundtrips_random_uuids() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..1_000 {
            let uuid = rng.uuid();
            assert_eq!(LoxoneUuid::parse(&uuid.format_loxone()).unwrap(), uuid);
        }
    }

    #[test]
    fn parse_accepts_rfc4122_dashes_and_uppercase() {
        let a = LoxoneUuid::parse("edfc5f9a-df3f-4cad-9ddd-cdc42c732be2").unwrap();
        let b = LoxoneUuid::parse("EDFC5F9A-DF3F-4CAD-9DDDCDC42C732BE2").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.format_loxone(), "edfc5f9a-df3f-4cad-9dddcdc42c732be2");
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(LoxoneUuid::parse("").is_err());
        assert!(LoxoneUuid::parse("1234").is_err());
        assert!(LoxoneUuid::parse("edfc5f9a-df3f-4cad-9dddcdc42c732be").is_err());
        assert!(LoxoneUuid::parse("edfc5f9a-df3f-4cad-9dddcdc42c732be22").is_err());
        assert!(LoxoneUuid::parse("gdfc5f9a-df3f-4cad-9dddcdc42c732be2").is_err());
    }

    fn hash_of(uuid: &LoxoneUuid) -> u64 {
        let mut h = DefaultHasher::new();
        uuid.hash(&mut h);
        h.finish()
    }

    #[test]
    fn hash_agrees_with_eq() {
        let mut rng = Rng(0x0bad_c0de_0bad_c0de);
        for _ in 0..1_000 {
            let uuid = rng.uuid();
            assert_eq!(hash_of(&uuid), hash_of(&LoxoneUuid(uuid.0)));

            let mut other = uuid.0;
            other[15] ^= 1;
            let other = LoxoneUuid(other);
            assert_ne!(uuid, other);
            assert_ne!(hash_of(&uuid), hash_of(&other));
        }
    }
}
