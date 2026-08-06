//! Owned snapshots of an event table, for consumers that cannot hold borrows.
//!
//! The [`LoxHandler`](crate::LoxHandler) callbacks hand out slices borrowed from
//! the frame buffer, which is the fastest thing the client can do but forces the
//! consumer to copy out whatever it wants to keep. Consumers that would rather
//! receive a finished map — the shape the Python/Cython reference returns from
//! `parse_message` — should use the helpers here instead of rolling their own,
//! because the obvious implementation is dominated by costs that are avoidable:
//!
//! - a `String` key allocates once per record; [`LoxoneUuidStr`] does not
//! - SipHash re-mixes a UUID that is already uniformly distributed
//!
//! Both are handled by [`UuidMap`] / [`UuidStrMap`] and their `collect_*`
//! constructors.

use crate::proto::{walk_texts, walk_values};
use crate::uuid::{LoxoneUuid, LoxoneUuidStr};
use bytes::Bytes;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Multiply-rotate hasher (FxHash construction) for keys that are already
/// well distributed.
///
/// Loxone UUIDs are random, so the collision resistance SipHash pays for is
/// wasted here; what matters on an event table is the per-key constant. Not
/// suitable for hashing untrusted input where collision attacks matter.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoxHasher {
    hash: u64,
}

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl LoxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for LoxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            // `chunks_exact(8)` guarantees the length, so the conversion holds.
            self.add(u64::from_ne_bytes(chunk.try_into().unwrap_or_default()));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_ne_bytes(buf));
        }
    }

    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.add(u64::from(n));
    }

    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.add(n);
    }

    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.add(n as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// [`BuildHasher`](std::hash::BuildHasher) for [`LoxHasher`].
pub type LoxBuildHasher = BuildHasherDefault<LoxHasher>;

/// Map keyed by the raw 16-byte UUID. Prefer this over [`UuidStrMap`].
pub type UuidMap<V> = HashMap<LoxoneUuid, V, LoxBuildHasher>;

/// Map keyed by the Loxone UUID string, stored inline.
///
/// Only worth it when the consumer has to match against something that already
/// speaks the string form, such as `LoxAPP3.json`.
pub type UuidStrMap<V> = HashMap<LoxoneUuidStr, V, LoxBuildHasher>;

fn map_with_capacity<K, V>(cap: usize) -> HashMap<K, V, LoxBuildHasher> {
    HashMap::with_capacity_and_hasher(cap, LoxBuildHasher::default())
}

/// Collect a type-2 value table into an owned map.
///
/// Later records win, matching the Cython `parse_message` dict semantics.
pub fn collect_values(payload: &[u8]) -> UuidMap<f64> {
    let mut map = map_with_capacity(payload.len() / crate::proto::VALUE_RECORD_SIZE);
    walk_values(payload, |uuid, value| {
        map.insert(*uuid, value);
    });
    map
}

/// Copy a text out of the frame buffer.
///
/// Roughly half the text records in a real event table carry an empty string,
/// and [`Bytes::copy_from_slice`] would still take the allocator for those.
#[inline]
fn own_text(text: &[u8]) -> Bytes {
    if text.is_empty() {
        Bytes::new()
    } else {
        Bytes::copy_from_slice(text)
    }
}

/// Record count guess for a text table, which has no fixed stride.
///
/// A record is at least [`TEXT_HEADER_SIZE`] bytes and empty texts are common,
/// so dividing by the header size stays close for the tables that matter and
/// only ever over-reserves — far cheaper than rehashing a growing table.
///
/// [`TEXT_HEADER_SIZE`]: crate::proto::TEXT_HEADER_SIZE
#[inline]
fn text_capacity(payload: &[u8]) -> usize {
    payload.len() / crate::proto::TEXT_HEADER_SIZE
}

/// Collect a type-3 text table into an owned map.
pub fn collect_texts(payload: &[u8]) -> UuidMap<Bytes> {
    let mut map = map_with_capacity(text_capacity(payload));
    walk_texts(payload, |uuid, _icon, text| {
        map.insert(*uuid, own_text(text));
    });
    map
}

/// Like [`collect_values`], keyed by the Loxone UUID string.
pub fn collect_values_by_name(payload: &[u8]) -> UuidStrMap<f64> {
    let mut map = map_with_capacity(payload.len() / crate::proto::VALUE_RECORD_SIZE);
    walk_values(payload, |uuid, value| {
        map.insert(uuid.format_loxone_key(), value);
    });
    map
}

/// Like [`collect_texts`], keyed by the Loxone UUID string.
pub fn collect_texts_by_name(payload: &[u8]) -> UuidStrMap<Bytes> {
    let mut map = map_with_capacity(text_capacity(payload));
    walk_texts(payload, |uuid, _icon, text| {
        map.insert(uuid.format_loxone_key(), own_text(text));
    });
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_record(tag: u8, value: f64) -> Vec<u8> {
        let mut buf = vec![tag; 16];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }

    fn text_record(tag: u8, text: &[u8]) -> Vec<u8> {
        let mut buf = vec![tag; 16];
        buf.extend_from_slice(&[tag; 16]);
        buf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        buf.extend_from_slice(text);
        buf.extend(std::iter::repeat_n(0u8, (4 - (text.len() % 4)) % 4));
        buf
    }

    #[test]
    fn collects_every_value_record() {
        let mut payload = value_record(1, 1.5);
        payload.extend_from_slice(&value_record(2, -3.25));

        let map = collect_values(&payload);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&LoxoneUuid::from_bytes([1u8; 16])], 1.5);
        assert_eq!(map[&LoxoneUuid::from_bytes([2u8; 16])], -3.25);
    }

    /// The Cython dict keeps the last write for a repeated UUID.
    #[test]
    fn later_records_overwrite_earlier_ones() {
        let mut payload = value_record(7, 1.0);
        payload.extend_from_slice(&value_record(7, 2.0));

        let map = collect_values(&payload);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&LoxoneUuid::from_bytes([7u8; 16])], 2.0);
    }

    #[test]
    fn collects_texts_including_empty_ones() {
        let mut payload = text_record(3, b"hello");
        payload.extend_from_slice(&text_record(4, b""));

        let map = collect_texts(&payload);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map[&LoxoneUuid::from_bytes([3u8; 16])],
            Bytes::from("hello")
        );
        assert!(map[&LoxoneUuid::from_bytes([4u8; 16])].is_empty());
    }

    /// A key built from a parsed UUID string must find the collected entry,
    /// which is how a consumer looks up a name taken from `LoxAPP3.json`.
    #[test]
    fn string_keys_are_reachable_from_a_parsed_name() {
        let payload = value_record(9, 42.0);
        let map = collect_values_by_name(&payload);

        let name = LoxoneUuid::from_bytes([9u8; 16]).format_loxone();
        let key = LoxoneUuid::parse(&name)
            .expect("own output parses")
            .format_loxone_key();
        assert_eq!(map.get(&key), Some(&42.0));
        assert_eq!(key.as_str(), name);
    }

    /// The inline key must stay a valid string despite `Hash` bypassing
    /// `as_str`, otherwise `Display` would silently render nothing.
    #[test]
    fn inline_keys_are_always_valid_ascii() {
        for byte in [0x00u8, 0x0f, 0x7f, 0x80, 0xff] {
            let key = LoxoneUuid::from_bytes([byte; 16]).format_loxone_key();
            assert_eq!(key.as_str().len(), key.as_bytes().len());
            assert!(key.as_str().is_ascii());
        }
    }

    #[test]
    fn both_key_flavours_agree_on_size() {
        let mut payload = text_record(1, b"a");
        payload.extend_from_slice(&text_record(2, b"bb"));
        assert_eq!(
            collect_texts(&payload).len(),
            collect_texts_by_name(&payload).len()
        );
    }

    /// A hasher that ignored part of the key would still pass the map tests,
    /// so check that distinct UUIDs actually reach distinct hashes.
    #[test]
    fn the_hasher_reads_the_whole_uuid() {
        use std::hash::Hash;

        let hash_of = |uuid: LoxoneUuid| {
            let mut h = LoxHasher::default();
            uuid.hash(&mut h);
            h.finish()
        };
        let base = [0u8; 16];
        let baseline = hash_of(LoxoneUuid::from_bytes(base));
        for byte in 0..16 {
            let mut raw = base;
            raw[byte] = 0xff;
            assert_ne!(
                hash_of(LoxoneUuid::from_bytes(raw)),
                baseline,
                "byte {byte} did not affect the hash"
            );
        }
    }
}
