//! Type-2 Event-Table of Value-States (zero-copy walk).

use crate::uuid::LoxoneUuid;
use zerocopy::little_endian::F64;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Fixed record size: UUID (16) + f64 (8).
pub const VALUE_RECORD_SIZE: usize = 24;

/// One value record, mapped directly onto the wire layout of `EvData`.
///
/// Both fields have alignment 1 — `LoxoneUuid` is transparent over `[u8; 16]`
/// and `F64` is a little-endian byte array — so `repr(C)` gives exactly the 24
/// wire bytes with no padding, and a payload can be reinterpreted as
/// `&[ValueRecord]` at any offset on any endianness.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ValueRecord {
    uuid: LoxoneUuid,
    value: F64,
}

/// Walk type-2 value records without allocating.
///
/// Invokes `f` once per complete 24-byte record. Truncated trailing bytes are
/// ignored (same as Cython `len // 24`).
///
/// The whole payload is validated as a `[ValueRecord]` once and then iterated
/// in place, so the callback gets a `&LoxoneUuid` pointing into the frame
/// buffer rather than a copy — this is the hottest path in the client, and a
/// per-record bounds check plus two `copy_from_slice` calls into stack arrays
/// cost measurably more than the walk itself.
#[inline]
pub fn walk_values(payload: &[u8], mut f: impl FnMut(&LoxoneUuid, f64)) {
    let count = payload.len() / VALUE_RECORD_SIZE;
    // Cannot fail: alignment is 1 and `count` was derived from the length.
    let Ok((records, _tail)) = <[ValueRecord]>::ref_from_prefix_with_elems(payload, count) else {
        return;
    };
    for record in records {
        f(&record.uuid, record.value.get());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(uuid: [u8; 16], value: f64) -> Vec<u8> {
        let mut buf = uuid.to_vec();
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }

    /// The slice cast is only sound if the struct is exactly the wire record.
    #[test]
    fn the_record_matches_the_wire_layout() {
        assert_eq!(size_of::<ValueRecord>(), VALUE_RECORD_SIZE);
        assert_eq!(align_of::<ValueRecord>(), 1);
    }

    /// The callback borrows into the payload rather than a stack copy, so a
    /// caller may keep the reference for as long as the frame buffer lives.
    #[test]
    fn the_uuid_is_borrowed_from_the_payload() {
        let buf = record([7u8; 16], 1.0);
        let mut seen: *const u8 = std::ptr::null();
        walk_values(&buf, |u, _| seen = u.as_bytes().as_ptr());
        assert_eq!(seen, buf.as_ptr());
    }

    #[test]
    fn walk_two_values() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&record([0u8; 16], 1.0));
        buf.extend_from_slice(&record([0xffu8; 16], 2.5));

        let mut out = Vec::new();
        walk_values(&buf, |u, v| out.push((u.0, v)));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1, 1.0);
        assert_eq!(out[1].1, 2.5);
        assert_eq!(out[1].0, [0xffu8; 16]);
    }

    #[test]
    fn truncates_partial_record() {
        let mut buf = vec![0u8; 24];
        buf.extend_from_slice(&[1u8; 10]); // incomplete second record
        let mut n = 0;
        walk_values(&buf, |_, _| n += 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn every_truncation_length_keeps_complete_records() {
        let mut buf = Vec::new();
        for i in 0..4u8 {
            buf.extend_from_slice(&record([i; 16], f64::from(i)));
        }
        for len in 0..=buf.len() {
            let mut seen = Vec::new();
            walk_values(&buf[..len], |u, v| seen.push((u.0[0], v)));
            assert_eq!(seen.len(), len / VALUE_RECORD_SIZE, "len={len}");
            for (i, (tag, value)) in seen.iter().enumerate() {
                assert_eq!(usize::from(*tag), i);
                assert_eq!(*value, i as f64);
            }
        }
    }

    #[test]
    fn empty_payload_yields_nothing() {
        let mut n = 0;
        walk_values(&[], |_, _| n += 1);
        walk_values(&[0u8; 23], |_, _| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn preserves_special_float_values() {
        let mut buf = Vec::new();
        let expected = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0];
        for v in expected {
            buf.extend_from_slice(&record([0u8; 16], v));
        }
        let mut got = Vec::new();
        walk_values(&buf, |_, v| got.push(v));
        assert_eq!(got.len(), 4);
        assert!(got[0].is_nan());
        assert_eq!(got[1], f64::INFINITY);
        assert_eq!(got[2], f64::NEG_INFINITY);
        assert!(got[3].is_sign_negative());
    }
}
