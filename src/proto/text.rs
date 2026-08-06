//! Type-3 Event-Table of Text-States (zero-copy walk + 4-byte pad).

use crate::uuid::LoxoneUuid;
use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Header size: uuid(16) + uuidIcon(16) + textLength(4).
pub const TEXT_HEADER_SIZE: usize = 36;

#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RecordHeader {
    uuid: [u8; 16],
    uuid_icon: [u8; 16],
    text_length: U32,
}

/// Walk type-3 text records.
///
/// Layout per record (starts at multiple of 4):
/// `uuid(16) | uuidIcon(16) | textLength(u32le) | text | pad to 4`.
///
/// The trailing padding of the final record may be missing; that record is still
/// dispatched. Parsing stops at the first record whose announced `textLength`
/// runs past the payload.
#[inline]
pub fn walk_texts(payload: &[u8], mut f: impl FnMut(&LoxoneUuid, &LoxoneUuid, &[u8])) {
    let mut rest = payload;
    while let Ok((header, after_header)) = RecordHeader::ref_from_prefix(rest) {
        let text_len = header.text_length.get() as usize;
        let Some(text) = after_header.get(..text_len) else {
            return;
        };
        let uuid = LoxoneUuid::from_bytes(header.uuid);
        let icon = LoxoneUuid::from_bytes(header.uuid_icon);
        f(&uuid, &icon, text);

        let record_len = (TEXT_HEADER_SIZE + text_len + 3) & !3;
        let Some(next) = rest.get(record_len..) else {
            return;
        };
        rest = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_record(buf: &mut Vec<u8>, uuid: u8, icon: u8, text: &[u8]) {
        buf.extend_from_slice(&[uuid; 16]);
        buf.extend_from_slice(&[icon; 16]);
        buf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        buf.extend_from_slice(text);
        let pad = (4 - (text.len() % 4)) % 4;
        buf.extend_from_slice(&vec![0u8; pad]);
    }

    #[test]
    fn walk_text_with_padding() {
        let mut buf = Vec::new();
        push_record(&mut buf, 0x11, 0x22, b"hi");
        assert_eq!(buf.len(), 40);

        let mut got = None;
        walk_texts(&buf, |u, i, t| {
            got = Some((u.0, i.0, t.to_vec()));
        });
        let (u, i, t) = got.expect("one record");
        assert_eq!(u, [0x11u8; 16]);
        assert_eq!(i, [0x22u8; 16]);
        assert_eq!(t, b"hi");
    }

    #[test]
    fn walk_text_exact_align() {
        let mut buf = Vec::new();
        push_record(&mut buf, 0, 1, b"abcd");

        let mut n = 0;
        walk_texts(&buf, |_, _, t| {
            assert_eq!(t, b"abcd");
            n += 1;
        });
        assert_eq!(n, 1);
    }

    #[test]
    fn all_padding_residues_chain_correctly() {
        for first in ["", "a", "ab", "abc"] {
            let mut buf = Vec::new();
            push_record(&mut buf, 1, 1, first.as_bytes());
            push_record(&mut buf, 2, 2, b"second");
            assert_eq!(buf.len() % 4, 0);

            let mut seen = Vec::new();
            walk_texts(&buf, |u, _, t| seen.push((u.0[0], t.to_vec())));
            assert_eq!(
                seen,
                vec![(1, first.as_bytes().to_vec()), (2, b"second".to_vec())],
                "first={first:?}"
            );
        }
    }

    #[test]
    fn last_record_without_padding_is_dispatched() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[7u8; 16]);
        buf.extend_from_slice(&[8u8; 16]);
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(b"abc");

        let mut seen = Vec::new();
        walk_texts(&buf, |_, _, t| seen.push(t.to_vec()));
        assert_eq!(seen, vec![b"abc".to_vec()]);
    }

    #[test]
    fn empty_text_is_dispatched() {
        let mut buf = Vec::new();
        push_record(&mut buf, 3, 4, b"");
        let mut seen = Vec::new();
        walk_texts(&buf, |_, _, t| seen.push(t.len()));
        assert_eq!(seen, vec![0]);
    }

    #[test]
    fn overlong_text_length_stops_parsing() {
        let mut buf = Vec::new();
        push_record(&mut buf, 1, 1, b"ok");
        buf.extend_from_slice(&[2u8; 16]);
        buf.extend_from_slice(&[2u8; 16]);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        buf.extend_from_slice(b"short");

        let mut seen = Vec::new();
        walk_texts(&buf, |u, _, _| seen.push(u.0[0]));
        assert_eq!(seen, vec![1]);
    }

    #[test]
    fn truncated_payload_never_panics() {
        let mut buf = Vec::new();
        push_record(&mut buf, 1, 1, b"first");
        push_record(&mut buf, 2, 2, b"second text");
        for len in 0..=buf.len() {
            let mut n = 0;
            walk_texts(&buf[..len], |_, _, _| n += 1);
            assert!(n <= 2);
        }
    }
}
