//! Type-4 Event-Table of Daytimer-States (PDF-complete; Python stubs this).

use crate::uuid::LoxoneUuid;
use std::fmt;
use zerocopy::little_endian::{F64, I32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Borrowed daytimer event for zero-copy handler dispatch.
#[derive(Debug)]
pub struct DaytimerEvent<'a> {
    pub uuid: LoxoneUuid,
    pub default_value: f64,
    pub entries: &'a [DaytimerEntry],
}

/// One daytimer entry (24 bytes), mapped directly onto the wire layout of
/// `EvDataDaytimerEntry`.
///
/// The fields are stored as little-endian byte arrays, so the struct has an
/// alignment of 1 and the exact wire size on every target. A `&[u8]` payload can
/// therefore be reinterpreted as `&[DaytimerEntry]` at any offset and on any
/// endianness. Read the values through the accessors ([`mode`](Self::mode),
/// [`from_minutes`](Self::from_minutes), [`to_minutes`](Self::to_minutes),
/// [`need_activate`](Self::need_activate), [`value`](Self::value)), which decode
/// to native types:
///
/// ```
/// # use loxwebsocket::DaytimerEntry;
/// let entry = DaytimerEntry::new(1, 480, 510, 1, 21.5);
/// assert_eq!(entry.mode(), 1);
/// assert_eq!(entry.value(), 21.5);
/// ```
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DaytimerEntry {
    mode: I32,
    from_minutes: I32,
    to_minutes: I32,
    need_activate: I32,
    value: F64,
}

impl DaytimerEntry {
    pub const SIZE: usize = 24;

    /// Build an entry from native values.
    #[inline]
    pub const fn new(
        mode: i32,
        from_minutes: i32,
        to_minutes: i32,
        need_activate: i32,
        value: f64,
    ) -> Self {
        Self {
            mode: I32::new(mode),
            from_minutes: I32::new(from_minutes),
            to_minutes: I32::new(to_minutes),
            need_activate: I32::new(need_activate),
            value: F64::new(value),
        }
    }

    /// Mode number of this entry.
    #[inline]
    pub fn mode(&self) -> i32 {
        self.mode.get()
    }

    /// Start time in minutes since midnight.
    #[inline]
    pub fn from_minutes(&self) -> i32 {
        self.from_minutes.get()
    }

    /// End time in minutes since midnight.
    #[inline]
    pub fn to_minutes(&self) -> i32 {
        self.to_minutes.get()
    }

    /// Trigger flag (`bNeedActivate`).
    #[inline]
    pub fn need_activate(&self) -> i32 {
        self.need_activate.get()
    }

    /// Entry value (analog daytimers only).
    #[inline]
    pub fn value(&self) -> f64 {
        self.value.get()
    }

    #[inline]
    pub fn read_at(buf: &[u8], offset: usize) -> Option<Self> {
        let end = offset.checked_add(Self::SIZE)?;
        Self::read_from_bytes(buf.get(offset..end)?).ok()
    }
}

impl fmt::Debug for DaytimerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaytimerEntry")
            .field("mode", &self.mode())
            .field("from_minutes", &self.from_minutes())
            .field("to_minutes", &self.to_minutes())
            .field("need_activate", &self.need_activate())
            .field("value", &self.value())
            .finish()
    }
}

/// Header size: uuid(16) + dDefValue(8) + nrEntries(4).
pub const DAYTIMER_HEADER_SIZE: usize = 28;

#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct TableHeader {
    uuid: [u8; 16],
    default_value: F64,
    nr_entries: I32,
}

#[inline]
fn entries_of(bytes: &[u8]) -> &[DaytimerEntry] {
    let count = bytes.len() / DaytimerEntry::SIZE;
    match <[DaytimerEntry]>::ref_from_prefix_with_elems(bytes, count) {
        Ok((entries, _)) => entries,
        Err(_) => &[],
    }
}

/// Split off one table header plus its entry bytes, returning the remaining payload.
#[inline]
fn split_table(payload: &[u8]) -> Option<(&TableHeader, &[u8], &[u8])> {
    let (header, after_header) = TableHeader::ref_from_prefix(payload).ok()?;
    let count = usize::try_from(header.nr_entries.get()).ok()?;
    let entries_len = count.checked_mul(DaytimerEntry::SIZE)?;
    let entries = after_header.get(..entries_len)?;
    let rest = after_header.get(entries_len..)?;
    Some((header, entries, rest))
}

/// Walk type-4 daytimer tables. Each table may contain multiple entries.
///
/// The entry array is reinterpreted in place, so no allocation happens per table.
/// Parsing stops at the first malformed table (truncated header, negative
/// `nrEntries`, or an entry array that runs past the payload).
pub fn walk_daytimers(payload: &[u8], mut f: impl FnMut(DaytimerEvent<'_>)) {
    let mut rest = payload;
    while let Some((header, entry_bytes, tail)) = split_table(rest) {
        rest = tail;
        f(DaytimerEvent {
            uuid: LoxoneUuid::from_bytes(header.uuid),
            default_value: header.default_value.get(),
            entries: entries_of(entry_bytes),
        });
    }
}

/// Zero-copy walk that invokes `entry_fn` for each entry without collecting them.
///
/// `table_fn` receives the table UUID, its default value and the announced entry
/// count before the entries of that table are dispatched.
pub fn walk_daytimer_raw(
    payload: &[u8],
    mut table_fn: impl FnMut(&LoxoneUuid, f64, i32),
    mut entry_fn: impl FnMut(&LoxoneUuid, DaytimerEntry),
) {
    let mut rest = payload;
    while let Some((header, entry_bytes, tail)) = split_table(rest) {
        let uuid = LoxoneUuid::from_bytes(header.uuid);
        table_fn(&uuid, header.default_value.get(), header.nr_entries.get());
        rest = tail;
        for entry in entries_of(entry_bytes) {
            entry_fn(&uuid, *entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: i32) -> DaytimerEntry {
        DaytimerEntry::new(i, 60 * i, 60 * i + 30, 1, 10.0 + f64::from(i))
    }

    fn push_table(
        buf: &mut Vec<u8>,
        uuid: [u8; 16],
        default_value: f64,
        entries: &[DaytimerEntry],
    ) {
        buf.extend_from_slice(&uuid);
        buf.extend_from_slice(&default_value.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as i32).to_le_bytes());
        buf.extend_from_slice(entries.as_bytes());
    }

    fn assert_same_entry(a: &DaytimerEntry, b: &DaytimerEntry) {
        assert_eq!(a.mode(), b.mode());
        assert_eq!(a.from_minutes(), b.from_minutes());
        assert_eq!(a.to_minutes(), b.to_minutes());
        assert_eq!(a.need_activate(), b.need_activate());
        assert_eq!(a.value(), b.value());
    }

    #[test]
    fn entry_wire_size_is_24() {
        assert_eq!(std::mem::size_of::<DaytimerEntry>(), DaytimerEntry::SIZE);
        assert_eq!(std::mem::align_of::<DaytimerEntry>(), 1);
    }

    #[test]
    fn accessors_roundtrip_native_values() {
        let e = DaytimerEntry::new(-3, 480, 510, 1, -0.5);
        assert_eq!(e.mode(), -3);
        assert_eq!(e.from_minutes(), 480);
        assert_eq!(e.to_minutes(), 510);
        assert_eq!(e.need_activate(), 1);
        assert_eq!(e.value(), -0.5);
        assert_eq!(e.as_bytes()[0..4], (-3i32).to_le_bytes());
        assert_eq!(e.as_bytes()[16..24], (-0.5f64).to_le_bytes());
    }

    #[test]
    fn debug_shows_decoded_values() {
        let s = format!("{:?}", entry(2));
        assert!(s.contains("mode: 2"), "{s}");
        assert!(s.contains("value: 12.0"), "{s}");
    }

    #[test]
    fn parse_daytimer_two_entries() {
        let mut buf = Vec::new();
        push_table(&mut buf, [0xAAu8; 16], 3.5, &[entry(0), entry(1)]);

        let mut tables = 0;
        walk_daytimers(&buf, |ev| {
            tables += 1;
            assert_eq!(ev.uuid.0, [0xAAu8; 16]);
            assert_eq!(ev.default_value, 3.5);
            assert_eq!(ev.entries.len(), 2);
            assert_eq!(ev.entries[0].mode(), 0);
            assert_eq!(ev.entries[1].from_minutes(), 60);
            assert_eq!(ev.entries[1].value(), 11.0);
        });
        assert_eq!(tables, 1);
    }

    #[test]
    fn slice_cast_matches_read_at() {
        let mut buf = Vec::new();
        let expected: Vec<DaytimerEntry> = (0..7).map(entry).collect();
        push_table(&mut buf, [0x11u8; 16], -1.5, &expected);

        let mut checked = 0;
        walk_daytimers(&buf, |ev| {
            assert_eq!(ev.entries.len(), expected.len());
            for (i, got) in ev.entries.iter().enumerate() {
                assert_same_entry(got, &expected[i]);
                let reference =
                    DaytimerEntry::read_at(&buf, DAYTIMER_HEADER_SIZE + i * DaytimerEntry::SIZE)
                        .expect("entry in bounds");
                assert_same_entry(got, &reference);
                checked += 1;
            }
        });
        assert_eq!(checked, 7);
    }

    #[test]
    fn entries_borrow_the_payload() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 0.0, &[entry(0), entry(1)]);
        walk_daytimers(&buf, |ev| {
            let entry_bytes = ev.entries.as_bytes();
            let start = entry_bytes.as_ptr() as usize - buf.as_ptr() as usize;
            assert_eq!(start, DAYTIMER_HEADER_SIZE);
            assert_eq!(entry_bytes.len(), 2 * DaytimerEntry::SIZE);
        });
    }

    #[test]
    fn multiple_tables_back_to_back() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1.0, &[entry(1)]);
        push_table(&mut buf, [2u8; 16], 2.0, &[]);
        push_table(&mut buf, [3u8; 16], 3.0, &[entry(2), entry(3), entry(4)]);

        let mut seen = Vec::new();
        walk_daytimers(&buf, |ev| {
            seen.push((ev.uuid.0[0], ev.default_value, ev.entries.len()))
        });
        assert_eq!(seen, vec![(1, 1.0, 1), (2, 2.0, 0), (3, 3.0, 3)]);
    }

    #[test]
    fn zero_entries_still_dispatches_table() {
        let mut buf = Vec::new();
        push_table(&mut buf, [0x42u8; 16], 7.25, &[]);
        let mut n = 0;
        walk_daytimers(&buf, |ev| {
            n += 1;
            assert!(ev.entries.is_empty());
            assert_eq!(ev.default_value, 7.25);
        });
        assert_eq!(n, 1);
    }

    #[test]
    fn negative_entry_count_stops_parsing() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1.0, &[entry(0)]);
        buf.extend_from_slice(&[2u8; 16]);
        buf.extend_from_slice(&0.0f64.to_le_bytes());
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        buf.extend_from_slice(&[0u8; 64]);

        let mut seen = Vec::new();
        walk_daytimers(&buf, |ev| seen.push(ev.uuid.0[0]));
        assert_eq!(seen, vec![1]);
    }

    #[test]
    fn overlong_entry_count_stops_parsing() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[9u8; 16]);
        buf.extend_from_slice(&0.0f64.to_le_bytes());
        buf.extend_from_slice(&i32::MAX.to_le_bytes());
        buf.extend_from_slice(&[0u8; 24]);

        let mut n = 0;
        walk_daytimers(&buf, |_| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn truncated_payload_never_panics() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1.0, &[entry(0), entry(1)]);
        push_table(&mut buf, [2u8; 16], 2.0, &[entry(2)]);
        for len in 0..=buf.len() {
            let mut n = 0;
            walk_daytimers(&buf[..len], |_| n += 1);
            walk_daytimer_raw(&buf[..len], |_, _, _| {}, |_, _| {});
            assert!(n <= 2);
        }
    }

    #[test]
    fn raw_walk_matches_collected_walk() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1.0, &[entry(1), entry(2)]);
        push_table(&mut buf, [2u8; 16], 2.0, &[]);
        push_table(&mut buf, [3u8; 16], 3.0, &[entry(3)]);

        let mut collected = Vec::new();
        walk_daytimers(&buf, |ev| {
            for e in ev.entries {
                collected.push((ev.uuid.0[0], e.mode()));
            }
        });

        let mut tables = Vec::new();
        let mut raw = Vec::new();
        walk_daytimer_raw(
            &buf,
            |u, d, n| tables.push((u.0[0], d, n)),
            |u, e| raw.push((u.0[0], e.mode())),
        );
        assert_eq!(raw, collected);
        assert_eq!(tables, vec![(1, 1.0, 2), (2, 2.0, 0), (3, 3.0, 1)]);
    }
}
