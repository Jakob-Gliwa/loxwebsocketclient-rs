//! Type-7 Event-Table of Weather-States (PDF-complete; Python stubs this).

use crate::uuid::LoxoneUuid;
use std::fmt;
use zerocopy::little_endian::{F64, I32, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Borrowed weather event for handler dispatch.
#[derive(Debug)]
pub struct WeatherEvent<'a> {
    pub uuid: LoxoneUuid,
    /// Seconds since 2009-01-01 UTC.
    pub last_update: u32,
    pub entries: &'a [WeatherEntry],
}

/// One weather entry (68 bytes), mapped directly onto the wire layout of
/// `EvDataWeatherEntry`.
///
/// The fields are stored as little-endian byte arrays, so the struct has an
/// alignment of 1 and the exact wire size on every target — in particular there is
/// no padding before `temperature`, which a natural `repr(C)` layout would insert.
/// A `&[u8]` payload can therefore be reinterpreted as `&[WeatherEntry]` at any
/// offset and on any endianness. Read the values through the accessors, which
/// decode to native types:
///
/// ```
/// # use loxwebsocket::WeatherEntry;
/// let entry = WeatherEntry::new(1_000, 2, 180, 500, 70, 21.5, 20.0, 10.0, 0.1, 3.2, 1013.25);
/// assert_eq!(entry.weather_type(), 2);
/// assert_eq!(entry.temperature(), 21.5);
/// ```
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct WeatherEntry {
    timestamp: I32,
    weather_type: I32,
    wind_direction: I32,
    solar_radiation: I32,
    relative_humidity: I32,
    temperature: F64,
    perceived_temperature: F64,
    dew_point: F64,
    precipitation: F64,
    wind_speed: F64,
    barometric_pressure: F64,
}

impl WeatherEntry {
    pub const SIZE: usize = 68;

    /// Build an entry from native values.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        timestamp: i32,
        weather_type: i32,
        wind_direction: i32,
        solar_radiation: i32,
        relative_humidity: i32,
        temperature: f64,
        perceived_temperature: f64,
        dew_point: f64,
        precipitation: f64,
        wind_speed: f64,
        barometric_pressure: f64,
    ) -> Self {
        Self {
            timestamp: I32::new(timestamp),
            weather_type: I32::new(weather_type),
            wind_direction: I32::new(wind_direction),
            solar_radiation: I32::new(solar_radiation),
            relative_humidity: I32::new(relative_humidity),
            temperature: F64::new(temperature),
            perceived_temperature: F64::new(perceived_temperature),
            dew_point: F64::new(dew_point),
            precipitation: F64::new(precipitation),
            wind_speed: F64::new(wind_speed),
            barometric_pressure: F64::new(barometric_pressure),
        }
    }

    /// Forecast timestamp, in seconds since 2009-01-01 UTC.
    #[inline]
    pub fn timestamp(&self) -> i32 {
        self.timestamp.get()
    }

    /// Loxone weather type code.
    #[inline]
    pub fn weather_type(&self) -> i32 {
        self.weather_type.get()
    }

    /// Wind direction in degrees.
    #[inline]
    pub fn wind_direction(&self) -> i32 {
        self.wind_direction.get()
    }

    /// Solar radiation in W/m².
    #[inline]
    pub fn solar_radiation(&self) -> i32 {
        self.solar_radiation.get()
    }

    /// Relative humidity in percent.
    #[inline]
    pub fn relative_humidity(&self) -> i32 {
        self.relative_humidity.get()
    }

    /// Temperature in °C.
    #[inline]
    pub fn temperature(&self) -> f64 {
        self.temperature.get()
    }

    /// Perceived ("feels like") temperature in °C.
    #[inline]
    pub fn perceived_temperature(&self) -> f64 {
        self.perceived_temperature.get()
    }

    /// Dew point in °C.
    #[inline]
    pub fn dew_point(&self) -> f64 {
        self.dew_point.get()
    }

    /// Precipitation in mm.
    #[inline]
    pub fn precipitation(&self) -> f64 {
        self.precipitation.get()
    }

    /// Wind speed in km/h.
    #[inline]
    pub fn wind_speed(&self) -> f64 {
        self.wind_speed.get()
    }

    /// Barometric pressure in hPa.
    #[inline]
    pub fn barometric_pressure(&self) -> f64 {
        self.barometric_pressure.get()
    }

    #[inline]
    pub fn read_at(buf: &[u8], offset: usize) -> Option<Self> {
        let end = offset.checked_add(Self::SIZE)?;
        Self::read_from_bytes(buf.get(offset..end)?).ok()
    }
}

impl fmt::Debug for WeatherEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeatherEntry")
            .field("timestamp", &self.timestamp())
            .field("weather_type", &self.weather_type())
            .field("wind_direction", &self.wind_direction())
            .field("solar_radiation", &self.solar_radiation())
            .field("relative_humidity", &self.relative_humidity())
            .field("temperature", &self.temperature())
            .field("perceived_temperature", &self.perceived_temperature())
            .field("dew_point", &self.dew_point())
            .field("precipitation", &self.precipitation())
            .field("wind_speed", &self.wind_speed())
            .field("barometric_pressure", &self.barometric_pressure())
            .finish()
    }
}

/// Header: uuid(16) + lastUpdate(u32) + nrEntries(i32).
pub const WEATHER_HEADER_SIZE: usize = 24;

#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct TableHeader {
    uuid: [u8; 16],
    last_update: U32,
    nr_entries: I32,
}

#[inline]
fn entries_of(bytes: &[u8]) -> &[WeatherEntry] {
    let count = bytes.len() / WeatherEntry::SIZE;
    match <[WeatherEntry]>::ref_from_prefix_with_elems(bytes, count) {
        Ok((entries, _)) => entries,
        Err(_) => &[],
    }
}

/// Split off one table header plus its entry bytes, returning the remaining payload.
#[inline]
fn split_table(payload: &[u8]) -> Option<(&TableHeader, &[u8], &[u8])> {
    let (header, after_header) = TableHeader::ref_from_prefix(payload).ok()?;
    let count = usize::try_from(header.nr_entries.get()).ok()?;
    let entries_len = count.checked_mul(WeatherEntry::SIZE)?;
    let entries = after_header.get(..entries_len)?;
    let rest = after_header.get(entries_len..)?;
    Some((header, entries, rest))
}

/// Walk type-7 weather tables.
///
/// The entry array is reinterpreted in place, so no allocation happens per table.
/// Parsing stops at the first malformed table (truncated header, negative
/// `nrEntries`, or an entry array that runs past the payload).
pub fn walk_weather(payload: &[u8], mut f: impl FnMut(WeatherEvent<'_>)) {
    let mut rest = payload;
    while let Some((header, entry_bytes, tail)) = split_table(rest) {
        rest = tail;
        f(WeatherEvent {
            uuid: LoxoneUuid::from_bytes(header.uuid),
            last_update: header.last_update.get(),
            entries: entries_of(entry_bytes),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: i32) -> WeatherEntry {
        WeatherEntry::new(
            1000 + i,
            2 + i,
            180,
            500,
            70,
            21.5 + f64::from(i),
            20.0,
            10.0,
            0.1,
            3.2,
            1013.25,
        )
    }

    fn push_table(buf: &mut Vec<u8>, uuid: [u8; 16], last_update: u32, entries: &[WeatherEntry]) {
        buf.extend_from_slice(&uuid);
        buf.extend_from_slice(&last_update.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as i32).to_le_bytes());
        buf.extend_from_slice(entries.as_bytes());
    }

    fn assert_same_entry(a: &WeatherEntry, b: &WeatherEntry) {
        assert_eq!(a.timestamp(), b.timestamp());
        assert_eq!(a.weather_type(), b.weather_type());
        assert_eq!(a.wind_direction(), b.wind_direction());
        assert_eq!(a.solar_radiation(), b.solar_radiation());
        assert_eq!(a.relative_humidity(), b.relative_humidity());
        assert_eq!(a.temperature(), b.temperature());
        assert_eq!(a.perceived_temperature(), b.perceived_temperature());
        assert_eq!(a.dew_point(), b.dew_point());
        assert_eq!(a.precipitation(), b.precipitation());
        assert_eq!(a.wind_speed(), b.wind_speed());
        assert_eq!(a.barometric_pressure(), b.barometric_pressure());
    }

    #[test]
    fn entry_wire_size_is_68() {
        assert_eq!(std::mem::size_of::<WeatherEntry>(), WeatherEntry::SIZE);
        assert_eq!(std::mem::align_of::<WeatherEntry>(), 1);
    }

    #[test]
    fn accessors_roundtrip_native_values() {
        let e = entry(0);
        assert_eq!(e.timestamp(), 1000);
        assert_eq!(e.weather_type(), 2);
        assert_eq!(e.wind_direction(), 180);
        assert_eq!(e.solar_radiation(), 500);
        assert_eq!(e.relative_humidity(), 70);
        assert_eq!(e.temperature(), 21.5);
        assert_eq!(e.perceived_temperature(), 20.0);
        assert_eq!(e.dew_point(), 10.0);
        assert_eq!(e.precipitation(), 0.1);
        assert_eq!(e.wind_speed(), 3.2);
        assert_eq!(e.barometric_pressure(), 1013.25);
        // temperature starts right after the five i32 fields, with no padding.
        assert_eq!(e.as_bytes()[20..28], 21.5f64.to_le_bytes());
    }

    #[test]
    fn debug_shows_decoded_values() {
        let s = format!("{:?}", entry(0));
        assert!(s.contains("weather_type: 2"), "{s}");
        assert!(s.contains("temperature: 21.5"), "{s}");
    }

    #[test]
    fn parse_weather_one_entry() {
        let mut buf = Vec::new();
        push_table(&mut buf, [0xBBu8; 16], 12345, &[entry(0)]);

        let mut n = 0;
        walk_weather(&buf, |ev| {
            n += 1;
            assert_eq!(ev.last_update, 12345);
            assert_eq!(ev.entries.len(), 1);
            assert_eq!(ev.entries[0].weather_type(), 2);
            assert_eq!(ev.entries[0].temperature(), 21.5);
            assert_eq!(ev.entries[0].barometric_pressure(), 1013.25);
        });
        assert_eq!(n, 1);
    }

    #[test]
    fn slice_cast_matches_read_at() {
        let mut buf = Vec::new();
        let expected: Vec<WeatherEntry> = (0..5).map(entry).collect();
        push_table(&mut buf, [0x11u8; 16], 7, &expected);

        let mut checked = 0;
        walk_weather(&buf, |ev| {
            assert_eq!(ev.entries.len(), expected.len());
            for (i, got) in ev.entries.iter().enumerate() {
                assert_same_entry(got, &expected[i]);
                let reference =
                    WeatherEntry::read_at(&buf, WEATHER_HEADER_SIZE + i * WeatherEntry::SIZE)
                        .expect("entry in bounds");
                assert_same_entry(got, &reference);
                checked += 1;
            }
        });
        assert_eq!(checked, 5);
    }

    #[test]
    fn entries_borrow_the_payload() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 0, &[entry(0), entry(1)]);
        walk_weather(&buf, |ev| {
            let entry_bytes = ev.entries.as_bytes();
            let start = entry_bytes.as_ptr() as usize - buf.as_ptr() as usize;
            assert_eq!(start, WEATHER_HEADER_SIZE);
            assert_eq!(entry_bytes.len(), 2 * WeatherEntry::SIZE);
        });
    }

    #[test]
    fn multiple_tables_back_to_back() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 10, &[entry(1)]);
        push_table(&mut buf, [2u8; 16], 20, &[]);
        push_table(&mut buf, [3u8; 16], 30, &[entry(2), entry(3)]);

        let mut seen = Vec::new();
        walk_weather(&buf, |ev| {
            seen.push((ev.uuid.0[0], ev.last_update, ev.entries.len()))
        });
        assert_eq!(seen, vec![(1, 10, 1), (2, 20, 0), (3, 30, 2)]);
    }

    #[test]
    fn zero_entries_still_dispatches_table() {
        let mut buf = Vec::new();
        push_table(&mut buf, [0x42u8; 16], 99, &[]);
        let mut n = 0;
        walk_weather(&buf, |ev| {
            n += 1;
            assert!(ev.entries.is_empty());
            assert_eq!(ev.last_update, 99);
        });
        assert_eq!(n, 1);
    }

    #[test]
    fn negative_entry_count_stops_parsing() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1, &[entry(0)]);
        buf.extend_from_slice(&[2u8; 16]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(-3i32).to_le_bytes());
        buf.extend_from_slice(&[0u8; 200]);

        let mut seen = Vec::new();
        walk_weather(&buf, |ev| seen.push(ev.uuid.0[0]));
        assert_eq!(seen, vec![1]);
    }

    #[test]
    fn overlong_entry_count_stops_parsing() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[9u8; 16]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&i32::MAX.to_le_bytes());
        buf.extend_from_slice(&[0u8; 68]);

        let mut n = 0;
        walk_weather(&buf, |_| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn truncated_payload_never_panics() {
        let mut buf = Vec::new();
        push_table(&mut buf, [1u8; 16], 1, &[entry(0), entry(1)]);
        push_table(&mut buf, [2u8; 16], 2, &[entry(2)]);
        for len in 0..=buf.len() {
            let mut n = 0;
            walk_weather(&buf[..len], |_| n += 1);
            assert!(n <= 2);
        }
    }
}
