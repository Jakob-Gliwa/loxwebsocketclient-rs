//! Zero-copy Loxone binary protocol parsers.

pub mod daytimer;
pub mod header;
pub mod text;
pub mod value;
pub mod weather;

pub use daytimer::{
    DAYTIMER_HEADER_SIZE, DaytimerEntry, DaytimerEvent, walk_daytimer_raw, walk_daytimers,
};
pub use header::{MessageType, WsBinHdr, parse_header};
pub use text::{TEXT_HEADER_SIZE, walk_texts};
pub use value::{VALUE_RECORD_SIZE, walk_values};
pub use weather::{WEATHER_HEADER_SIZE, WeatherEntry, WeatherEvent, walk_weather};
