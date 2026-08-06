//! Loxone WebSocket binary message header (`WsBinHdr`).

use crate::error::{Error, Result};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Identifier byte values from the protocol document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Text = 0,
    BinaryFile = 1,
    ValueStates = 2,
    TextStates = 3,
    DaytimerStates = 4,
    OutOfService = 5,
    Keepalive = 6,
    WeatherStates = 7,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Text),
            1 => Some(Self::BinaryFile),
            2 => Some(Self::ValueStates),
            3 => Some(Self::TextStates),
            4 => Some(Self::DaytimerStates),
            5 => Some(Self::OutOfService),
            6 => Some(Self::Keepalive),
            7 => Some(Self::WeatherStates),
            _ => None,
        }
    }
}

/// Packed 8-byte Loxone message header.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct WsBinHdr {
    pub bin_type: u8,
    pub identifier: u8,
    pub info: u8,
    pub reserved: u8,
    pub len: [u8; 4],
}

impl WsBinHdr {
    pub const SIZE: usize = 8;
    pub const MAGIC: u8 = 0x03;
    /// Info bit 0: payload length is estimated; an exact header follows.
    pub const INFO_ESTIMATED: u8 = 0x01;

    #[inline]
    pub fn payload_len(&self) -> u32 {
        u32::from_le_bytes(self.len)
    }

    #[inline]
    pub fn is_estimated(&self) -> bool {
        self.info & Self::INFO_ESTIMATED != 0
    }

    #[inline]
    pub fn message_type(&self) -> Option<MessageType> {
        MessageType::from_u8(self.identifier)
    }
}

/// Parse an 8-byte header. Returns `Ok(None)` when the frame is not a header
/// (wrong length or magic). Estimated headers are returned as-is so the caller
/// can skip them and wait for the exact header.
pub fn parse_header(buf: &[u8]) -> Result<Option<WsBinHdr>> {
    if buf.len() != WsBinHdr::SIZE {
        return Ok(None);
    }
    let hdr =
        WsBinHdr::read_from_bytes(buf).map_err(|_| Error::protocol("invalid header layout"))?;
    if hdr.bin_type != WsBinHdr::MAGIC {
        return Ok(None);
    }
    Ok(Some(hdr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_header() {
        let mut buf = [0u8; 8];
        buf[0] = 0x03;
        buf[1] = 2;
        buf[2] = 0;
        buf[4..8].copy_from_slice(&48u32.to_le_bytes());
        let hdr = parse_header(&buf).unwrap().unwrap();
        assert_eq!(hdr.message_type(), Some(MessageType::ValueStates));
        assert_eq!(hdr.payload_len(), 48);
        assert!(!hdr.is_estimated());
    }

    #[test]
    fn estimated_bit() {
        let mut buf = [0u8; 8];
        buf[0] = 0x03;
        buf[1] = 2;
        buf[2] = WsBinHdr::INFO_ESTIMATED;
        let hdr = parse_header(&buf).unwrap().unwrap();
        assert!(hdr.is_estimated());
    }

    #[test]
    fn non_header_length() {
        assert!(parse_header(&[0x03, 0, 0, 0, 0, 0, 0]).unwrap().is_none());
    }
}
