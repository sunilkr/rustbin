use std::{
    fmt::Display, 
    io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom}, 
    string::{FromUtf16Error, FromUtf8Error}
};

use byteorder::{ReadBytesExt, LittleEndian};
use serde::Serialize;

use crate::pe::PeError;

#[derive(Debug, Default, PartialEq, Clone, Copy, Serialize)]
pub struct HeaderField<T> {
    pub value: T,
    pub offset: u64,
    pub rva: u64,
    //pub size: u32,
}

// impl<T> Debug for HeaderField<T> where T: Debug {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{:?}(0x{:x?}])@{{0x{:x?}, 0x{:?}}}", self.value, self.value, self.offset, self.rva)
//     }
// }

impl<T> Display for HeaderField<T> where T: Display {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

pub trait Header {
    ///Parse from an instance of `BufReadExt`.
    /// will read `Self::length()` bytes from `offset` and
    /// will use `pos` for calculating field `offset` and `rva`.
    fn parse_buf(reader: &mut impl BufReadExt, pos: u64, offset: u64) -> std::result::Result<Self, PeError> where Self: Sized {
        let size = Self::length();
        let result = reader.read_bytes_at_offset(offset, size)?;
        Self::parse_bytes(result, pos)
    }

    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> std::result::Result<Self, PeError> where Self: Sized;
    fn is_valid(&self) -> bool;
    fn length() -> usize;
}


pub trait BufReadExt : BufRead + Seek {
    //#[allow(unused_variables)]
    fn read_string_at_offset(&mut self, offset: u64) -> Result<String, ReadExtError>{
        let mut buf:Vec<u8> = Vec::new();
        self.seek(SeekFrom::Start(offset))?;
        self.read_until(b'\0', &mut buf)?;
        Ok(String::from_utf8(buf[..(buf.len()-1)].to_vec())?)
    }

    //#[allow(unused_variables)]
    fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, ReadExtError> {
        let mut buf:Vec<u8> = vec![0; size];
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    //#[allow(unused_variables)]
    fn read_wchar_string_at_offset(&mut self, offset: u64) -> Result<String, ReadExtError> {
        self.seek( SeekFrom::Start(offset))?;
        let len = self.read_u16::<LittleEndian>()?;
        let mut buf = vec![0u16; len.into()];
        self.read_u16_into::<LittleEndian>(&mut buf)?;
        Ok(String::from_utf16(&buf)?)
    }
}

impl<T> BufReadExt for BufReader<T> where T: Read + Seek { }

impl<T> BufReadExt for Cursor<T> where T: AsRef<[u8]> { }

impl BufReadExt for Box<dyn BufReadExt + '_> { }

#[derive(Debug, thiserror::Error)]
pub enum ReadExtError {
    #[error(transparent)]
    Seek(#[from] std::io::Error),

    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),

    #[error(transparent)]
    FromUtf16(#[from] FromUtf16Error),

    #[error("offset {offset} is less than base {base}")]
    OffsetBelowBase {base: u64, offset: u64},
}
