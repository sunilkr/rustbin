use std::{io::{Error, Cursor}, mem::size_of, fmt::Display};

use byteorder::{ReadBytesExt, LittleEndian};
use chrono::prelude::*;
use bitflags::bitflags;

use crate::{types::{HeaderField, Header}, errors::InvalidTimestamp};

pub const HEADER_LENGTH: u64 = 24;

#[derive(Debug, PartialEq)]
pub enum MachineType {    
    UNKNOWN = 0x0,    
    AMD64   = 0x8664,
    ARM     = 0x1c0,
    ARM64   = 0xaa64,
    I386    = 0x14c,
    IA64    = 0x200,
    THUMB   = 0x1c2,    
}

impl From<u16> for MachineType {
    fn from(value: u16) -> Self {
        match value {
            0x8664 => Self::AMD64,
            0x1c0 => Self::ARM,
            0xaa64 => Self::ARM64,
            0x14c => Self::I386,
            0x200 => Self::IA64,
            0x1c2 => Self::THUMB,
            _ => Self::UNKNOWN
        }
    }
}

bitflags! {
    pub struct Flags: u16 {
        const UNKNOWN = 0x0000;
        const RELOCS_STRIPPED = 0x0001;
        const EXECUTABLE = 0x0002;
        //const //LINE_NUMS_STRIPPED = 0x0004,
        //const //LOCAL_SYMS_STRIPPED = 0x0008,
        //const //AGGRESSIVE_WS_TRIM = 0x0010,
        const LARGE_ADDRESS_AWARE = 0x0020;
        const RESERVED = 0x0040;
        //const //BYTES_REVERSED_LO = 0x0080,
        const MACHINE_32BIT = 0x0100;
        const DEBUG_STRIPPED = 0x0200;
        const REMOVABLE_RUN_FROM_SWAP = 0x0400;
        const NET_RUN_FROM_SWAP = 0x0800;
        const SYSTEM = 0x1000;
        const DLL = 0x2000;
        const UP_SYSTEM_ONLY = 0x4000;
        //const //BYTES_REVERSED_HI = 0x8000,
    }
}

#[derive(Debug)]
pub struct FileHeader {
    pub magic: HeaderField<u32>,
    pub machine: HeaderField<MachineType>,
    pub sections: HeaderField<u16>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub symbol_table_ptr: HeaderField<u32>,
    pub symbols: HeaderField<u32>,
    pub optional_header_size: HeaderField<u16>,
    pub characteristics: HeaderField<u16>,
}

impl FileHeader {
    pub fn new() -> Self {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::default(), Utc);
        FileHeader {
            magic: Default::default(),
            machine: HeaderField { value: MachineType::UNKNOWN, offset: 0, rva: 0 },
            sections: Default::default(),
            timestamp: HeaderField { value: dt, offset:0, rva:0 },
            symbol_table_ptr: Default::default(),
            symbols: Default::default(),
            optional_header_size: Default::default(),
            characteristics: Default::default(),
        }
    }
    
    pub fn flags(&self) -> Option<Flags> {
        Flags::from_bits(self.characteristics.value)
    }
}

impl Display for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{Magic: '{}', Machine: {:?}, Sections: {}, Timestamp: {:?}, Charactristics: {:?}}}", 
            std::str::from_utf8(&self.magic.value.to_le_bytes()).unwrap_or("ERR"), 
            self.machine.value, self.sections.value, self.timestamp.value, 
            self.flags().unwrap_or(Flags::UNKNOWN))
    }
}

impl Header for FileHeader {
    fn parse_bytes(bytes: &[u8], pos: u64) -> crate::Result<Self> where Self: Sized {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err ( 
                Box::new(Error::new (
                    std::io::ErrorKind::InvalidData, 
                    format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes_len)
                ))
            );
        }

        let mut cursor = Cursor::new(bytes);
        //cursor.seek(SeekFrom::Start(pos))?;
        let mut offset = pos;
        let mut file_hdr = Self::new();

        file_hdr.magic = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);

        let data = cursor.read_u16::<LittleEndian>()?;
        file_hdr.machine = HeaderField { value: MachineType::from(data), offset: offset, rva: offset };
        offset += size_of::<u16>() as u64;

        file_hdr.sections = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        
        let data = cursor.read_u32::<LittleEndian>()?;
        let nts = NaiveDateTime::from_timestamp_opt(data.into(), 0).ok_or(InvalidTimestamp{ data: data.into() })?;
        let ts = DateTime::<Utc>::from_utc(nts, Utc);
        file_hdr.timestamp = HeaderField { value: ts, offset: offset, rva: offset} ;
        offset += size_of::<u32>() as u64;

        file_hdr.symbol_table_ptr = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        file_hdr.symbols = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        file_hdr.optional_header_size = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        file_hdr.characteristics = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);

        Ok(file_hdr)
    }

    fn is_valid(&self) -> bool {
        self.magic.value == 0x00004550
    }

    fn length() -> usize { HEADER_LENGTH as usize }
}

#[cfg(test)]
mod tests {
    use crate::{types::Header, pe::file::{MachineType, Flags}};

    use super::{HEADER_LENGTH, FileHeader};

    const RAW_BYTES: [u8; HEADER_LENGTH as usize] = [
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 0xA5, 0xE6, 0xE4, 0x61, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00 ];

    #[test]
    fn parse_valid_header() {
        let file_hdr = FileHeader::parse_bytes(&RAW_BYTES, 0).unwrap();
        // eprintln!("{:?}", file_hdr);
        // eprintln!("{:?}", file_hdr.flags());
        assert!(file_hdr.is_valid());
        assert_eq!(file_hdr.machine.value, MachineType::AMD64);
        assert_eq!(file_hdr.timestamp.value.format("%Y-%m-%d %H:%M:%S").to_string(), "2022-01-17 03:46:45");
        assert_eq!(file_hdr.sections.value, 5);
        assert_eq!(file_hdr.optional_header_size.value, 0x00f0);
        assert_eq!(file_hdr.characteristics.value, 0x22);
        assert_eq!(file_hdr.flags().unwrap(), Flags::EXECUTABLE | Flags::LARGE_ADDRESS_AWARE);
    }

    #[test]
    fn parse_invalid_header() {
        let mut buf = RAW_BYTES.to_vec();
        buf[0] = 0x46;
        let file_hdr = FileHeader::parse_bytes(&buf, 0).unwrap();
        assert!(!file_hdr.is_valid())
    }
}