use std::{fmt::{Display, Formatter}, io::Cursor, mem::size_of};

use byteorder::{ReadBytesExt, LittleEndian};
use chrono::prelude::*;
use bitflags::bitflags;
use serde::Serialize;

use crate::{new_header_field, types::{Header, HeaderField}, utils::flags_to_str};

use super::PeError;

pub const HEADER_LENGTH: u64 = 24;

#[derive(Debug, PartialEq, Default, Serialize, Clone, Copy)]
pub enum MachineType {   
    #[default]
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
            0x01c0 => Self::ARM,
            0xaa64 => Self::ARM64,
            0x014c => Self::I386,
            0x0200 => Self::IA64,
            0x01c2 => Self::THUMB,
            _ => Self::UNKNOWN
        }
    }
}

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, Serialize)]
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

impl Display for Flags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", flags_to_str(self))
    }
}


#[derive(Debug, Default, Serialize)]
pub struct FileHeader {
    pub magic: HeaderField<u32>,
    pub machine: HeaderField<MachineType>,
    pub sections: HeaderField<u16>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub symbol_table_ptr: HeaderField<u32>,
    pub symbols: HeaderField<u32>,
    pub optional_header_size: HeaderField<u16>,
    pub charactristics: HeaderField<u16>,
}

impl FileHeader {
    pub fn new() -> Self {
        Default::default()
    }
    
    pub fn flags(&self) -> Option<Flags> {
        Flags::from_bits(self.charactristics.value)
    }
}

impl Display for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{Magic: '{}', Machine: {:?}, Sections: {}, Timestamp: {:?}, Charactristics: {}}}", 
            std::str::from_utf8(&self.magic.value.to_le_bytes()).unwrap_or("ERR"), 
            self.machine.value, self.sections.value, self.timestamp.value, 
            self.flags().unwrap_or(Flags::UNKNOWN))
    }
}

impl Header for FileHeader {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err ( 
                PeError::BufferTooSmall { target: "FileHeader".into(), expected: HEADER_LENGTH, actual:bytes_len }
            );
        }

        let mut cursor = Cursor::new(bytes);
        //cursor.seek(SeekFrom::Start(pos))?;
        let mut offset = pos;
        let mut file_hdr = Self::new();

        file_hdr.magic = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        let data = cursor.read_u16::<LittleEndian>()?;
        file_hdr.machine = HeaderField { value: MachineType::from(data), offset: offset, rva: offset };
        offset += size_of::<u16>() as u64;

        file_hdr.sections = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        
        let data = cursor.read_u32::<LittleEndian>()?;
        let ts = DateTime::<Utc>::from_timestamp(data.into(), 0).ok_or(PeError::InvalidTimestamp(data.into()))?; //TODO: map to FileParseError?
        file_hdr.timestamp = HeaderField { value: ts, offset: offset, rva: offset} ;
        offset += size_of::<u32>() as u64;

        file_hdr.symbol_table_ptr = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        file_hdr.symbols = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        file_hdr.optional_header_size = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        file_hdr.charactristics = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);

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
        let file_hdr = FileHeader::parse_bytes(RAW_BYTES.to_vec(), 0).unwrap();
        // eprintln!("{:?}", file_hdr);
        // eprintln!("{:?}", file_hdr.flags());
        assert!(file_hdr.is_valid());
        assert_eq!(file_hdr.machine.value, MachineType::AMD64);
        assert_eq!(file_hdr.timestamp.value.format("%Y-%m-%d %H:%M:%S").to_string(), "2022-01-17 03:46:45");
        assert_eq!(file_hdr.sections.value, 5);
        assert_eq!(file_hdr.optional_header_size.value, 0x00f0);
        assert_eq!(file_hdr.charactristics.value, 0x22);
        assert_eq!(file_hdr.flags().unwrap(), Flags::EXECUTABLE | Flags::LARGE_ADDRESS_AWARE);

        eprintln!("{file_hdr}");
        assert!(format!("{file_hdr}").contains("EXECUTABLE | LARGE_ADDRESS_AWARE"));
    }

    #[test]
    fn parse_invalid_header() {
        let mut buf = RAW_BYTES.to_vec();
        buf[0] = 0x46;
        let file_hdr = FileHeader::parse_bytes(buf, 0).unwrap();
        assert!(!file_hdr.is_valid())
    }

    #[test]
    fn file_hdr_to_json() {
        let file_hdr = FileHeader::parse_bytes(RAW_BYTES.to_vec(), 0).unwrap();
        let json = serde_json::to_string_pretty(&file_hdr).unwrap();
        eprintln!("{json}");
    }
}
