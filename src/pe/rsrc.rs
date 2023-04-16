#![allow(non_camel_case_types)]

use std::{io::{Error, ErrorKind, Cursor}, mem::size_of, default, fmt::Display, };

use byteorder::{ReadBytesExt, LittleEndian};
use chrono::{DateTime, Utc, NaiveDateTime};
use derivative::*;

use crate::{types::{HeaderField, Header}, errors::InvalidTimestamp, utils::Reader};

use super::section::SectionTable;

pub const HEADER_LENGTH: u64 = 16;

#[repr(u8)]
#[derive(Derivative)]
#[derivative(Debug, Default)]
pub enum ResourceType {
    #[derivative(Default)]
    UNKNOWN = 0,
    CURSOR = 1,
    BITMAP = 2,
    ICON = 3,
    MENU = 4,
    DIALOG = 5,
    STRING = 6,
    FONTDIR = 7,
    FONT = 8,
    ACCELERATOR = 9,
    RCDATA = 10,
    MESSAGETABLE = 11,
    GROUP_CURSOR = 12,
    GROUP_ICON = 14,
    VERSION = 16,
    DLGINCLUDE = 17,
    PLUGPLAY = 19,
    VXD = 20,
    ANICURSOR = 21,
    ANIICON = 22,
    HTML = 23,
    MANIFEST = 24,
}

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct ResourceString {
    pub length: HeaderField<u32>,
    pub value: HeaderField<String>,
}

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct ResourceData {
    pub rva: HeaderField<u32>,
    pub size: HeaderField<u32>,
    pub code_page: HeaderField<u32>,
    reservd: HeaderField<u32>,
}

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub enum ResourceNode {
    Str(ResourceString),
    Data(ResourceData),
    #[derivative(Default)]
    Entry(ResourceEntry),
}

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct ResourceEntry {
    pub name_is_string: bool,
    pub data_is_dir: bool,
    pub name_offset: HeaderField<u32>,
    pub data_offset: HeaderField<u32>,
    pub data: Box<ResourceNode>,
}

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct ResourceTable {
    pub charactristics: HeaderField<u32>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub major_version: HeaderField<u16>,
    pub minor_version: HeaderField<u16>,
    pub named_entry_count: HeaderField<u16>,
    pub id_entry_count: HeaderField<u16>,
    pub entries: Vec<ResourceEntry>,
}

impl Display for ResourceTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ Charactristics: {:#08x}, Timestamp: {:?}, MajorVersion: {}, MinorVersion: {}, NumberOfNamedEntries: {}, NumberOfIdEntries: {}",
            self.charactristics.value, self.timestamp.value, self.major_version.value, self.minor_version, self.named_entry_count, self.id_entry_count
        )
    }
}

impl ResourceTable {
    pub fn parse_rsrc(&mut self, sections: &SectionTable, reader: &mut dyn Reader) -> crate::Result<()>{
        todo!()
    }
}

impl Header for ResourceTable {
    fn parse_bytes(bytes: &[u8], pos: u64) -> crate::Result<Self> where Self: Sized {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err ( 
                Box::new(Error::new (
                    ErrorKind::InvalidData, 
                    format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes_len)
                ))
            );
        }

        let mut hdr = Self::default();
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        hdr.charactristics = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        
        let data = cursor.read_u32::<LittleEndian>()?;
        let nts = NaiveDateTime::from_timestamp_opt(data.into(), 0).ok_or(InvalidTimestamp{ data: data.into() })?;
        let ts = DateTime::<Utc>::from_utc(nts, Utc);
        hdr.timestamp = HeaderField {value: ts, offset:offset, rva: offset};
        offset += size_of::<u32>() as u64;

        hdr.major_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.named_entry_count = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.id_entry_count = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.charactristics.value == 0
    }

    fn length() -> usize {
        todo!()
    }
}


#[cfg(test)]
mod test{
    use crate::types::Header;

    use super::ResourceTable;


    #[test]
    fn parse_rsrc_table() {
        let rsrc_tbl_bytes = [
            0x00 as u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00,
        ];

        let rst = ResourceTable::parse_bytes(&rsrc_tbl_bytes, 0x89200).unwrap();

        assert_eq!(rst.charactristics.value, 0);
        assert_eq!(rst.charactristics.offset, 0x89200);
        assert_eq!(rst.timestamp.value.format("%Y-%m-%d %H:%M:%S").to_string(), "1970-01-01 00:00:00");
        assert_eq!(rst.timestamp.offset, 0x89204);
        assert_eq!(rst.major_version.value, 0x0004);
        assert_eq!(rst.major_version.offset, 0x89208);
        assert_eq!(rst.minor_version.value, 0);
        assert_eq!(rst.minor_version.offset, 0x8920a);
        assert_eq!(rst.named_entry_count.value, 0x0000);
        assert_eq!(rst.named_entry_count.offset, 0x8920c);
        assert_eq!(rst.id_entry_count.value, 0x000a);
        assert_eq!(rst.id_entry_count.offset, 0x8920e);
    }
}
