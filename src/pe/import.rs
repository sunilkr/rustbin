use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc, NaiveDateTime};

use crate::types::{HeaderField, Header, PeHeader};
use std::{io::{Result, Cursor}, mem::size_of, };
use super::PeImage;

#[derive(Debug)]
pub struct ImportName {
    hint: HeaderField<u16>,
    name: HeaderField<String>,
}

#[derive(Debug)]
pub struct ImportLookup32 {
    value: HeaderField<u32>,
    is_ordinal: bool,
    ordinal: Option<u16>,
    name: Option<HeaderField<ImportName>>,
}

#[derive(Debug)]
pub struct ImportLookup64 {
    value: HeaderField<u64>,
    is_ordinal: bool,
    ordinal: Option<u16>,
    name: Option<HeaderField<ImportName>>,
}

#[derive(Debug)]
pub enum ImportLookup {
    X86(ImportLookup32),
    X64(ImportLookup64),
}

pub const IMPORT_DESCRIPTOR_SIZE:usize = 20;

#[derive(Debug)]
pub struct ImportDescriptor {
    ilt: HeaderField<u32>,
    timestamp: HeaderField<DateTime<Utc>>,
    forwarder_chain: HeaderField<u32>,
    name_rva: HeaderField<u32>,
    first_thunk: HeaderField<u32>,
    name: Option<String>,
    imports: Vec<ImportLookup>,
}

impl ImportDescriptor {
    pub fn new() -> Self {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        ImportDescriptor { 
            ilt: Default::default(), 
            timestamp: HeaderField {value: dt, rva: 0, offset: 0},
            forwarder_chain: Default::default(), 
            name_rva: Default::default(), 
            first_thunk: Default::default(), 
            name: Default::default(), 
            imports: Default::default() 
        }
    }

    pub fn update_name(&mut self, image: &PeImage) {
        self.name = image.read_string_at_rva(self.name_rva.value);
    }

    pub fn parse_imports(&mut self, image: &PeImage) {
        todo!()
    }
}
 
impl Header for ImportDescriptor {
    fn parse_bytes(bytes: &[u8], pos: u64) -> Result<Self> where Self: Sized {
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        let mut id = Self::new();
        id.ilt = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);

        let dt = cursor.read_u32::<LittleEndian>()?;
        let ts = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(dt as i64, 0), Utc);
        id.timestamp = HeaderField {value: ts, offset: offset, rva: offset};
        offset += size_of::<u32>() as u64;

        id.forwarder_chain = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        id.name_rva = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        id.first_thunk = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        Ok(id)
    }

    fn is_valid(&self) -> bool {
        self.ilt.value != 0 && self.name_rva.value != 0 && self.first_thunk.value != 0
    }

    fn length() -> usize {
        IMPORT_DESCRIPTOR_SIZE
    }
}


impl PeHeader for ImportDescriptor {
    fn parse_bytes_for_image(bytes: &[u8], pos: u64, image: &PeImage) -> Result<Self> where Self: Sized {
         let mut id = Self::parse_bytes(bytes, pos)?;
         //id.ilt.rva = image.off
         id.update_name(image);
         Ok(id)
    }
}

#[derive(Debug)]
pub struct ImportDirectory<'a> {
    descriptors: Vec<HeaderField<ImportDescriptor>>,
    image: &'a PeImage,
}

impl<'a> ImportDirectory<'a> {
    pub fn new(image: &'a PeImage) -> Self {
        Self {
            descriptors: Vec::new(),
            image: image,
        }
    }
}

impl<'a> Header for ImportDirectory<'a> {
    fn parse_bytes(bytes: &[u8], pos: u64) -> Result<Self> where Self: Sized {
        todo!()
    }

    fn is_valid(&self) -> bool {
        todo!()
    }

    fn length() -> usize {
        todo!()
    }

}