#![allow(non_camel_case_types)]

use std::{fmt::{Display, Write}, io::{Cursor, SeekFrom}, mem::size_of};

use byteorder::{ReadBytesExt, LittleEndian};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{types::{Header, HeaderField, BufReadExt, new_header_field}, Result};

use super::{section::{offset_to_rva, SectionHeader, SectionTable}, PeError};

pub const DIR_LENGTH: u64 = 16;
pub const ENTRY_LENGTH: u64 = 8;
pub const DATA_LENGTH: u64 = 16;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Clone, Copy, Serialize)]
pub enum ResourceType {
    #[default]
    CURSOR = 1,
    BITMAP = 2,
    ICON = 3,
    MENU = 4,
    DIALOG = 5,
    STRING = 6,
    FONTDIR = 7,
    FONT = 8,
    ACCELERATOR = 9,
    RC_DATA = 10,
    MESSAGE_TABLE = 11,
    GROUP_CURSOR = 12,
    GROUP_ICON = 14,
    VERSION = 16,
    DLG_INCLUDE = 17,
    PLUG_PLAY = 19,
    VXD = 20,
    ANIMATED_CURSOR = 21,
    ANIMATED_ICON = 22,
    HTML = 23,
    MANIFEST = 24,
    UNKNOWN(u32),
}

impl From<u32> for ResourceType {
    fn from(value: u32) -> Self {
        match value {
            01 => Self::CURSOR,
            02 => Self::BITMAP,
            03 => Self::ICON,
            04 => Self::MENU,
            05 => Self::DIALOG,
            06 => Self::STRING,
            07 => Self::FONTDIR,
            08 => Self::FONT,
            09 => Self::ACCELERATOR,
            10 => Self::RC_DATA,
            11 => Self::MESSAGE_TABLE,
            12 => Self::GROUP_CURSOR,
            14 => Self::GROUP_ICON,
            16 => Self::VERSION,
            17 => Self::DLG_INCLUDE,
            19 => Self::PLUG_PLAY,
            20 => Self::VXD,
            21 => Self::ANIMATED_CURSOR,
            22 => Self::ANIMATED_ICON,
            23 => Self::HTML,
            24 => Self::MANIFEST,
            _  => Self::UNKNOWN(value),
        }
    }
}


#[derive(Debug, Default, Serialize)]
pub struct ResourceString {
    pub length: HeaderField<u16>,
    pub value: HeaderField<String>,
}

impl ResourceString {
    pub fn fix_rvas(&mut self, sections: &SectionTable) -> crate::Result<()> {
        self.length.rva = Some(offset_to_rva(sections, self.length.offset as u32)
            .ok_or(PeError::NoSectionForOffset(self.length.offset.into()))?
            .into());
        self.value.rva = Some(offset_to_rva(sections, self.value.offset as u32)
            .ok_or(PeError::NoSectionForOffset(self.value.offset.into()))?
            .into());

        Ok(())
    }
}

impl Header for ResourceString {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut hdr = Self::default();
        let offset = pos;
        
        let mut cursor = Cursor::new(bytes);
        hdr.value.value = cursor.read_wchar_string_at_offset(0)?;
        hdr.value.offset = offset + 2;
        hdr.length.value = hdr.value.value.len() as u16;
        hdr.length.offset = offset;

        Ok(hdr)
    }

    fn parse_buf(reader: &mut impl BufReadExt, pos: u64, offset: u64) -> crate::Result<Self> where Self: Sized {
        let mut hdr = Self::default();
        let mut field_pos = pos;
        reader.seek(SeekFrom::Start(offset))?;

        hdr.length = new_header_field!(reader.read_u16::<LittleEndian>()?, field_pos);
        hdr.value.value = reader.read_wchar_string_at_offset(offset + 2)?;
        hdr.value.offset = field_pos + 2;

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.length.value > 0 && self.value.value.len() == self.length.value as usize
    }

    fn length() -> usize {
        unimplemented!()
    }
}

impl Display for ResourceString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.value)
    }
}


#[derive(Debug, Default, Serialize)]
pub struct ResourceData {
    pub rva: HeaderField<u32>,
    pub size: HeaderField<u32>,
    pub code_page: HeaderField<u32>,
    #[serde(skip_serializing)]
    reserved: HeaderField<u32>,
    #[serde(skip_serializing)]
    pub value: HeaderField<Vec<u8>>,
}

impl ResourceData {
    pub fn load_data(&mut self, section: &SectionHeader, reader: &mut dyn BufReadExt) -> crate::Result<&mut Self> {
        let section_offset = section.raw_data_ptr.value as u64;
        let section_len = section.virtual_size.value as u64;

        let rv_offset = self.rva.value as i64 - section.virtual_address.value as i64; //relative virtual offset.
        if rv_offset <= 0 { // must be in resource section?
            let section_endva = (section.virtual_address.value + section.virtual_size.value) as u64;
            return Err(
                PeError::BeyondRange {
                    name: format!("{} section", section.name_str()?),
                    typ: "rva".into(), 
                    value: self.rva.value.into(), 
                    start: section.virtual_address.value.into(), 
                    end: section_endva,
                }
            )
        }

        let offset = section.raw_data_ptr.value as u64 + rv_offset as u64;
        let section_end_offset = section_offset + section_len;
        if offset > section_end_offset { // must be in resource section?
            return Err(
                PeError::BeyondRange {
                    name: format!("{} section", section.name_str()?),
                    typ: "offset".into(), 
                    value: offset.into(), 
                    start: section.raw_data_ptr.value.into(), 
                    end: section_end_offset,
                }
            )
        }

        let data = reader.read_bytes_at_offset(offset, self.size.value as usize)?;
        let data_len = data.len();
        self.value = HeaderField{value: data, offset, rva: Some(self.rva.value.into()), size: data_len as u64 };

        Ok(self)
    }

    pub fn fix_rvas(&mut self, sections: &SectionTable) -> crate::Result<()> {
        self.rva.rva = Some(offset_to_rva(sections, self.rva.offset as u32)
            .ok_or(PeError::InvalidOffset(self.rva.offset.into()))?
            .into());

        self.size.rva = Some(offset_to_rva(sections, self.size.offset as u32)
            .ok_or(PeError::InvalidOffset(self.size.offset.into()))?
            .into());

        self.code_page.rva = Some(offset_to_rva(sections, self.code_page.offset as u32)
            .ok_or(PeError::InvalidOffset(self.code_page.value.into()))?
            .into());

        self.reserved.rva = Some(offset_to_rva(sections, self.reserved.offset as u32)
            .ok_or(PeError::InvalidOffset(self.reserved.offset.into()))?
            .into());
        
        Ok(())
    }
}

impl Header for ResourceData {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut offset = pos;
        let mut hdr = Self::default();
        
        let mut cursor = Cursor::new(bytes);
        //cursor.seek(SeekFrom::Start(offset))?;

        hdr.rva = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        hdr.size = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        hdr.code_page = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        hdr.reserved = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.reserved.value == 0
    }

    fn length() -> usize {
        DATA_LENGTH as usize
    }
}

impl Display for ResourceData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ RVA: {:08x}, Size: {}, CodePage: {} }}", self.rva.value, self.size.value, self.code_page.value)
    }
}

#[derive(Debug)]
pub enum ResourceNode {
    Str(ResourceString),
    Data(ResourceData),
    Dir(ResourceDirectory)
}

impl Default for ResourceNode {
    fn default() -> Self {
        Self::Dir(Default::default())
    }
}


impl ResourceNode {
    pub fn fix_rvas(&mut self, sections: &SectionTable) -> crate::Result<()> {
        match self {
            Self::Data(data) => data.fix_rvas(sections),
            Self::Str(rstr) => rstr.fix_rvas(sections),
            Self::Dir(dir) => dir.fix_rvas(sections),
        }
    }
}

impl Display for ResourceNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug)]
pub enum DataType {
    STRING,
    DATA,
    DIR,
}


#[derive(Debug, Default)]
pub struct ResourceEntry {
    pub is_string: bool,
    pub is_data: bool,
    pub id: ResourceType,
    pub name_offset: HeaderField<u32>,
    pub data_offset: HeaderField<u32>,
    pub data: ResourceNode,
}

impl ResourceEntry {
    fn parse_rsrc(&mut self, section: &SectionHeader, reader: &mut impl BufReadExt)-> crate::Result<&mut Self> where Self: Sized {
        const OFFSET_MASK: u32 = 0x7fffffff;
        let section_offset = section.raw_data_ptr.value as u64;

        if self.is_data {
            let offset = (self.data_offset.value & OFFSET_MASK) as u64;
            let pos = section_offset + offset;
            let bytes = reader.read_bytes_at_offset(pos, DATA_LENGTH as usize)?;
            let data = ResourceData::parse_bytes(bytes, pos)?;

            self.data = ResourceNode::Data(data);
        }
        else if self.is_string {
            let offset = (self.name_offset.value & OFFSET_MASK) as u64;
            let pos = section_offset + offset;
            let rstr = reader.read_wchar_string_at_offset(pos)?;
            let rstr_len = rstr.len();
            let data = ResourceString { 
                length: HeaderField { value: rstr.len() as u16, offset: pos, rva: Some(pos), size: 2 }, 
                value: HeaderField { value: rstr, offset: pos + 2, rva: Some(pos + 2), size: rstr_len as u64 }
            };

            self.data = ResourceNode::Str(data);
        }
        else {
            let offset = (self.data_offset.value & OFFSET_MASK) as u64;
            let pos = section_offset + offset;
            let bytes = reader.read_bytes_at_offset(pos, DIR_LENGTH as usize)?;
            let mut data = ResourceDirectory::parse_bytes(bytes, pos)?;
            data.parse_rsrc(section, reader)?;

            self.data = ResourceNode::Dir(data);
        }

        Ok(self)
    }

    pub fn fix_rvas(&mut self, sections: &SectionTable) -> crate::Result<()> {
        self.name_offset.rva = Some(offset_to_rva(sections, self.name_offset.offset as u32)
            .ok_or(PeError::InvalidOffset(self.name_offset.offset.into()))?
            .into());
        
        self.data_offset.rva = Some(offset_to_rva(sections, self.data_offset.offset as u32)
            .ok_or(PeError::InvalidOffset(self.data_offset.offset.into()))?
            .into());

        self.data.fix_rvas(sections)?;

        Ok(())
    }
}

impl Header for ResourceEntry {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut hdr = Self::default();
        let mut offset = pos;

        let mut cursor = Cursor::new(bytes);
        //cursor.seek(SeekFrom::Start(offset))?;

        hdr.name_offset = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        hdr.data_offset = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        if hdr.name_offset.value & 0x80000000 == 0 {
            hdr.is_string = false;
            hdr.id = ResourceType::from(hdr.name_offset.value & 0x7fffffff);
        }
        else {
            hdr.is_string = true;
            hdr.id = ResourceType::from(0);
        }

        hdr.is_data = hdr.data_offset.value & 0x80000000 == 0;
            
        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.data_offset.value != 0 || self.name_offset.value != 0
    }

    fn length() -> usize {
        ENTRY_LENGTH as usize
    }
}

impl Display for ResourceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ IsString: {}, IsData: {}, ID: {:?}, NameOffset: {:08x}, DataOffset: {:08x} }}", self.is_string, self.is_data, self.id, self.name_offset.value, self.data_offset.value)
    }
}


#[derive(Debug, Default)]
pub struct ResourceDirectory {
    pub charactristics: HeaderField<u32>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub major_version: HeaderField<u16>,
    pub minor_version: HeaderField<u16>,
    pub named_entry_count: HeaderField<u16>,
    pub id_entry_count: HeaderField<u16>,
    pub entries: Vec<ResourceEntry>,
}

impl Display for ResourceDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ Charactristics: {:#08x}, Timestamp: {:?}, MajorVersion: {}, MinorVersion: {}, NumberOfNamedEntries: {}, NumberOfIdEntries: {} }}",
            self.charactristics.value, self.timestamp.value, self.major_version.value, self.minor_version, self.named_entry_count, self.id_entry_count
        )
    }
}

impl ResourceDirectory {
    pub fn parse_rsrc(&mut self, section: &SectionHeader, reader: &mut impl BufReadExt) -> crate::Result<()> {
        let entry_count:u32 = self.named_entry_count.value as u32 + self.id_entry_count.value as u32; 

        for i in 0..entry_count {
            let pos = self.charactristics.offset + DIR_LENGTH + (i * ENTRY_LENGTH as u32) as u64;
            //let offset = section_offset + self.charactristics.offset + DIR_LENGTH + (i + ENTRY_LENGTH as u16) as u64;
            let buf = reader.read_bytes_at_offset(pos, ENTRY_LENGTH as usize)?;
            let mut entry = ResourceEntry::parse_bytes(buf, pos)?;
            entry.parse_rsrc(section, reader)?;
            self.entries.push(entry);
        }

        Ok(())
    }

    pub fn fix_rvas(&mut self, sections: &SectionTable) -> Result<()> {
        self.charactristics.rva = Some(offset_to_rva(sections, self.charactristics.offset as u32)
            .ok_or(PeError::InvalidOffset(self.charactristics.offset.into()))?
            .into());

        self.timestamp.rva = Some(offset_to_rva(sections, self.timestamp.offset as u32)
            .ok_or(PeError::InvalidOffset(self.timestamp.offset.into()))?
            .into());

        self.major_version.rva = Some(offset_to_rva(sections, self.major_version.offset as u32)
            .ok_or(PeError::InvalidOffset(self.major_version.offset.into()))?
            .into());

        self.minor_version.rva = Some(offset_to_rva(sections, self.minor_version.offset as u32)
            .ok_or(PeError::InvalidOffset(self.minor_version.offset.into()))?
            .into());

        self.named_entry_count.rva = Some(offset_to_rva(sections, self.named_entry_count.offset as u32)
            .ok_or(PeError::InvalidOffset(self.named_entry_count.offset.into()))?
            .into());

        self.id_entry_count.rva = Some(offset_to_rva(sections, self.id_entry_count.offset as u32)
            .ok_or(PeError::InvalidOffset(self.id_entry_count.offset.into()))?
            .into());

        for entry in &mut self.entries {
            entry.fix_rvas(sections)?;
        }

        Ok(())
    }
}

impl Header for ResourceDirectory {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let bytes_len = bytes.len() as u64;
        let mut offset = pos;

        if bytes_len < DIR_LENGTH {
            return Err ( 
                PeError::BufferTooSmall { target: "ResourceDir".to_owned(), expected: DIR_LENGTH, actual: bytes_len }
            );
        }

        let mut hdr = Self::default();
        let mut cursor = Cursor::new(bytes);
        //cursor.seek(SeekFrom::Start(offset))?;

        hdr.charactristics = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        
        let data = cursor.read_u32::<LittleEndian>()?;
        let ts = DateTime::<Utc>::from_timestamp(data.into(), 0).ok_or(PeError::InvalidTimestamp(data.into()))?; //TODO: map to RsrcParseError?
        hdr.timestamp = HeaderField {value: ts, offset:offset, rva: Some(offset), size: 4 };
        offset += size_of::<u32>() as u64;

        hdr.major_version = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        hdr.minor_version = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        hdr.named_entry_count = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        hdr.id_entry_count = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.charactristics.value == 0 && (self.named_entry_count.value + self.id_entry_count.value) > 0
    }

    fn length() -> usize {
        DIR_LENGTH as usize
    }
}


pub(crate) fn display_rsrc_tree(dir: &ResourceDirectory, f: &mut dyn Write, seperator: &String, level: u8) -> std::fmt::Result {
    writeln!(f, "{} Dir: {}", seperator.repeat(level.into()), dir)?;

    for entry in &dir.entries {
        writeln!(f, "{} Entry: {}", seperator.repeat((level + 1).into()), entry)?;
        let prefix = seperator.repeat((level + 2).into());
        match &entry.data {
            ResourceNode::Str(str) => writeln!(f, "{prefix} Str: {str}")?,
            ResourceNode::Data(data) => writeln!(f, "{prefix} Data: {data}")?,
            ResourceNode::Dir(dir) => display_rsrc_tree(&dir, f, seperator, level+3)?
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests;
