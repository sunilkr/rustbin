#![allow(non_camel_case_types)]

use std::{io::{Error, Cursor, ErrorKind, Read}, string::FromUtf8Error, fmt::Display};
use bitflags::bitflags;
use byteorder::{ReadBytesExt, LittleEndian};

use crate::types::{HeaderField, Header};

use super::optional::{DataDirectory, DirectoryType};

#[derive(Debug, Clone)]
pub struct BadRvaError(pub u64);

impl Display for BadRvaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid RVA: {}", &self.0)
    }
}

impl std::error::Error for BadRvaError {

}

#[derive(Debug, Clone)]
pub struct BadOffsetError(pub u64);

impl Display for BadOffsetError{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Offset: {}", self.0)
    }
}

impl std::error::Error for BadOffsetError {
    
}


pub const HEADER_LENGTH: u64 = 40;

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct Flags: u32 {
        const UNKNOWN = 0x00000000;
        const NO_PAD = 0x00000008;
        const CODE = 0x00000020;
        const INITIALIZED_DATA= 0x00000040;
        const UNINITIALIZED_DATA = 0x00000080;
        const LNK_OTHER = 0x00000100;
        const LNK_INFO = 0x00000200;
        const LNK_REMOVE = 0x00000800;
        const LNK_COMDAT = 0x00001000;
        const NO_DEFER_SPEC_EXC = 0x00004000;
        const GPREL = 0x00008000;
        const MEM_PURGEABLE = 0x00020000;
        const MEM_LOCKED = 0x00040000;
        const MEM_PRELOAD = 0x00080000;        
        const LNK_NRELOC_OVFL = 0x01000000;
        const MEM_DISCARDABLE = 0x02000000;
        const MEM_NOT_CACHED = 0x04000000;
        const MEM_NOT_PAGED = 0x08000000;
        const MEM_SHARED = 0x10000000;
        const MEM_EXECUTE = 0x20000000;
        const MEM_READ = 0x40000000;
        const MEM_WRITE = 0x80000000;
    }
}

#[derive(Debug, Default)]
pub struct SectionHeader {
    pub name: HeaderField<[u8; 8]>,
    pub virtual_size: HeaderField<u32>, //Not using Misc.PhysicalAddress
    pub virtual_address: HeaderField<u32>,    
    pub sizeof_raw_data: HeaderField<u32>,    
    pub raw_data_ptr: HeaderField<u32>,
    pub relocs_ptr: HeaderField<u32>,
    pub line_num_ptr: HeaderField<u32>,
    pub relocs_count: HeaderField<u16>,
    pub line_num_count: HeaderField<u16>,
    pub charactristics: HeaderField<u32>,
}

impl SectionHeader {
    pub fn flags(&self) -> Option<Flags> {
        Flags::from_bits(self.charactristics.value)
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        let end_va = self.virtual_address.value + self.virtual_size.value;
        rva >= self.virtual_address.value && rva <= end_va
    }

    pub fn contains_va(&self, va: u64, base: u64) -> bool {
        let rva = va - base;
        self.contains_rva(rva as u32)
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if !self.contains_rva(rva) {
            return None; 
        }

        let offset = rva - self.virtual_address.value + self.raw_data_ptr.value;
        Some(offset)
    }

    pub fn offset_to_rva(&self, offset: u32) -> Option<u32> {        
        if self.contains_offset(offset) {
            let section_offset = offset - self.raw_data_ptr.value;
            let rva = self.virtual_address.value + section_offset;
            return Some(rva);
        }
        None
    }

    pub fn contains_offset(&self, offset: u32) -> bool {
        if self.raw_data_ptr.value <= offset{
            if self.raw_data_ptr.value + self.sizeof_raw_data.value > offset{
                return true;
            }
        }
        false
    }

    pub fn name_str(&self) -> std::result::Result<String, FromUtf8Error> {
        let str = String::from_utf8(self.name.value.to_vec())?;
        Ok(str.trim_matches(char::from(0)).to_string())
    }

    pub fn directories(&self, dirs: &Vec<HeaderField<DataDirectory>>) -> Vec<DirectoryType> {
        let mut dtypes = Vec::<DirectoryType>::new();
        for dir in dirs {
            let rva = dir.value.rva.value;
            if self.contains_rva(rva) {
                dtypes.push(dir.value.member);
            }
        }
        dtypes
    }
}

impl Header for SectionHeader {
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

        let mut hdr = Self { ..Default::default() };
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        let mut name: [u8; 8] = [0; 8];
        cursor.read(&mut name)?;
        hdr.name = Self::new_header_field(name, &mut offset);
        hdr.virtual_size = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.virtual_address = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_raw_data = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.raw_data_ptr = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.relocs_ptr = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.line_num_ptr = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.relocs_count = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.line_num_count = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.charactristics = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.line_num_count.value < 0xffff && self.relocs_count.value < 0xffff
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }
}

impl Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {}, RVA: {:#08x}, Size: {:#08x}, RawAddr: {:#08x}, RawSize: {:#08x}, Flags: {:?}}}", 
            self.name_str().unwrap_or("Err".into()), self.virtual_address.value, self.virtual_size.value, self.raw_data_ptr.value, self.sizeof_raw_data.value, self.flags().unwrap_or(Flags::UNKNOWN))
    }
}

pub type SectionTable = Vec<HeaderField<SectionHeader>>;

pub fn parse_sections(bytes: &[u8], count: u16, pos: u64) -> crate::Result<SectionTable> {
    let mut sections = Vec::with_capacity(count as usize);
    let bytes_len = bytes.len() as u64;

    if bytes_len < (HEADER_LENGTH * count as u64) {
        return Err ( 
            Box::new(Error::new (
                std::io::ErrorKind::InvalidData, 
                format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes_len)
            ))
        );
    }

    let mut offset = pos;
    let mut slice_start = 0u64;
    let mut slice_end = HEADER_LENGTH;

    for _ in 0..count {
        let buf = &bytes[slice_start as usize..slice_end as usize];
        let section = SectionHeader::parse_bytes(buf, offset)?;
        offset += HEADER_LENGTH;
        slice_start = slice_end;
        slice_end += HEADER_LENGTH;
        sections.push(HeaderField { value: section, offset: slice_start, rva: slice_start}); 
    }
    Ok(sections)
}

pub fn rva_to_offset(sections: &SectionTable, rva: u32) -> Option<u32> {
    for s in sections {
        if let Some(offset) = s.value.rva_to_offset(rva) {
            return Some(offset);
        }
    }
    None
}

pub fn rva_to_section(sections: &SectionTable, rva: u32) -> Option<&SectionHeader> {
    for s in sections {
        if s.value.contains_rva(rva) {
            return Some(&s.value);    
        }
    }
    None
}

pub fn offset_to_rva(sections: &SectionTable, offset: u32) -> Option<u32> {
    for s in sections {
        if let Some(rva) = s.value.offset_to_rva(offset) {
            return Some(rva);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{types::Header, pe::section::{rva_to_offset, offset_to_rva}};

    use super::{HEADER_LENGTH, SectionHeader, Flags, parse_sections};

    const RAW_BYTES: [u8; 240] = [
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xEB, 0xBB, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xBC, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x8E, 0x5F, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x78, 0x13, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00,
        0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x67, 0x66, 0x69, 0x64, 0x73, 0x00, 0x00,
        0xDC, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00,
        0x00, 0x66, 0x00, 0x00, 0x00, 0x2A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00,
        0x98, 0x0F, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42
    ];

    #[test]
    fn parse_one_section() {
        let bytes = &RAW_BYTES[0..HEADER_LENGTH as usize];
        let sh = SectionHeader::parse_bytes(bytes, 0x208).unwrap();
        assert!(sh.is_valid());
        assert_eq!(sh.name_str().unwrap(), String::from(".text"));
        assert_eq!(sh.name.offset, 0x208);
        assert_eq!(sh.virtual_size.value, 0xbbeb);
        assert_eq!(sh.virtual_size.offset, 0x210);
        assert_eq!(sh.virtual_address.value, 0x00001000);
        assert_eq!(sh.virtual_address.offset, 0x214);
        assert_eq!(sh.sizeof_raw_data.value, 0x0000bc00);
        assert_eq!(sh.sizeof_raw_data.offset, 0x218);
        assert_eq!(sh.raw_data_ptr.value, 0x00000400);
        assert_eq!(sh.raw_data_ptr.offset, 0x21c);
        assert_eq!(sh.relocs_ptr.value, 0);
        assert_eq!(sh.relocs_ptr.offset, 0x220);
        assert_eq!(sh.line_num_ptr.value, 0);
        assert_eq!(sh.line_num_ptr.offset, 0x224);
        assert_eq!(sh.relocs_count.value, 0);
        assert_eq!(sh.relocs_count.offset, 0x228);
        assert_eq!(sh.line_num_count.value, 0);
        assert_eq!(sh.line_num_count.offset, 0x22a);
        assert_eq!(sh.flags().unwrap(), Flags::CODE | Flags::MEM_EXECUTE | Flags::MEM_READ);
    }

    #[test]
    fn parse_all_sections() {
        let sections = parse_sections(&RAW_BYTES, 6, 0x208).unwrap();
        assert_eq!(sections.len(), 6);
        let names = [".text", ".rdata", ".data", ".gfids", ".rsrc", ".reloc"];
        let sec_flags = [
            Flags::CODE | Flags::MEM_READ | Flags::MEM_EXECUTE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_WRITE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_DISCARDABLE,
        ];
        for i in 0..6 {
            let hf_section = &sections[i];
            let sh = &hf_section.value;
            assert!(sh.is_valid());
            assert_eq!(sh.name_str().unwrap(), String::from(names[i]));
            assert_eq!(sh.flags().unwrap(), sec_flags[i]);
        }
    }

    #[test]
    fn oep_in_text_section() {
        let oep = 0x0000209B;
        let sections = parse_sections(&RAW_BYTES, 6, 0x208).unwrap();
        let txt_section = &sections[0].value;
        assert_eq!(txt_section.name_str().unwrap(), String::from(".text"));
        assert!(txt_section.contains_rva(oep));
    }

    #[test]
    fn oep_to_offset() {
        let offset: u32 = 0x0000149B;
        let oep: u32 = 0x0000209B;
        let sections = parse_sections(&RAW_BYTES, 6, 0x208).unwrap();
        assert_eq!(rva_to_offset(&sections, oep).unwrap(), offset);
    }

    #[test]
    fn oep_from_offset() {
        let offset: u32 = 0x0000149B;
        let oep: u32 = 0x0000209B;
        let sections = parse_sections(&RAW_BYTES, 6, 0x208).unwrap();
        assert_eq!(offset_to_rva(&sections, offset).unwrap(), oep);
    }
}