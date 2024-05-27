#![allow(non_camel_case_types)]

pub mod x86;
pub mod x64;

use std::fmt::Display;
use std::io::Cursor;

use crate::types::{Header, HeaderField};
use crate::utils::flags_to_str;
use byteorder::{LittleEndian, ReadBytesExt};
use bitflags::bitflags;
use serde::Serialize;

use self::x86::OptionalHeader32 as OptionalHeader32; 
use self::x64::OptionalHeader64 as OptionalHeader64;

pub const HEADER_LENGTH_64: u64 = x64::HEADER_LENGTH;
pub const HEADER_LENGTH_32: u64 = x86::HEADER_LENGTH;
pub const DATA_DIRS_LENGTH: u64 = 128;
pub const MAX_DIRS: u8 = 15;

#[derive(Debug, Default)]
pub struct DataDirectory {
    pub member: DirectoryType,
    pub rva: HeaderField<u32>,
    pub size: HeaderField<u32>,
}

impl Display for DataDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {:?}, RVA: {:08x}, Size: {:08x} }}", self.member, self.rva.value, self.size.value)
    }
}


#[derive(Debug, Default, PartialEq, Serialize, Clone, Copy)]
pub enum DirectoryType {
    Export = 0,
    Import,
    Resource,
    Exception,
    Security,
    Relocation,
    Debug,
    Architecture,
    Reserved,
    TLS,
    Configuration,
    BoundImport,
    ImportAddressTable,
    DelayImport,
    DotNetMetadata,
    #[default]
    UNKNOWN = 255,
}

impl From<u8> for DirectoryType{
    fn from(value: u8) -> Self {
        match value {
           0  => Self::Export,
           1  => Self::Import,
           2  => Self::Resource,
           3  => Self::Exception,
           4  => Self::Security,
           5  => Self::Relocation,
           6  => Self::Debug,
           7  => Self::Architecture,
           8  => Self::Reserved,
           9  => Self::TLS,
           10 => Self::Configuration,
           11 => Self::BoundImport,
           12 => Self::ImportAddressTable,
           13 => Self::DelayImport,
           14 => Self::DotNetMetadata,
           _  => Self::UNKNOWN,
        }
    }
}


#[derive(Debug, Default, PartialEq, Serialize, Clone, Copy)]
pub enum ImageType {
    #[default]
    UNKNOWN = 0,
    ROM = 0x107,
    PE32 = 0x10b,
    #[serde(rename="PE32+")]
    PE64 = 0x20b,
}

impl From<u16> for ImageType {
    fn from(value: u16) -> Self {
        match value {
            0x107 => Self::ROM,
            0x10b => Self::PE32,
            0x20b => Self::PE64,
            _ => Self::UNKNOWN,
        }
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Clone, Copy)]
pub enum SubSystem {
    #[default]
    UNKNOWN = 0,
    NATIVE = 1,
    WINDOWS_GUI = 2,
    WINDOWS_CUI = 3,
    OS2_CUI = 5,
    POSIX_CUI = 7,
    WINDOWS_CE_GUI = 9,
    EFI_APPLICATION = 10,
    EFI_BOOT_SERVICE_DRIVER = 11,
    EFI_RUNTIME_DRIVER = 12,
    EFI_ROM = 13,
    XBOX = 14,
    WINDOWS_BOOT_APPLICATION = 16,
}

impl From<u16> for SubSystem{
    fn from(value : u16) -> Self {
        match value {
            1 => Self::NATIVE,
            2 => Self::WINDOWS_GUI,
            3 => Self::WINDOWS_CUI,
            5 => Self::OS2_CUI,
            7 => Self::POSIX_CUI,
            9 => Self::WINDOWS_CE_GUI,
            10 => Self::EFI_APPLICATION,
            11 => Self::EFI_BOOT_SERVICE_DRIVER,
            12 => Self::EFI_BOOT_SERVICE_DRIVER,
            13 => Self::EFI_ROM,
            14 => Self::XBOX,
            16 => Self:: WINDOWS_BOOT_APPLICATION,
            _ => Self::UNKNOWN,
        }
    }
}

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, Serialize)]
    pub struct Flags: u16 {
        const UNKNOWN = 0x0000;
        const HIGH_ENTROPY_VA = 0x0020;
        const DYNAMIC_BASE = 0x0040;
        const FORCE_INTEGRITY = 0x0080;
        const NX_COMPAT = 0x0100;
        const NO_ISOLATION = 0x0200;
        const NO_SEH = 0x0400;
        const NO_BIND = 0x0800;
        const APPCONTAINER = 0x1000;
        const WDM_DRIVER = 0x2000;
        const GUARD_CF = 0x4000;
        const TERMINAL_SERVER_AWARE = 0x8000;
    }
}

impl Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", flags_to_str(self))
    }
}

#[derive(Debug)]
pub enum OptionalHeader {
    X86(OptionalHeader32),
    X64(OptionalHeader64),
}

impl Display for OptionalHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionalHeader::X86(o) => write!(f, "{}", o),
            OptionalHeader::X64(o) => write!(f, "{}", o),
        }
    }
}

impl Default for OptionalHeader {
    fn default() -> Self {
        Self::X86(Default::default())
    }
}

impl OptionalHeader {
    pub fn get_image_type(&self) -> ImageType {
        match self {
            OptionalHeader::X86(_) => ImageType::PE32,
            OptionalHeader::X64(_) => ImageType::PE64,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            OptionalHeader::X86(o) => o.is_valid(),
            OptionalHeader::X64(o) => o.is_valid(),
        }
    }
}

pub fn parse_data_directories(bytes: &[u8], count: u8, pos: u64) -> crate::Result<Vec<HeaderField<DataDirectory>>> {
    //let mut hdr = Some(oh);
    let size = if count > MAX_DIRS {MAX_DIRS} else {count};
    let mut data_dirs = Vec::with_capacity(15);
    let mut cursor = Cursor::new(bytes);
    let mut offset = pos;
    
    for i in 0..size {
        let old_offset = offset;
        let rva = HeaderField { value: cursor.read_u32::<LittleEndian>()?, offset: offset, rva: offset };
        offset = offset + 4;
        let size = HeaderField { value: cursor.read_u32::<LittleEndian>()?, offset: offset, rva: offset };
        offset = offset + 4;
        let data_dir = DataDirectory { member: DirectoryType::from(i), rva, size };
        data_dirs.push(HeaderField { value:data_dir, offset: old_offset, rva: old_offset });
    }
    Ok(data_dirs)
}


#[cfg(test)]
mod tests {
    use crate::pe::optional::DirectoryType;

    use super::{parse_data_directories, MAX_DIRS};

    const RAW_BYTES: [u8; 128] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x26, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00,
        0x00, 0x60, 0x01, 0x00, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xA0, 0x01, 0x00, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00, 0x98, 0x0F, 0x00, 0x00,
        0x80, 0x1D, 0x01, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF0, 0x1D, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xD0, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    #[test]
    fn parse_valid_data() {
        let start = 0x188;        
        let dirs = parse_data_directories(&RAW_BYTES, 0x10, start).unwrap();
        let rvas= [
            0, 0x000126DC, 0x00016000, 0, 0x0001A000, 0x0001D000, 0x00011D80, 
            0, 0, 0, 0x00011DF0, 0, 0x0000D000, 0, 0
        ];

        let sizes = [
            0, 0x00000050, 0x000064E8, 0, 0x00001EB8, 0x00000F98, 0x00000070,
            0, 0, 0, 0x00000040, 0, 0x00000174, 0, 0
        ];

        let members = [
            DirectoryType::Export,
            DirectoryType::Import,
            DirectoryType::Resource,
            DirectoryType::Exception,
            DirectoryType::Security,
            DirectoryType::Relocation,
            DirectoryType::Debug,
            DirectoryType::Architecture,
            DirectoryType::Reserved,
            DirectoryType::TLS,
            DirectoryType::Configuration,
            DirectoryType::BoundImport,
            DirectoryType::ImportAddressTable,
            DirectoryType::DelayImport,
            DirectoryType::DotNetMetadata,
        ];

        for i in 0..MAX_DIRS as usize {
            let dir = &dirs[i];
            assert_eq!(dir.offset, start + (8 * (i as u64)));
            assert_eq!(dir.value.member, members[i]);
            assert_eq!(dir.value.rva.value, rvas[i]);
            assert_eq!(dir.value.rva.offset, start + (8 * (i as u64)));            
            assert_eq!(dir.value.size.value, sizes[i]);
            assert_eq!(dir.value.size.offset, start + (8 * (i as u64)) + 4);
        }
    }
}