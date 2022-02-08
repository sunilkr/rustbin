#![allow(non_camel_case_types)]

pub mod x86;
pub mod x64;

use std::{io::Cursor};

use crate::types::{HeaderField};
use byteorder::{LittleEndian, ReadBytesExt};
use derivative::Derivative;
use bitflags::bitflags;

use self::x86::OptionalHeader32 as OptionalHeader32; 
use self::x64::OptionalHeader64 as OptionalHeader64;

pub const HEADER_LENGTH_64: u64 = x64::HEADER_LENGTH;
pub const HEADER_LENGTH_32: u64 = x86::HEADER_LENGTH;

#[derive(Debug, Default)]
pub struct DataDirectory {
    pub rva: HeaderField<u32>,
    pub size: HeaderField<u32>,
}

#[derive(Derivative)]
#[derivative(Debug, Default, PartialEq)]
pub enum ImageType {
    #[derivative(Default)]
    UNKNOWN = 0,
    ROM = 0x107,
    PE32 = 0x10b,
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

#[derive(Derivative)]
#[derivative(Debug, Default, PartialEq)]
pub enum SubSystem {
    #[derivative(Default)]
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
    pub struct Flags: u16 {
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

#[derive(Debug)]
pub enum OptionalHeader {
    X86(OptionalHeader32),
    X64(OptionalHeader64),
}

pub fn parse_data_directories(cursor: &mut Cursor<&[u8]>, count: u8, offset: &mut u64) -> Vec<HeaderField<DataDirectory>> {
    //let mut hdr = Some(oh);
    let mut data_dirs = Vec::<HeaderField<DataDirectory>>::with_capacity(count as usize);
    
    for _ in 0..count {
        let old_offset = *offset;
        let rva = HeaderField { value: cursor.read_u32::<LittleEndian>().unwrap(), offset: *offset, rva: *offset };
        *offset = *offset + 4;
        let size = HeaderField { value: cursor.read_u32::<LittleEndian>().unwrap(), offset: *offset, rva: *offset };
        *offset = *offset + 4;
        let data_dir = DataDirectory{rva, size};
        data_dirs.push(HeaderField { value:data_dir, offset: old_offset, rva: old_offset });
    }
    data_dirs
}


