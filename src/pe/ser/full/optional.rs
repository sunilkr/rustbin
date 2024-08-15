use serde::Serialize;

use crate::{pe::optional::{self, x64::OptionalHeader64, x86::OptionalHeader32, Flags, OptionalHeader}, types::HeaderField};

use super::{hf_to_hfx, HeaderFieldEx};


#[derive(Debug, Serialize)]
pub enum OptionalHeaderEx {
    #[serde(untagged)]
    X86(OptionalHeaderEx32),
    #[serde(untagged)]
    X64(OptionalHeaderEx64),
}

impl From<&OptionalHeader> for OptionalHeaderEx {
    fn from(value: &OptionalHeader) -> Self {
        match value {
            OptionalHeader::X86(opt32) => Self::X86(OptionalHeaderEx32::from(opt32)),
            OptionalHeader::X64(opt64) => Self::X64(OptionalHeaderEx64::from(opt64)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OptionalHeaderEx64 {
    pub(crate) magic: HeaderFieldEx<optional::ImageType>,
    #[serde(rename="major_linker_version")]
    pub(crate) major_linker_ver: HeaderFieldEx<u8>,
    #[serde(rename="minor_linker_version")]
    pub(crate) minor_linker_ver: HeaderFieldEx<u8>,
    #[serde(rename="size_of_code")]
    pub(crate) sizeof_code: HeaderFieldEx<u32>,
    #[serde(rename="size_of_initialized_data")]
    pub(crate) sizeof_initiailized_data: HeaderFieldEx<u32>,
    #[serde(rename="size_of_uninitialized_data")]
    pub(crate) sizeof_uninitiailized_data: HeaderFieldEx<u32>,
    pub(crate) address_of_entry_point: HeaderFieldEx<u32>,
    pub(crate) base_of_code: HeaderFieldEx<u32>,
    pub(crate) image_base: HeaderFieldEx<u64>,
    pub(crate) section_alignment: HeaderFieldEx<u32>,
    pub(crate) file_alignment: HeaderFieldEx<u32>,
    pub(crate) major_os_version: HeaderFieldEx<u16>,
    pub(crate) minor_os_version: HeaderFieldEx<u16>,
    pub(crate) major_image_version: HeaderFieldEx<u16>,
    pub(crate) minor_image_version: HeaderFieldEx<u16>,
    pub(crate) major_subsystem_version: HeaderFieldEx<u16>,
    pub(crate) minor_subsystem_version: HeaderFieldEx<u16>,
    pub(crate) win32_version: HeaderFieldEx<u32>,
    #[serde(rename="size_of_image")]
    pub(crate) sizeof_image: HeaderFieldEx<u32>,
    #[serde(rename="size_of_headers")]
    pub(crate) sizeof_headers: HeaderFieldEx<u32>,
    pub(crate) checksum: HeaderFieldEx<u32>,
    pub(crate) subsystem: HeaderFieldEx<optional::SubSystem>,
    pub(crate) dll_charactristics: HeaderFieldEx<optional::Flags>,
    pub(crate) sizeof_stack_reserve: HeaderFieldEx<u64>,
    pub(crate) sizeof_stack_commit: HeaderFieldEx<u64>,
    pub(crate) sizeof_heap_reserve: HeaderFieldEx<u64>,
    pub(crate) sizeof_heap_commit: HeaderFieldEx<u64>,
    pub(crate) loader_flags: HeaderFieldEx<u32>,
    pub(crate) number_of_rva_and_sizes: HeaderFieldEx<u32>,
}

impl From<&OptionalHeader64> for OptionalHeaderEx64 {
    fn from(value: &OptionalHeader64) -> Self {
        Self { 
            magic: HeaderFieldEx { 
                raw: (value.magic.value as u16).to_be_bytes().to_vec(), 
                value: value.magic.clone() 
            },

            major_linker_ver: hf_to_hfx(&value.major_linker_ver, super::ByteEndian::LE), 
            minor_linker_ver: hf_to_hfx(&value.minor_linker_ver, super::ByteEndian::LE), 
            sizeof_code: hf_to_hfx(&value.sizeof_code, super::ByteEndian::LE), 
            sizeof_initiailized_data: hf_to_hfx(&value.sizeof_initiailized_data, super::ByteEndian::LE), 
            sizeof_uninitiailized_data: hf_to_hfx(&value.sizeof_uninitiailized_data, super::ByteEndian::LE), 
            address_of_entry_point: hf_to_hfx(&value.address_of_entry_point, super::ByteEndian::LE), 
            base_of_code: hf_to_hfx(&value.base_of_code, super::ByteEndian::LE), 
            image_base: hf_to_hfx(&value.image_base, super::ByteEndian::LE), 
            section_alignment: hf_to_hfx(&value.section_alignment, super::ByteEndian::LE), 
            file_alignment: hf_to_hfx(&value.file_alignment, super::ByteEndian::LE), 
            major_os_version: hf_to_hfx(&value.major_os_version, super::ByteEndian::LE), 
            minor_os_version: hf_to_hfx(&value.minor_os_version, super::ByteEndian::LE), 
            major_image_version: hf_to_hfx(&value.major_image_version, super::ByteEndian::LE), 
            minor_image_version: hf_to_hfx(&value.minor_image_version, super::ByteEndian::LE), 
            major_subsystem_version: hf_to_hfx(&value.major_subsystem_version, super::ByteEndian::LE), 
            minor_subsystem_version: hf_to_hfx(&value.minor_subsystem_version, super::ByteEndian::LE),
            win32_version: hf_to_hfx(&value.win32_version, super::ByteEndian::LE), 
            sizeof_image: hf_to_hfx(&value.sizeof_image, super::ByteEndian::LE), 
            sizeof_headers: hf_to_hfx(&value.sizeof_headers, super::ByteEndian::LE), 
            checksum: hf_to_hfx(&value.checksum, super::ByteEndian::LE), 
            
            subsystem: HeaderFieldEx { 
                raw: (value.subsystem.value as u16).to_le_bytes().to_vec(), 
                value: value.subsystem.clone(),
            },

            dll_charactristics: HeaderFieldEx { 
                raw: value.dll_charactristics.value.to_le_bytes().to_vec(), 
                value: HeaderField {
                    value: optional::Flags::from_bits_truncate(value.dll_charactristics.value),
                    offset: value.dll_charactristics.offset,
                    rva: value.dll_charactristics.rva,
                    size: value.dll_charactristics.size,
                }
            },

            sizeof_stack_reserve: hf_to_hfx(&value.sizeof_stack_reserve, super::ByteEndian::LE), 
            sizeof_stack_commit: hf_to_hfx(&value.sizeof_stack_commit, super::ByteEndian::LE), 
            sizeof_heap_reserve: hf_to_hfx(&value.sizeof_heap_reserve, super::ByteEndian::LE), 
            sizeof_heap_commit: hf_to_hfx(&value.sizeof_heap_commit, super::ByteEndian::LE), 
            loader_flags: hf_to_hfx(&value.loader_flags, super::ByteEndian::LE), 
            number_of_rva_and_sizes: hf_to_hfx(&value.number_of_rva_and_sizes, super::ByteEndian::LE) 
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OptionalHeaderEx32 {
    pub(crate) magic: HeaderFieldEx<optional::ImageType>,
    #[serde(rename="major_linker_version")]
    pub(crate) major_linker_ver: HeaderFieldEx<u8>,
    #[serde(rename="minor_linker_version")]
    pub(crate) minor_linker_ver: HeaderFieldEx<u8>,
    #[serde(rename="size_of_code")]
    pub(crate) sizeof_code: HeaderFieldEx<u32>,
    #[serde(rename="size_of_initialized_data")]
    pub(crate) sizeof_initiailized_data: HeaderFieldEx<u32>,
    #[serde(rename="size_of_uninitialized_data")]
    pub(crate) sizeof_uninitiailized_data: HeaderFieldEx<u32>,
    pub(crate) address_of_entry_point: HeaderFieldEx<u32>,
    pub(crate) base_of_code: HeaderFieldEx<u32>,
    pub(crate) base_of_data: HeaderFieldEx<u32>,
    pub(crate) image_base: HeaderFieldEx<u32>,
    pub(crate) section_alignment: HeaderFieldEx<u32>,
    pub(crate) file_alignment: HeaderFieldEx<u32>,
    pub(crate) major_os_version: HeaderFieldEx<u16>,
    pub(crate) minor_os_version: HeaderFieldEx<u16>,
    pub(crate) major_image_version: HeaderFieldEx<u16>,
    pub(crate) minor_image_version: HeaderFieldEx<u16>,
    pub(crate) major_subsystem_version: HeaderFieldEx<u16>,
    pub(crate) minor_subsystem_version: HeaderFieldEx<u16>,
    pub(crate) win32_version: HeaderFieldEx<u32>,
    pub(crate) sizeof_image: HeaderFieldEx<u32>,
    pub(crate) sizeof_headers: HeaderFieldEx<u32>,
    pub(crate) checksum: HeaderFieldEx<u32>,
    pub(crate) subsystem: HeaderFieldEx<optional::SubSystem>,
    pub(crate) dll_charactristics: HeaderFieldEx<Flags>,
    pub(crate) sizeof_stack_reserve: HeaderFieldEx<u32>,
    pub(crate) sizeof_stack_commit: HeaderFieldEx<u32>,
    pub(crate) sizeof_heap_reserve: HeaderFieldEx<u32>,
    pub(crate) sizeof_heap_commit: HeaderFieldEx<u32>,
    pub(crate) loader_flags: HeaderFieldEx<u32>,
    pub(crate) number_of_rva_and_sizes: HeaderFieldEx<u32>,
}

impl From<&OptionalHeader32> for OptionalHeaderEx32 {
    fn from(value: &OptionalHeader32) -> Self {
        Self { 
            magic: HeaderFieldEx { 
                raw: (value.magic.value as u16).to_be_bytes().to_vec(), 
                value: value.magic.clone() 
            },

            major_linker_ver: hf_to_hfx(&value.major_linker_ver, super::ByteEndian::LE), 
            minor_linker_ver: hf_to_hfx(&value.minor_linker_ver, super::ByteEndian::LE), 
            sizeof_code: hf_to_hfx(&value.sizeof_code, super::ByteEndian::LE), 
            sizeof_initiailized_data: hf_to_hfx(&value.sizeof_initiailized_data, super::ByteEndian::LE), 
            sizeof_uninitiailized_data: hf_to_hfx(&value.sizeof_uninitiailized_data, super::ByteEndian::LE), 
            address_of_entry_point: hf_to_hfx(&value.address_of_entry_point, super::ByteEndian::LE), 
            base_of_code: hf_to_hfx(&value.base_of_code, super::ByteEndian::LE),
            base_of_data: hf_to_hfx(&value.base_of_data, super::ByteEndian::LE),
            image_base: hf_to_hfx(&value.image_base, super::ByteEndian::LE), 
            section_alignment: hf_to_hfx(&value.section_alignment, super::ByteEndian::LE), 
            file_alignment: hf_to_hfx(&value.file_alignment, super::ByteEndian::LE), 
            major_os_version: hf_to_hfx(&value.major_os_version, super::ByteEndian::LE), 
            minor_os_version: hf_to_hfx(&value.minor_os_version, super::ByteEndian::LE), 
            major_image_version: hf_to_hfx(&value.major_image_version, super::ByteEndian::LE), 
            minor_image_version: hf_to_hfx(&value.minor_image_version, super::ByteEndian::LE), 
            major_subsystem_version: hf_to_hfx(&value.major_subsystem_version, super::ByteEndian::LE), 
            minor_subsystem_version: hf_to_hfx(&value.minor_subsystem_version, super::ByteEndian::LE),
            win32_version: hf_to_hfx(&value.win32_version, super::ByteEndian::LE), 
            sizeof_image: hf_to_hfx(&value.sizeof_image, super::ByteEndian::LE), 
            sizeof_headers: hf_to_hfx(&value.sizeof_headers, super::ByteEndian::LE), 
            checksum: hf_to_hfx(&value.checksum, super::ByteEndian::LE), 
            
            subsystem: HeaderFieldEx { 
                raw: (value.subsystem.value as u16).to_le_bytes().to_vec(), 
                value: value.subsystem.clone(),
            },

            dll_charactristics: HeaderFieldEx { 
                raw: value.dll_charactristics.value.to_le_bytes().to_vec(), 
                value: HeaderField {
                    value: optional::Flags::from_bits_truncate(value.dll_charactristics.value),
                    offset: value.dll_charactristics.offset,
                    rva: value.dll_charactristics.rva,
                    size: value.dll_charactristics.size,
                }
            },

            sizeof_stack_reserve: hf_to_hfx(&value.sizeof_stack_reserve, super::ByteEndian::LE), 
            sizeof_stack_commit: hf_to_hfx(&value.sizeof_stack_commit, super::ByteEndian::LE), 
            sizeof_heap_reserve: hf_to_hfx(&value.sizeof_heap_reserve, super::ByteEndian::LE), 
            sizeof_heap_commit: hf_to_hfx(&value.sizeof_heap_commit, super::ByteEndian::LE), 
            loader_flags: hf_to_hfx(&value.loader_flags, super::ByteEndian::LE), 
            number_of_rva_and_sizes: hf_to_hfx(&value.number_of_rva_and_sizes, super::ByteEndian::LE) 
        }
    }
}
