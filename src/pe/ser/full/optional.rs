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


#[cfg(test)]
mod tests {

    use crate::{pe::optional::{self, x64::OptionalHeader64, x86::OptionalHeader32, OptionalHeader}, types::Header};

    use super::OptionalHeaderEx;


    //Tests for OptionalHeader32.
    const RAW_OPT32_BYTES: [u8; 96] = [
        0x0B, 0x01, 0x0E, 0x00, 0x00, 0xBC, 0x00, 0x00, 0x00, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x9B, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x01, 0x00,
        0x00, 0x04, 0x00, 0x00, 0xF1, 0xE2, 0x01, 0x00, 0x02, 0x00, 0x40, 0x81, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    ];
    
    const OPT32_POS: u64 = 0x128;

    #[test]
    fn test_opt32() {
        let opt_hdr = OptionalHeader::X86(OptionalHeader32::parse_bytes(RAW_OPT32_BYTES.into(), OPT32_POS).unwrap());
        let ser_opt32 = OptionalHeaderEx::from(&opt_hdr);
        match ser_opt32 {
            OptionalHeaderEx::X86(opt) => {
                assert_eq!(opt.address_of_entry_point.raw, vec![0x9b, 0x20, 0, 0]);
                assert_eq!(opt.address_of_entry_point.value.value, 0x209b);
                
                assert_eq!(
                    opt.dll_charactristics.raw, 
                    (optional::Flags::NX_COMPAT | optional::Flags::DYNAMIC_BASE | optional::Flags::TERMINAL_SERVER_AWARE)
                    .bits()
                    .to_le_bytes()
                    .to_vec()
                );

            },

            OptionalHeaderEx::X64(_) => assert!(false, "should have been parsed as 32 bit optional header"),
        }

    }

    //Tests for OptionalHeader64.
    const RAW_OPT64_BYTES: [u8; 112] = [
        0x0B, 0x02, 0x0E, 0x1C, 0x00, 0x7E, 0x03, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x74, 0x71, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x04, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x60, 0x81, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    ];

    const OPT64_POS: u64 = 0x108;

    #[test]
    fn test_opt64() {
        let opt_hdr = OptionalHeader::X64(OptionalHeader64::parse_bytes(RAW_OPT64_BYTES.into(), OPT64_POS).unwrap());
        let ser_opt = OptionalHeaderEx::from(&opt_hdr);
        match ser_opt {
            OptionalHeaderEx::X64(opt) => {
                assert_eq!(opt.address_of_entry_point.raw, vec![0x74, 0x71, 0x03, 0x00]);
                assert_eq!(opt.address_of_entry_point.value.value, 0x37174);
                
                assert_eq!(
                    opt.dll_charactristics.raw, 
                    (optional::Flags::NX_COMPAT | optional::Flags::DYNAMIC_BASE | optional::Flags::TERMINAL_SERVER_AWARE | optional::Flags::HIGH_ENTROPY_VA)
                    .bits()
                    .to_le_bytes()
                    .to_vec()
                );

            },

            OptionalHeaderEx::X86(_) => assert!(false, "should have been parsed as 64 bit optional header"),
        }

    }
}