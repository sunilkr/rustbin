use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::pe::{
    dos::DosHeader, 
    file::{self, FileHeader, MachineType}, 
    optional::{self, x64::OptionalHeader64, x86::OptionalHeader32}, 
    section::{self, SectionHeader}
};

#[derive(Debug, Serialize)]
#[serde(rename="dos_header")]
struct MinDosHeader {
    pub magic: String,
    pub e_lfanew: u32,    
}

impl From<&DosHeader> for MinDosHeader {
    fn from(value: &DosHeader) -> Self {
        Self { 
            magic: std::str::from_utf8(&value.e_magic.value.to_le_bytes())
                    .unwrap_or("ERR")
                    .trim_matches('\0') //has trailing NULL bytes
                    .to_string(),
            e_lfanew: value.e_lfanew.value, 
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="file_header")]
struct MinFileHeader {
    pub magic: String,
    #[serde(rename="machine_type")]
    pub machine: MachineType,
    #[serde(rename="number_of_sections")]
    pub sections: u16,
    pub timestamp: DateTime<Utc>,
    #[serde(rename="pointer_to_symbol_table")]
    pub sym_ptr: u32,
    #[serde(rename="number_of_symbols")]
    pub symbols: u32,
    #[serde(rename="size_of_optional_header")]
    pub optional_header_size: u16,
    pub charactristics: file::Flags,
}

impl From<&FileHeader> for MinFileHeader {
    fn from(value: &FileHeader) -> Self {
        Self { 
            magic: std::str::from_utf8(&value.magic.value.to_le_bytes())
                    .unwrap_or("ERR")
                    .trim_matches('\0') //magic has traling NULL bytes 
                    .to_string(), 
            machine: value.machine.value, 
            sections: value.sections.value, 
            timestamp: value.timestamp.value, 
            sym_ptr: value.symbol_table_ptr.value, 
            symbols: value.symbols.value, 
            optional_header_size: value.optional_header_size.value, 
            charactristics: file::Flags::from_bits_truncate(value.charactristics.value),
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="optional_header")]
pub struct MinOptionalHeader32 {
    pub magic: optional::ImageType,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: optional::SubSystem,
    pub dll_charactristics: optional::Flags,
    pub number_of_rva_and_sizes: u32,
}

impl From<&OptionalHeader32> for MinOptionalHeader32 {
    fn from(value: &OptionalHeader32) -> Self {
        Self { 
            magic: value.magic.value, 
            major_linker_version: value.major_linker_ver.value, 
            minor_linker_version: value.minor_linker_ver.value, 
            size_of_code: value.sizeof_code.value, 
            size_of_initialized_data: value.sizeof_initiailized_data.value, 
            size_of_uninitialized_data: value.sizeof_uninitiailized_data.value,
            address_of_entry_point: value.address_of_entry_point.value, 
            base_of_code: value.base_of_code.value,
            base_of_data: value.base_of_data.value,
            image_base: value.image_base.value, 
            major_os_version: value.major_os_version.value,
            minor_os_version: value.minor_os_version.value,
            major_subsystem_version: value.major_subsystem_version.value,
            minor_subsystem_version: value.minor_subsystem_version.value,
            size_of_image: value.sizeof_image.value, 
            size_of_headers: value.sizeof_headers.value, 
            checksum: value.checksum.value, 
            subsystem: value.subsystem.value, 
            dll_charactristics: optional::Flags::from_bits_retain(value.dll_charactristics.value), 
            number_of_rva_and_sizes:  value.number_of_rva_and_sizes.value
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename="optional_header")]
pub struct MinOptionalHeader64 {
    pub magic: optional::ImageType,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: optional::SubSystem,
    pub dll_charactristics: optional::Flags,
    pub number_of_rva_and_sizes: u32,
}

impl From<&OptionalHeader64> for MinOptionalHeader64 {
    fn from(value: &OptionalHeader64) -> Self {
        Self { 
            magic: value.magic.value, 
            major_linker_version: value.major_linker_ver.value, 
            minor_linker_version: value.minor_linker_ver.value, 
            size_of_code: value.sizeof_code.value, 
            size_of_initialized_data: value.sizeof_initiailized_data.value, 
            size_of_uninitialized_data: value.sizeof_uninitiailized_data.value,
            address_of_entry_point: value.address_of_entry_point.value, 
            base_of_code: value.base_of_code.value,
            image_base: value.image_base.value, 
            major_os_version: value.major_os_version.value,
            minor_os_version: value.minor_os_version.value,
            major_subsystem_version: value.major_subsystem_version.value,
            minor_subsystem_version: value.minor_subsystem_version.value,
            size_of_image: value.sizeof_image.value, 
            size_of_headers: value.sizeof_headers.value, 
            checksum: value.checksum.value, 
            subsystem: value.subsystem.value, 
            dll_charactristics: optional::Flags::from_bits_retain(value.dll_charactristics.value), 
            number_of_rva_and_sizes:  value.number_of_rva_and_sizes.value
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename="optional_header")]
pub enum MinOptionalHeader {
    #[serde(untagged)]
    X86(MinOptionalHeader32),
    #[serde(untagged)]
    X64(MinOptionalHeader64),
}


#[derive(Debug, Serialize)]
#[serde(rename="section")]
pub struct MinSectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    #[serde(rename="size_of_raw_data")]
    pub sizeof_raw_data: u32,
    #[serde(rename="pointer_to_raw_data")]
    pub raw_data_ptr: u32,
    pub charactristics: section::Flags,
}

impl From<&SectionHeader> for MinSectionHeader {
    fn from(value: &SectionHeader) -> Self {
        Self { 
            name: String::from_utf8(value.name.value.to_vec())
                    .unwrap_or("ERR".to_string())
                    .trim_end_matches('\0') //section name usually has trailing NULL bytes.
                    .to_string(), 
            virtual_size: value.virtual_size.value,
            virtual_address: value.virtual_address.value,
            sizeof_raw_data: value.sizeof_raw_data.value,
            raw_data_ptr: value.raw_data_ptr.value,
            charactristics: section::Flags::from_bits_retain(value.charactristics.value),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_test::{assert_ser_tokens, Configure, Token};

    use crate::{pe::{dos::DosHeader, file::FileHeader, optional, section::parse_sections, ser::min::MinSectionHeader}, types::Header};
    use super::{MinFileHeader, MinOptionalHeader, MinOptionalHeader32, MinOptionalHeader64};

    const RAW_DOS_BYTES: [u8; 64] = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 
                                    0x00, 0x00, 0xB8, 0x00, 00, 00, 00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 0xF8, 00, 00, 00];
    #[test]
    fn serialize_dos(){
        let buf = RAW_DOS_BYTES;
        let dos_header = DosHeader::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid());

        let min_dos = super::MinDosHeader::from(&dos_header);

        assert_ser_tokens(&min_dos, &[
            Token::Struct { name: "dos_header", len: 2 },
            
            Token::String("magic"),
            Token::String("MZ"),

            Token::String("e_lfanew"),
            Token::U32(0xf8),

            Token::StructEnd
        ])
    }

    #[cfg(feature="json")]
    #[test]
    fn min_dos_to_json() {

        let buf = RAW_DOS_BYTES;
        let dos_header = DosHeader::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid());

        let min_dos = super::MinDosHeader::from(&dos_header);
        let jstr = serde_json::to_string_pretty(&min_dos).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains("\"magic\": \"MZ\""));
        assert!(jstr.contains("\"e_lfanew\": 248"));
    }

    const RAW_FILE_BYTES: [u8; 24] = [
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 0xA5, 0xE6, 0xE4, 0x61, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00 ];

    #[test]
    fn serialize_file() {
        let file_hdr = FileHeader::parse_bytes(&RAW_FILE_BYTES, 0).unwrap();
        assert!(file_hdr.is_valid());

        let min_file = super::MinFileHeader::from(&file_hdr);

        assert_ser_tokens(&min_file.readable(), &[
            Token::Struct { name: "file_header", len: 8 },
            
            Token::String("magic"),
            Token::String("PE"),

            Token::String("machine_type"),
            Token::UnitVariant { name: "MachineType", variant: "AMD64" },

            Token::String("number_of_sections"),
            Token::U16(5),

            Token::String("timestamp"),
            Token::String("2022-01-17T03:46:45Z"),

            Token::String("pointer_to_symbol_table"),
            Token::U32(0),

            Token::String("number_of_symbols"),
            Token::U32(0),

            Token::String("size_of_optional_header"),
            Token::U16(240),

            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("EXECUTABLE | LARGE_ADDRESS_AWARE"),

            Token::StructEnd,
        ])
    }

    #[cfg(feature="json")]
    #[test]
    fn min_file_to_json() {
        let file_hdr = FileHeader::parse_bytes(&RAW_FILE_BYTES, 0).unwrap();
        assert!(file_hdr.is_valid());

        let min_file = MinFileHeader::from(&file_hdr);
        let jstr = serde_json::to_string_pretty(&min_file).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains("\"charactristics\": \"EXECUTABLE | LARGE_ADDRESS_AWARE\""));
    }

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

    #[test]
    fn serialize_opt_hdr_32() {
        let opt = optional::x86::OptionalHeader32::parse_bytes(&RAW_OPT32_BYTES, 0x128).unwrap();
        assert!(opt.is_valid());

        let min_opt = MinOptionalHeader::X86(MinOptionalHeader32::from(&opt));

        assert_ser_tokens(&min_opt.readable(), &[
            Token::Struct { name: "optional_header", len: 20 },

            Token::String("magic"),
            Token::UnitVariant { name: "ImageType", variant: "PE32"},

            Token::String("major_linker_version"),
            Token::U8(14),

            Token::String("minor_linker_version"),
            Token::U8(0),

            Token::String("size_of_code"),
            Token::U32(0xbc00),

            Token::String("size_of_initialized_data"),
            Token::U32(0xec00),

            Token::String("size_of_uninitialized_data"),
            Token::U32(0),

            Token::String("address_of_entry_point"),
            Token::U32(0x209b),

            Token::String("base_of_code"),
            Token::U32(0x1000),

            Token::String("base_of_data"),
            Token::U32(0xd000),

            Token::String("image_base"),
            Token::U32(0x00400000),

            Token::String("major_os_version"),
            Token::U16(6),

            Token::String("minor_os_version"),
            Token::U16(0),

            Token::String("major_subsystem_version"),
            Token::U16(6),

            Token::String("minor_subsystem_version"),
            Token::U16(0),

            Token::String("size_of_image"),
            Token::U32(0x1e000),

            Token::String("size_of_headers"),
            Token::U32(0x400),

            Token::String("checksum"),
            Token::U32(0x1e2f1),

            Token::String("subsystem"),
            Token::UnitVariant { name: "SubSystem", variant: "WINDOWS_GUI" },

            Token::String("dll_charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE"),

            Token::String("number_of_rva_and_sizes"),
            Token::U32(16),

            Token::StructEnd,
        ]);
    }

    #[cfg(feature="json")]
    #[test]
    fn opt32_to_json() {
        let opt = optional::x86::OptionalHeader32::parse_bytes(&RAW_OPT32_BYTES, 0x128).unwrap();
        assert!(opt.is_valid());

        let min_opt = MinOptionalHeader::X86(MinOptionalHeader32::from(&opt));
        let jstr = serde_json::to_string_pretty(&min_opt).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains("\"dll_charactristics\": \"DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE\""));
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

    #[test]
    fn serialize_opt_hdr_64() {
        let opt = optional::x64::OptionalHeader64::parse_bytes(&RAW_OPT64_BYTES, 0x108).unwrap();
        assert!(opt.is_valid());

        let min_opt = MinOptionalHeader::X64(MinOptionalHeader64::from(&opt));

        assert_ser_tokens(&min_opt.readable(), &[
            Token::Struct { name: "optional_header", len: 19 },

            Token::String("magic"),
            Token::UnitVariant { name: "ImageType", variant: "PE32+"},

            Token::String("major_linker_version"),
            Token::U8(14),

            Token::String("minor_linker_version"),
            Token::U8(0x1c),

            Token::String("size_of_code"),
            Token::U32(0x37e00),

            Token::String("size_of_initialized_data"),
            Token::U32(0x14000),

            Token::String("size_of_uninitialized_data"),
            Token::U32(0),

            Token::String("address_of_entry_point"),
            Token::U32(0x37174),

            Token::String("base_of_code"),
            Token::U32(0x1000),

            Token::String("image_base"),
            Token::U64(0x0000000140000000),

            Token::String("major_os_version"),
            Token::U16(6),

            Token::String("minor_os_version"),
            Token::U16(0),

            Token::String("major_subsystem_version"),
            Token::U16(6),

            Token::String("minor_subsystem_version"),
            Token::U16(0),

            Token::String("size_of_image"),
            Token::U32(0x4f000),

            Token::String("size_of_headers"),
            Token::U32(0x400),

            Token::String("checksum"),
            Token::U32(0),

            Token::String("subsystem"),
            Token::UnitVariant { name: "SubSystem", variant: "WINDOWS_CUI" },

            Token::String("dll_charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE"),

            Token::String("number_of_rva_and_sizes"),
            Token::U32(16),

            Token::StructEnd,
        ]);
    }


    #[cfg(feature="json")]
    #[test]
    fn opt64_to_json() {
        let opt = optional::x64::OptionalHeader64::parse_bytes(&RAW_OPT64_BYTES, 0x108).unwrap();
        assert!(opt.is_valid());

        let min_opt = MinOptionalHeader::X64(MinOptionalHeader64::from(&opt));
        let jstr = serde_json::to_string_pretty(&min_opt).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains("\"dll_charactristics\": \"HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE\""));
    }

    //Tests for section header.
    const RAW_SECTION_BYTES: [u8; 240] = [
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
    fn serialize_sections() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208).unwrap();
        assert_eq!(sections.len(), 6);

        let min_secions: Vec<MinSectionHeader> = sections.into_iter().map(|hs| MinSectionHeader::from(&hs.value)).collect();
        assert_ser_tokens(&min_secions.readable(), &[
            Token::Seq { len: Some(6) },

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".text"),
            Token::String("virtual_size"),
            Token::U32(0xbbeb),
            Token::String("virtual_address"),
            Token::U32(0x00001000),
            Token::String("size_of_raw_data"),
            Token::U32(0x0000bc00),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00000400),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("CODE | MEM_EXECUTE | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".rdata"),
            Token::String("virtual_size"),
            Token::U32(0x5f8e),
            Token::String("virtual_address"),
            Token::U32(0x0000d000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00006000),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x0000c000),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".data"),
            Token::String("virtual_size"),
            Token::U32(0x1378),
            Token::String("virtual_address"),
            Token::U32(0x00013000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00000800),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00012000),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ | MEM_WRITE"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".gfids"),
            Token::String("virtual_size"),
            Token::U32(0xdc),
            Token::String("virtual_address"),
            Token::U32(0x00015000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00000200),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00012800),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".rsrc"),
            Token::String("virtual_size"),
            Token::U32(0x000064e8),
            Token::String("virtual_address"),
            Token::U32(0x00016000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00006600),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00012a00),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".reloc"),
            Token::String("virtual_size"),
            Token::U32(0x00000f98),
            Token::String("virtual_address"),
            Token::U32(0x0001d000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00001000),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00019000),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ"),
            Token::StructEnd,

            Token::SeqEnd,
        ])
    }

    #[test]
    fn sections_to_json() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208).unwrap();
        assert_eq!(sections.len(), 6);

        let min_secions: Vec<MinSectionHeader> = sections.into_iter().map(|hs| MinSectionHeader::from(&hs.value)).collect();
        let jstr = serde_json::to_string_pretty(&min_secions).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains(".text"));
    }
}
