

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::pe::{
    dos::DosHeader, export::ExportDirectory, file::{self, FileHeader, MachineType}, import::{x64::ImportLookup64, x86::ImportLookup32, ImportDescriptor, ImportLookup}, optional::{self, x64::OptionalHeader64, x86::OptionalHeader32, OptionalHeader}, rsrc::{ResourceDirectory, ResourceEntry, ResourceNode, ResourceType}, section::{self, SectionHeader}, PeImage
};

use super::{DataDirValue, ExportValue, RelocBlockValue, ResourceDataValue, ResourceStringValue};


#[derive(Debug, Serialize)]
pub struct MinPeImage {
    pub dos_header: MinDosHeader,
    pub file_hedaer: MinFileHeader,
    pub optional_header: MinOptionalHeader,
    pub data_directories: Vec<DataDirValue>,
    pub sections: Vec<MinSectionHeader>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub import_directories: Option<Vec<MinImportDescriptor>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub export_directory: Option<MinExportDirectory>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub relocations: Option<Vec<RelocBlockValue>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub resources: Option<MinRsrcDirectory>,
}

impl From<&PeImage> for MinPeImage {
    fn from(value: &PeImage) -> Self {
        Self { 
            dos_header: MinDosHeader::from(&value.dos.value),
            file_hedaer: MinFileHeader::from(&value.file.value),
            optional_header: MinOptionalHeader::from(&value.optional.value),
            
            data_directories: value.data_dirs.value
                .iter()
                .filter(|dir| dir.value.size.value > 0)
                .map(|dir| DataDirValue::from(&dir.value))
                .collect::<Vec<DataDirValue>>(),
            
            sections: value.sections.value
                .iter()
                .map(|s| MinSectionHeader::from(&s.value))
                .collect(),
            
            import_directories: if value.has_imports() {
                Some( 
                    value.imports.value
                    .iter()
                    .map(|id| MinImportDescriptor::from(&id.value))
                    .collect()
                )} else { Option::None },

            export_directory: if value.has_exports() {
                    Some(MinExportDirectory::from(&value.exports.value))
                } else { Option::None },
            
            relocations: if value.has_relocations() { 
                Some(
                    value.relocations.value.blocks
                    .iter()
                    .map(|rb| RelocBlockValue::from(&rb.value))
                    .collect() 
                )} else { Option::None },

            resources: if value.has_rsrc() {
                    Some( MinRsrcDirectory::from(&value.resources.value))
                } else { Option::None }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename="dos_header")]
pub struct MinDosHeader {
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
pub struct MinFileHeader {
    pub magic: String,
    #[serde(rename="machine_type")]
    pub machine: MachineType,
    #[serde(rename="number_of_sections")]
    pub sections: u16,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing)]
    #[serde(rename="pointer_to_symbol_table")]
    pub sym_ptr: u32,
    #[serde(skip_serializing)]
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


impl From<&OptionalHeader> for MinOptionalHeader {
    fn from(value: &OptionalHeader) -> Self {
        match value {
            OptionalHeader::X86(opt) => Self::X86(MinOptionalHeader32::from(opt)),
            OptionalHeader::X64(opt) => Self::X64(MinOptionalHeader64::from(opt)),
        }
    }
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



/** **V**alue **O**nly variant of `ImportLookup`s.  
  For every member, takes only `value` form `HeaderField`. 
*/
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ImportLookupVO {
    Ordinal(u16),
    Name(String),
}

impl From<&ImportLookup32> for ImportLookupVO{
    fn from(value: &ImportLookup32) -> Self {
        if let Some(iname)  = &value.iname {
            Self::Name(iname.value.name.value.clone())
        }
        else {
            Self::Ordinal(value.ordinal.unwrap_or_default())
        }
    }
}

impl From<&ImportLookup64> for ImportLookupVO{
    fn from(value: &ImportLookup64) -> Self {
        if let Some(iname)  = &value.iname {
            Self::Name(iname.value.name.value.clone())
        }
        else {
            Self::Ordinal(value.ordinal.unwrap_or_default())
        }
    }
}

impl From<&ImportLookup> for ImportLookupVO {
    fn from(value: &ImportLookup) -> Self {
        match value {
            ImportLookup::X86(import) => Self::from(import),
            ImportLookup::X64(import) => Self::from(import),
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="import_descriptor")]
pub struct MinImportDescriptor {
    pub dll_name: String,
    //#[serde(flatten)]
    pub functions: Vec<ImportLookupVO>,
}

impl From<&ImportDescriptor> for MinImportDescriptor {
    fn from(value: &ImportDescriptor) -> Self {
        Self { 
            dll_name: value.name.clone().unwrap_or(String::from("ERR")), 
            functions: value.imports
                .iter()
                .map(|i| ImportLookupVO::from(i))
                .collect()
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="export_directory")]
pub struct MinExportDirectory {
    pub timestamp: DateTime<Utc>,
    pub name: String, 
    pub exports: Vec<ExportValue>,
}

impl From<&ExportDirectory> for MinExportDirectory {
    fn from(value: &ExportDirectory) -> Self {
        Self { 
            timestamp: value.timestamp.value, 
            name: value.name.clone(), 
            exports: value.exports
                .iter()
                .map(|ex| ExportValue::from(ex))
                .collect(),
            }
    }
}



#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum MinRsrcNode {
    Str(ResourceStringValue),
    Data(ResourceDataValue),
    Dir(MinRsrcDirectory)
}

impl From<&ResourceNode> for MinRsrcNode {
    fn from(value: &ResourceNode) -> Self {
        match value {
            ResourceNode::Str(str) => Self::Str(ResourceStringValue::from(str)),
            ResourceNode::Data(data) => Self::Data(ResourceDataValue::from(data)),
            ResourceNode::Dir(dir) => Self::Dir(MinRsrcDirectory::from(dir)),
        }
    }
}


#[derive(Debug, Serialize)]
pub struct MinRsrcEntry {
    pub id: ResourceType,
    pub data: MinRsrcNode,
}

impl From<&ResourceEntry> for MinRsrcEntry {
    fn from(rsrc_entry: &ResourceEntry) -> Self {
        Self { id: rsrc_entry.id, data: MinRsrcNode::from(&rsrc_entry.data) }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="resource_directory")]
pub struct MinRsrcDirectory {
    #[serde(rename="number_of_named_entries")]
    pub named_entry_count: u16,
    #[serde(rename="number_of_id_entries")]
    pub id_entry_count: u16,
    pub entries: Vec<MinRsrcEntry>,
}


impl From<&ResourceDirectory> for MinRsrcDirectory {
    fn from(rsrc_dir: &ResourceDirectory) -> Self {
        Self { 
            named_entry_count: rsrc_dir.named_entry_count.value, 
            id_entry_count: rsrc_dir.id_entry_count.value, 
            entries:  rsrc_dir.entries
                .iter()
                .map(|e| MinRsrcEntry::from(e))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, 
        fs::OpenOptions, 
        io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom}
    };

    use serde_test::{assert_ser_tokens, Configure, Token};

    use crate::{
        pe::{
            dos::DosHeader, 
            export::ExportDirectory, 
            file::FileHeader, 
            import::ImportDirectory, 
            optional::{self, ImageType}, 
            section::parse_sections, 
            PeImage
        }, 
        types::Header, 
        utils::Reader
    };

    use super::{MinExportDirectory, MinFileHeader, MinOptionalHeader, MinOptionalHeader32, MinOptionalHeader64, MinImportDescriptor, MinPeImage, MinSectionHeader};

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
            Token::Struct { name: "file_header", len: 6 },
            
            Token::String("magic"),
            Token::String("PE"),

            Token::String("machine_type"),
            Token::UnitVariant { name: "MachineType", variant: "AMD64" },

            Token::String("number_of_sections"),
            Token::U16(5),

            Token::String("timestamp"),
            Token::String("2022-01-17T03:46:45Z"),

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
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x54, 0xAC, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xAE, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xEC, 0x64, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0xB2, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0xB8, 0x39, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00,
        0x00, 0x16, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xB8, 0x08, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x2E, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0xA8, 0x05, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3E, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42
    ];

    #[test]
    fn serialize_sections() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x200).unwrap();
        assert_eq!(sections.len(), 6);

        let min_secions: Vec<MinSectionHeader> = sections.into_iter().map(|hs| MinSectionHeader::from(&hs.value)).collect();
        assert_ser_tokens(&min_secions.readable(), &[
            Token::Seq { len: Some(6) },

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".text"),
            Token::String("virtual_size"),
            Token::U32(0x0000ac54),
            Token::String("virtual_address"),
            Token::U32(0x00001000),
            Token::String("size_of_raw_data"),
            Token::U32(0x0000ae00),
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
            Token::U32(0x000064ec),
            Token::String("virtual_address"),
            Token::U32(0x0000c000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00006600),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x0000b200),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".data"),
            Token::String("virtual_size"),
            Token::U32(0x000039b8),
            Token::String("virtual_address"),
            Token::U32(0x00013000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00001600),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00011800),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ | MEM_WRITE"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".pdata"),
            Token::String("virtual_size"),
            Token::U32(0x000008b8),
            Token::String("virtual_address"),
            Token::U32(0x00017000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00000a00),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00012e00),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".rsrc"),
            Token::String("virtual_size"),
            Token::U32(0x000005a8),
            Token::String("virtual_address"),
            Token::U32(0x00018000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00000600),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00013800),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_READ"),
            Token::StructEnd,

            Token::Struct { name: "section", len: 6 },
            Token::String("name"),
            Token::String(".reloc"),
            Token::String("virtual_size"),
            Token::U32(0x00000524),
            Token::String("virtual_address"),
            Token::U32(0x00019000),
            Token::String("size_of_raw_data"),
            Token::U32(0x00000600),
            Token::String("pointer_to_raw_data"),
            Token::U32(0x00013e00),
            Token::String("charactristics"),
            Token::NewtypeStruct { name: "Flags" },
            Token::Str("INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ"),
            Token::StructEnd,

            Token::SeqEnd,
        ])
    }

    #[cfg(feature="json")]
    #[test]
    fn sections_to_json() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208).unwrap();
        assert_eq!(sections.len(), 6);

        let min_secions: Vec<MinSectionHeader> = sections.into_iter().map(|hs| MinSectionHeader::from(&hs.value)).collect();
        let jstr = serde_json::to_string_pretty(&min_secions).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains(".text"));
    }

    //Tests for imports
    fn parse_and_validate_imports() -> crate::Result<Vec<MinImportDescriptor>> {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208)?;
        assert_eq!(sections.len(), 6);

        let mut imports = ImportDirectory::parse_bytes(&RAW_IAT, IAT_OFFSET)?;
        assert_eq!(imports.len(), 2);

        let mut reader = FragmentDataReader::new(&RAW_IMPORT_NAMES, NAMES_OFFSET);
        for i in 0..imports.len() {
            let idesc = &mut imports[i].value;
            idesc.update_name(&sections, &mut reader)?;
            idesc.parse_imports(&sections, ImageType::PE64, &mut reader)?;
        }

        assert_eq!(imports[0].value.name.as_ref().unwrap(), "libglib-2.0-0.dll");
        assert_eq!(imports[1].value.name.as_ref().unwrap(), "KERNEL32.dll");

        let min_imports: Vec<MinImportDescriptor> = imports
            .iter()
            .map(|id| MinImportDescriptor::from(&id.value))
            .collect();

        Ok(min_imports)
    }

    #[test]
    fn serialize_imports() {
        let min_imports = parse_and_validate_imports().unwrap();

        let mut tokens = vec![
            Token::Seq { len: Some(2) },
            Token::Struct { name: "import_descriptor", len: 2 },
            Token::String("dll_name"),
            Token::String("libglib-2.0-0.dll"),

            Token::String("functions"),
            Token::Seq { len: Some(2) },
            Token::String("g_log"),
            Token::String("g_assertion_message_expr"),
            Token::SeqEnd,
            Token::StructEnd,

            Token::Struct { name: "import_descriptor", len: 2 },
            Token::String("dll_name"),
            Token::String("KERNEL32.dll"),
            Token::String("functions"),
            Token::Seq { len: Some(63) },
        ];
        
        let kernel_fns = [
            "TlsGetValue", "CreateFileW", "CloseHandle", "GetCommandLineA", "GetCurrentThreadId", "IsDebuggerPresent", 
            "IsProcessorFeaturePresent", "GetLastError", "SetLastError", "EncodePointer", "DecodePointer", "ExitProcess", 
            "GetModuleHandleExW", "GetProcAddress", "MultiByteToWideChar", "WideCharToMultiByte", "GetProcessHeap", 
            "GetStdHandle", "GetFileType", "DeleteCriticalSection", "GetStartupInfoW", "GetModuleFileNameA", "HeapFree", 
            "QueryPerformanceCounter", "GetCurrentProcessId", "GetSystemTimeAsFileTime", "GetEnvironmentStringsW", 
            "FreeEnvironmentStringsW", "RtlCaptureContext", "RtlLookupFunctionEntry", "RtlVirtualUnwind", "UnhandledExceptionFilter", 
            "SetUnhandledExceptionFilter", "InitializeCriticalSectionAndSpinCount", "Sleep", "GetCurrentProcess", "TerminateProcess", 
            "TlsAlloc", "TlsSetValue", "TlsFree", "GetModuleHandleW", "RtlUnwindEx", "EnterCriticalSection", "LeaveCriticalSection", 
            "IsValidCodePage", "GetACP", "GetOEMCP", "GetCPInfo", "WriteFile", "GetModuleFileNameW", "LoadLibraryExW", 
            "HeapAlloc", "HeapReAlloc", "GetStringTypeW", "OutputDebugStringW", "HeapSize", "LCMapStringW", "FlushFileBuffers", 
            "GetConsoleCP", "GetConsoleMode", "SetStdHandle", "SetFilePointerEx", "WriteConsoleW"
        ];
 
        for fun in kernel_fns {
            tokens.push(Token::Str(fun));
        }

        tokens.push(Token::SeqEnd);
        tokens.push(Token::StructEnd);
        tokens.push(Token::SeqEnd);

        assert_ser_tokens(&min_imports, &tokens)
    }


    #[cfg(feature="json")]
    #[test]
    fn imports_to_json() {
        let min_imports = parse_and_validate_imports().unwrap();
        let jstr = serde_json::to_string_pretty(&min_imports).unwrap();
        //eprintln!("{jstr}");
        assert!(jstr.contains("KERNEL32.dll"))
    }


    const EXPORT_OFFSET: u64 = 0x10f30;
    const RAW_EXPORT_BYTES: [u8; 144] = [
        0x00, 0x00, 0x00, 0x00, 0x57, 0xBB, 0x3B, 0x56, 0x00, 0x00, 0x00, 0x00, 0x6C, 0x1D, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x58, 0x1D, 0x01, 0x00,
        0x60, 0x1D, 0x01, 0x00, 0x68, 0x1D, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x20, 0x10, 0x00, 0x00,
        0x81, 0x1D, 0x01, 0x00, 0x8F, 0x1D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x6C, 0x69, 0x62, 0x67,
        0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x2D, 0x32, 0x2E, 0x30, 0x2D, 0x30, 0x2E, 0x64, 0x6C, 0x6C,
        0x00, 0x67, 0x5F, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x5F, 0x69, 0x6E, 0x69, 0x74, 0x00, 0x67,
        0x5F, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x5F, 0x69, 0x6E, 0x69, 0x74, 0x5F, 0x77, 0x69, 0x74,
        0x68, 0x5F, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x5F, 0x6D, 0x75, 0x74,
        0x65, 0x78, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x1F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn serialize_exports() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208).unwrap();
        let mut exports = ExportDirectory::parse_bytes(&RAW_EXPORT_BYTES, EXPORT_OFFSET).unwrap();
        let mut reader = FragmentDataReader::new(&RAW_EXPORT_BYTES, EXPORT_OFFSET);
        exports.parse_exports(&sections, &mut reader).unwrap();

        let min_exports = MinExportDirectory::from(&exports);

        assert_ser_tokens(&min_exports, &[
            Token::Struct { name: "export_directory", len: 3 },
            
            Token::String("timestamp"),
            Token::String("2015-11-05T20:25:59Z"),

            Token::String("name"),
            Token::String("libgthread-2.0-0.dll"),

            Token::String("exports"),
            Token::Seq { len: Some(2) },
            
            Token::Struct { name: "export", len: 3 },
            Token::String("name"),
            Token::String("g_thread_init"),
            Token::String("rva"),
            Token::U32(0x1000),
            Token::String("ordinal"),
            Token::U16(0),
            Token::StructEnd,

            Token::Struct { name: "export", len: 3 },
            Token::String("name"),
            Token::String("g_thread_init_with_errorcheck_mutexes"),
            Token::String("rva"),
            Token::U32(0x1020),
            Token::String("ordinal"),
            Token::U16(1),
            Token::StructEnd,

            Token::SeqEnd,
            Token::StructEnd,
        ])
    }
    
    #[cfg(feature="json")]
    #[test]
    fn export_to_json() {
        let sections = parse_sections(&RAW_SECTION_BYTES, 6, 0x208).unwrap();
        let mut exports = ExportDirectory::parse_bytes(&RAW_EXPORT_BYTES, EXPORT_OFFSET).unwrap();
        let mut reader = FragmentDataReader::new(&RAW_EXPORT_BYTES, EXPORT_OFFSET);
        exports.parse_exports(&sections, &mut reader).unwrap();

        let min_exports = MinExportDirectory::from(&exports);
        let jstr = serde_json::to_string_pretty(&min_exports).unwrap();
        eprintln!("{jstr}");

        assert!(jstr.contains("g_thread_init"));
        assert!(jstr.contains("g_thread_init_with_errorcheck_mutexes"));
    }


    //Test full image
    #[cfg(feature="json")]
    #[test]
    fn pe_to_json() {
        let path = env::current_dir()
            .unwrap()
            .join("test-data")
            .join("test.dll");

        eprintln!("TargetPath: {path:?}");
        assert!(path.is_file());

        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .unwrap();

        let mut pe = PeImage::parse_file(&mut BufReader::new(file), 0).unwrap();
        pe.parse_import_directory().unwrap();
        pe.parse_exports().unwrap();
        pe.parse_relocations().unwrap();
        pe.parse_resources().unwrap();

        let min_pe = MinPeImage::from(&pe);
        
        let jstr = serde_json::to_string_pretty(&min_pe).unwrap();
        eprintln!("{jstr}");
    }


    //Import related RAW data.
    const IAT_OFFSET: u64 = 0x10fb8;

    const RAW_IAT: [u8; 64] = [
        0xF8, 0x1F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x20, 0x01, 0x00,
        0x00, 0xC2, 0x00, 0x00, 0xF8, 0x1D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xDE, 0x24, 0x01, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const NAMES_OFFSET: u64 = 0x10ff0;

    const RAW_IMPORT_NAMES: [u8; 1792] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xD0, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6E, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9E, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAE, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xBE, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCE, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xDE, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2A, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x52, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x70, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9A, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xBC, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xEC, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4E, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7C, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB6, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE6, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0E, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x36, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x54, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7A, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA4, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAE, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xBA, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xD2, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFA, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3C, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6C, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7C, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8E, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9E, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x24, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x10, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x27, 0x00, 0x67, 0x5F, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6F, 0x6E, 0x5F, 0x6D, 0x65,
	    0x73, 0x73, 0x61, 0x67, 0x65, 0x5F, 0x65, 0x78, 0x70, 0x72, 0x00, 0x00, 0x5C, 0x02, 0x67, 0x5F,
	    0x6C, 0x6F, 0x67, 0x00, 0x6C, 0x69, 0x62, 0x67, 0x6C, 0x69, 0x62, 0x2D, 0x32, 0x2E, 0x30, 0x2D,
	    0x30, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x8C, 0x01, 0x47, 0x65, 0x74, 0x43, 0x6F, 0x6D, 0x6D, 0x61,
	    0x6E, 0x64, 0x4C, 0x69, 0x6E, 0x65, 0x41, 0x00, 0xCB, 0x01, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72,
	    0x72, 0x65, 0x6E, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x49, 0x64, 0x00, 0x00, 0x02, 0x03,
	    0x49, 0x73, 0x44, 0x65, 0x62, 0x75, 0x67, 0x67, 0x65, 0x72, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6E,
	    0x74, 0x00, 0x06, 0x03, 0x49, 0x73, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x6F, 0x72, 0x46,
	    0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6E, 0x74, 0x00, 0x08, 0x02,
	    0x47, 0x65, 0x74, 0x4C, 0x61, 0x73, 0x74, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x00, 0x00, 0x80, 0x04,
	    0x53, 0x65, 0x74, 0x4C, 0x61, 0x73, 0x74, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x00, 0x00, 0xEE, 0x00,
	    0x45, 0x6E, 0x63, 0x6F, 0x64, 0x65, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x00, 0xCB, 0x00,
	    0x44, 0x65, 0x63, 0x6F, 0x64, 0x65, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x00, 0x1F, 0x01,
	    0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0x1D, 0x02, 0x47, 0x65,
	    0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x45, 0x78, 0x57,
	    0x00, 0x00, 0x4C, 0x02, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65,
	    0x73, 0x73, 0x00, 0x00, 0x69, 0x03, 0x4D, 0x75, 0x6C, 0x74, 0x69, 0x42, 0x79, 0x74, 0x65, 0x54,
	    0x6F, 0x57, 0x69, 0x64, 0x65, 0x43, 0x68, 0x61, 0x72, 0x00, 0x20, 0x05, 0x57, 0x69, 0x64, 0x65,
	    0x43, 0x68, 0x61, 0x72, 0x54, 0x6F, 0x4D, 0x75, 0x6C, 0x74, 0x69, 0x42, 0x79, 0x74, 0x65, 0x00,
	    0x51, 0x02, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x48, 0x65, 0x61, 0x70,
	    0x00, 0x00, 0x6B, 0x02, 0x47, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65,
	    0x00, 0x00, 0xFA, 0x01, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6C, 0x65, 0x54, 0x79, 0x70, 0x65, 0x00,
	    0xD2, 0x00, 0x44, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C,
	    0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x6A, 0x02, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61,
	    0x72, 0x74, 0x75, 0x70, 0x49, 0x6E, 0x66, 0x6F, 0x57, 0x00, 0x19, 0x02, 0x47, 0x65, 0x74, 0x4D,
	    0x6F, 0x64, 0x75, 0x6C, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x4E, 0x61, 0x6D, 0x65, 0x41, 0x00, 0x00,
	    0xD7, 0x02, 0x48, 0x65, 0x61, 0x70, 0x46, 0x72, 0x65, 0x65, 0x00, 0x00, 0xA9, 0x03, 0x51, 0x75,
	    0x65, 0x72, 0x79, 0x50, 0x65, 0x72, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x6E, 0x63, 0x65, 0x43, 0x6F,
	    0x75, 0x6E, 0x74, 0x65, 0x72, 0x00, 0xC7, 0x01, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65,
	    0x6E, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x00, 0x80, 0x02, 0x47, 0x65,
	    0x74, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x54, 0x69, 0x6D, 0x65, 0x41, 0x73, 0x46, 0x69, 0x6C,
	    0x65, 0x54, 0x69, 0x6D, 0x65, 0x00, 0xE1, 0x01, 0x47, 0x65, 0x74, 0x45, 0x6E, 0x76, 0x69, 0x72,
	    0x6F, 0x6E, 0x6D, 0x65, 0x6E, 0x74, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x73, 0x57, 0x00, 0x00,
	    0x67, 0x01, 0x46, 0x72, 0x65, 0x65, 0x45, 0x6E, 0x76, 0x69, 0x72, 0x6F, 0x6E, 0x6D, 0x65, 0x6E,
	    0x74, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x73, 0x57, 0x00, 0x18, 0x04, 0x52, 0x74, 0x6C, 0x43,
	    0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x1F, 0x04,
	    0x52, 0x74, 0x6C, 0x4C, 0x6F, 0x6F, 0x6B, 0x75, 0x70, 0x46, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F,
	    0x6E, 0x45, 0x6E, 0x74, 0x72, 0x79, 0x00, 0x00, 0x26, 0x04, 0x52, 0x74, 0x6C, 0x56, 0x69, 0x72,
	    0x74, 0x75, 0x61, 0x6C, 0x55, 0x6E, 0x77, 0x69, 0x6E, 0x64, 0x00, 0x00, 0xE2, 0x04, 0x55, 0x6E,
	    0x68, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x64, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6F, 0x6E,
	    0x46, 0x69, 0x6C, 0x74, 0x65, 0x72, 0x00, 0x00, 0xB3, 0x04, 0x53, 0x65, 0x74, 0x55, 0x6E, 0x68,
	    0x61, 0x6E, 0x64, 0x6C, 0x65, 0x64, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x46,
	    0x69, 0x6C, 0x74, 0x65, 0x72, 0x00, 0xEB, 0x02, 0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x6C, 0x69,
	    0x7A, 0x65, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F,
	    0x6E, 0x41, 0x6E, 0x64, 0x53, 0x70, 0x69, 0x6E, 0x43, 0x6F, 0x75, 0x6E, 0x74, 0x00, 0xC0, 0x04,
	    0x53, 0x6C, 0x65, 0x65, 0x70, 0x00, 0xC6, 0x01, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65,
	    0x6E, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0xCE, 0x04, 0x54, 0x65, 0x72, 0x6D,
	    0x69, 0x6E, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0x00, 0xD3, 0x04,
	    0x54, 0x6C, 0x73, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0xD5, 0x04, 0x54, 0x6C, 0x73, 0x47,
	    0x65, 0x74, 0x56, 0x61, 0x6C, 0x75, 0x65, 0x00, 0xD6, 0x04, 0x54, 0x6C, 0x73, 0x53, 0x65, 0x74,
	    0x56, 0x61, 0x6C, 0x75, 0x65, 0x00, 0xD4, 0x04, 0x54, 0x6C, 0x73, 0x46, 0x72, 0x65, 0x65, 0x00,
	    0x1E, 0x02, 0x47, 0x65, 0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x48, 0x61, 0x6E, 0x64, 0x6C,
	    0x65, 0x57, 0x00, 0x00, 0x25, 0x04, 0x52, 0x74, 0x6C, 0x55, 0x6E, 0x77, 0x69, 0x6E, 0x64, 0x45,
	    0x78, 0x00, 0xF2, 0x00, 0x45, 0x6E, 0x74, 0x65, 0x72, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61,
	    0x6C, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x3B, 0x03, 0x4C, 0x65, 0x61, 0x76,
	    0x65, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E,
	    0x00, 0x00, 0x0C, 0x03, 0x49, 0x73, 0x56, 0x61, 0x6C, 0x69, 0x64, 0x43, 0x6F, 0x64, 0x65, 0x50,
	    0x61, 0x67, 0x65, 0x00, 0x6E, 0x01, 0x47, 0x65, 0x74, 0x41, 0x43, 0x50, 0x00, 0x00, 0x3E, 0x02,
	    0x47, 0x65, 0x74, 0x4F, 0x45, 0x4D, 0x43, 0x50, 0x00, 0x00, 0x78, 0x01, 0x47, 0x65, 0x74, 0x43,
	    0x50, 0x49, 0x6E, 0x66, 0x6F, 0x00, 0x34, 0x05, 0x57, 0x72, 0x69, 0x74, 0x65, 0x46, 0x69, 0x6C,
	    0x65, 0x00, 0x1A, 0x02, 0x47, 0x65, 0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x46, 0x69, 0x6C,
	    0x65, 0x4E, 0x61, 0x6D, 0x65, 0x57, 0x00, 0x00, 0x40, 0x03, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69,
	    0x62, 0x72, 0x61, 0x72, 0x79, 0x45, 0x78, 0x57, 0x00, 0x00, 0xD3, 0x02, 0x48, 0x65, 0x61, 0x70,
	    0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x00, 0xDA, 0x02, 0x48, 0x65, 0x61, 0x70, 0x52, 0x65, 0x41, 0x6C,
	    0x6C, 0x6F, 0x63, 0x00, 0x70, 0x02, 0x47, 0x65, 0x74, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x54,
	    0x79, 0x70, 0x65, 0x57, 0x00, 0x00, 0x8C, 0x03, 0x4F, 0x75, 0x74, 0x70, 0x75, 0x74, 0x44, 0x65,
	    0x62, 0x75, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x57, 0x00, 0x00, 0xDC, 0x02, 0x48, 0x65,
	    0x61, 0x70, 0x53, 0x69, 0x7A, 0x65, 0x00, 0x00, 0x2F, 0x03, 0x4C, 0x43, 0x4D, 0x61, 0x70, 0x53,
	    0x74, 0x72, 0x69, 0x6E, 0x67, 0x57, 0x00, 0x00, 0x5D, 0x01, 0x46, 0x6C, 0x75, 0x73, 0x68, 0x46,
	    0x69, 0x6C, 0x65, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x73, 0x00, 0x00, 0xA0, 0x01, 0x47, 0x65,
	    0x74, 0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x43, 0x50, 0x00, 0x00, 0xB2, 0x01, 0x47, 0x65,
	    0x74, 0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x4D, 0x6F, 0x64, 0x65, 0x00, 0x00, 0x94, 0x04,
	    0x53, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x75, 0x04,
	    0x53, 0x65, 0x74, 0x46, 0x69, 0x6C, 0x65, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x45, 0x78,
	    0x00, 0x00, 0x33, 0x05, 0x57, 0x72, 0x69, 0x74, 0x65, 0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65,
	    0x57, 0x00, 0x52, 0x00, 0x43, 0x6C, 0x6F, 0x73, 0x65, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00,
	    0x8F, 0x00, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x57, 0x00, 0x4B, 0x45,
	    0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    struct FragmentDataReader<'a> {
        cursor: Cursor<&'a [u8]>,
        pos: u64,
    }
    
    impl<'a> FragmentDataReader<'a> {
        pub fn new(content: &'a[u8], pos: u64) -> Self {
            let cursor = Cursor::new(content);
            Self { cursor, pos }
        }
    }
    
    impl Reader for FragmentDataReader<'_> {
        fn read_string_at_offset(&mut self, offset: u64) -> crate::Result<String> {
            let mut buf:Vec<u8> = Vec::new();
            let new_offset = offset - self.pos;
            self.cursor.seek(SeekFrom::Start(new_offset))?;
            self.cursor.read_until(b'\0', &mut buf)?;
            Ok(String::from_utf8(buf[..(buf.len()-1)].to_vec())?)
        }
    
        fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> crate::Result<Vec<u8>> {
            let new_offset = offset - self.pos;
            let mut buf:Vec<u8> = vec![0; size];
            self.cursor.seek(SeekFrom::Start(new_offset))?;
            self.cursor.read_exact(&mut buf)?;
            Ok(buf)
        }
    }
}
