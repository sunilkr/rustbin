use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::pe::{
    dos::DosHeader, 
    export::ExportDirectory, 
    file::{self, FileHeader, MachineType}, 
    import::{ImpLookup, ImportDescriptor, ImportLookup}, 
    optional::{self, x64::OptionalHeader64, x86::OptionalHeader32, OptionalHeader}, 
    rsrc::{ResourceDirectory, ResourceEntry, ResourceNode, ResourceType}, 
    section::{self, SectionHeader}, 
    PeImage};

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

impl From<&ImpLookup<u32>> for ImportLookupVO{
    fn from(value: &ImpLookup<u32>) -> Self {
        if let Some(iname)  = &value.iname {
            Self::Name(iname.value.name.value.clone())
        }
        else {
            Self::Ordinal(value.ordinal.unwrap_or_default())
        }
    }
}

impl From<&ImpLookup<u64>> for ImportLookupVO{
    fn from(value: &ImpLookup<u64>) -> Self {
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
            dll_name: if let Some(name_hdr) =  &value.name{
                name_hdr.value.clone()
            } 
            else { 
                String::from("ERR") 
            },

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
//#[serde(untagged)]
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
#[serde(rename="Entry")]
pub struct MinRsrcEntry {
    pub id: ResourceType,
    #[serde(flatten)]
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
mod tests;
