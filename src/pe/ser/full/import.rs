use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{pe::import::{ImpLookup, ImportDescriptor, ImportLookup, ImportName}, types::HeaderField};

use super::{hf_to_hfx, ByteEndian, HeaderFieldEx};

#[derive(Debug, Serialize)]
pub struct ImportDescriptorEx {
    #[serde(rename="import_lookup_table")]
    pub ilt: HeaderFieldEx<u32>,
    pub timestamp: HeaderFieldEx<DateTime<Utc>>,
    pub forwarder_chain: HeaderFieldEx<u32>,
    pub name_rva: HeaderFieldEx<u32>,
    pub first_thunk: HeaderFieldEx<u32>,
    #[serde(rename="dll_name")]
    pub name: Option<HeaderFieldEx<String>>,
    pub imports: Vec<ImportLookupEx>,
}

impl From<&ImportDescriptor> for ImportDescriptorEx{
    fn from(value: &ImportDescriptor) -> Self {
        Self { 
            ilt: hf_to_hfx(&value.ilt, ByteEndian::LE), 
            
            timestamp: HeaderFieldEx { 
                raw: ((value.timestamp.value.timestamp_millis() / 1000) as u32)
                    .to_le_bytes()
                    .to_vec(),
                value: value.timestamp.clone(),
            },

            forwarder_chain: hf_to_hfx(&value.forwarder_chain, ByteEndian::LE), 
            name_rva: hf_to_hfx(&value.name_rva, ByteEndian::LE), 
            first_thunk: hf_to_hfx(&value.first_thunk, ByteEndian::LE), 
            
            name: if let Some(name) = &value.name {
                Some(
                    HeaderFieldEx { raw: name.value.as_bytes().to_vec(), value: name.clone() }
                )
            } else { None },

            imports: value.imports
                .iter()
                .map(|il| ImportLookupEx::from(il))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum ImportLookupEx {
    #[serde(untagged)]
    X86(ImpLookupEx<u32>),
    #[serde(untagged)]
    X64(ImpLookupEx<u64>),
}

impl From<&ImportLookup> for ImportLookupEx {
    fn from(value: &ImportLookup) -> Self {
        match value {
            ImportLookup::X86(il) => ImportLookupEx::X86(ImpLookupEx::from(il)),
            ImportLookup::X64(il) => ImportLookupEx::X64(ImpLookupEx::from(il)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ImpLookupEx<T> {
    pub value: HeaderFieldEx<T>,
    pub is_ordinal: bool,
    #[serde(skip_serializing_if="Option::is_none")]
    pub ordinal: Option<u16>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub iname: Option<HeaderField<ImportNameEx>>,
}

impl From<&ImpLookup<u32>> for ImpLookupEx<u32> {
    fn from(value: &ImpLookup<u32>) -> Self {
        Self { 
            value: hf_to_hfx(&value.value, ByteEndian::LE), 
            is_ordinal: value.is_ordinal, 
            ordinal: value.ordinal, 
            iname: if let Some(il) = &value.iname {
                Some(
                    HeaderField { 
                        value: ImportNameEx::from(&il.value),
                        offset: il.offset,
                        rva: il.rva,
                        size: il.size,
                    }
                )
            }
            else { None }
        }
    }
}


impl From<&ImpLookup<u64>> for ImpLookupEx<u64> {
    fn from(value: &ImpLookup<u64>) -> Self {
        Self { 
            value: hf_to_hfx(&value.value, ByteEndian::LE), 
            is_ordinal: value.is_ordinal, 
            ordinal: value.ordinal, 
            iname: if let Some(il) = &value.iname {
                Some(
                    HeaderField { 
                        value: ImportNameEx::from(&il.value),
                        offset: il.offset,
                        rva: il.rva,
                        size: il.size,
                    }
                )
            }
            else { None }
        }
    }
}


#[derive(Debug, Serialize)]
pub struct ImportNameEx {
    pub hint: HeaderFieldEx<u16>,
    pub name: HeaderFieldEx<String>,
}

impl From<&ImportName> for ImportNameEx {
    fn from(value: &ImportName) -> Self {
        Self { 
            hint: hf_to_hfx(&value.hint, ByteEndian::LE),
            name: HeaderFieldEx { 
                raw: value.name.value.as_bytes().to_vec(),
                value: value.name.clone()
            } 
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::{pe::{import::ImportDirectory, optional::ImageType, section::parse_sections}, types::Header as _, utils::FragmentReader};

    use super::{ImportDescriptorEx, ImportLookupEx};


    #[test]
    fn ser_imports() {
        let sections = parse_sections(&RAW_SECTION_BYTES, SECTION_COUNT, SECTION_POS).unwrap();
        
        let mut imports = ImportDirectory::parse_bytes(RAW_IAT.to_vec(), IAT_OFFSET).unwrap();
    
        let mut reader = FragmentReader::new(RAW_IMPORT_NAMES.to_vec(), NAMES_OFFSET);
        for i in 0..imports.len() {
            let idesc = &mut imports[i].value;
            idesc.update_name(&sections, &mut reader).unwrap();
            idesc.parse_imports(&sections, ImageType::PE64, &mut reader).unwrap();
        }

        let full_imports = imports
            .iter()
            .map(|import| ImportDescriptorEx::from(&import.value))
            .collect::<Vec<ImportDescriptorEx>>();

        assert_eq!(full_imports.len(), 2);

        let dll_name = full_imports[0].name.as_ref().unwrap();
        assert_eq!(dll_name.value.size, 18); //include NULL byte
        assert_eq!(
            dll_name.raw,
            vec![0x6c,0x69,0x62,0x67,0x6c,0x69,0x62,0x2d,0x32,0x2e,0x30,0x2d,0x30,0x2e,0x64,0x6c,0x6c]
        );

        assert_eq!(full_imports[0].imports.len(), 2);
        let import = &full_imports[0].imports[0];
        match import {
            ImportLookupEx::X86(_) => assert!(false, "should have been parsed as x64"),
            ImportLookupEx::X64(imp) => {
                assert_eq!(imp.is_ordinal, false);
                assert_eq!(imp.ordinal, None);
                
                let iname = &imp.iname.as_ref().unwrap().value.name;
                assert_eq!(iname.value.size, 6); //include NULL byte
                assert_eq!(
                    iname.raw,
                    vec![0x67,0x5f,0x6c,0x6f,0x67]
                );

            },
        }

        let dll_name = full_imports[1].name.as_ref().unwrap();
        assert_eq!(dll_name.value.size, 13); //include NULL byte
        assert_eq!(
            dll_name.raw,
            vec![0x4b,0x45,0x52,0x4e,0x45,0x4c,0x33,0x32,0x2e,0x64,0x6c,0x6c]
        );
    }

    const SECTION_POS: u64 = 0x200;
    const SECTION_COUNT: u16 = 6;
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
}