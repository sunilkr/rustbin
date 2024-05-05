use serde::Serialize;

use super::{export::Export, optional::{DataDirectory, DirectoryType}, relocs::{Reloc, RelocBlock}};

pub mod min;

#[derive(Debug, Serialize)]
#[serde(rename="data_directory")]
pub struct DataDirValue {
    #[serde(rename="type")]
    pub member: DirectoryType,
    pub rva: u32,
    pub size: u32,
}

impl From<&DataDirectory> for DataDirValue {
    fn from(value: &DataDirectory) -> Self {
        Self { member: value.member, rva: value.rva.value, size: value.size.value }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="export")]
pub struct ExportValue {
    pub name: String,
    #[serde(rename="rva")]
    pub address: u32,
    pub ordinal: u16,
}

impl From<&Export> for ExportValue {
    fn from(value: &Export) -> Self {
        Self { 
            name: value.name.value.clone(), 
            address: value.address.value, 
            ordinal: value.ordinal.value 
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="relocation_block")]
pub struct RelocBlockValue {
    pub virtual_address : u32,
    pub size : u32,
    pub relocations : Vec<Reloc>,
}


impl From<&RelocBlock> for RelocBlockValue {
    fn from(value: &RelocBlock) -> Self {
        Self { 
            virtual_address: value.va.value, 
            size: value.size.value, 
            relocations: value.relocs
                .iter()
                .map(|rel| rel.value.clone())
                .collect()
        }
    }
}


#[cfg(test)]
mod tests {
    use serde_test::{assert_ser_tokens, Token};

    use crate::{pe::{optional::parse_data_directories, relocs::{self, RelocBlock}}, types::Header};

    use super::{DataDirValue, RelocBlockValue};

    const RAW_DATA_DIR_BYTES: [u8; 128] = [
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
    fn ser_data_dirs() {
        let start = 0x188;        
        let dirs = parse_data_directories(&RAW_DATA_DIR_BYTES, 0x10, start).unwrap();
        let dirs_vo = dirs
            .iter()
            .filter(|dir| dir.value.size.value > 0)
            .map(|dir| DataDirValue::from(&dir.value))
            .collect::<Vec<DataDirValue>>();

        assert_ser_tokens(&dirs_vo, &[
            Token::Seq { len: Some(7) },

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Import" },
            Token::String("rva"),
            Token::U32(0x000126DC),
            Token::String("size"),
            Token::U32(0x00000050),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Resource" },
            Token::String("rva"),
            Token::U32(0x00016000),
            Token::String("size"),
            Token::U32(0x000064E8),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Security" },
            Token::String("rva"),
            Token::U32(0x0001A000),
            Token::String("size"),
            Token::U32(0x00001EB8),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Relocation" },
            Token::String("rva"),
            Token::U32(0x0001D000),
            Token::String("size"),
            Token::U32(0x00000F98),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Debug" },
            Token::String("rva"),
            Token::U32(0x00011D80),
            Token::String("size"),
            Token::U32(0x00000070),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "Configuration" },
            Token::String("rva"),
            Token::U32(0x00011DF0),
            Token::String("size"),
            Token::U32(0x00000040),
            Token::StructEnd,

            Token::Struct { name: "data_directory", len: 3 },
            Token::String("type"),
            Token::UnitVariant { name: "DirectoryType", variant: "ImportAddressTable" },
            Token::String("rva"),
            Token::U32(0x0000D000),
            Token::String("size"),
            Token::U32(0x00000174),
            Token::StructEnd,
            
            Token::SeqEnd,
        ]);
    }


    #[cfg(feature="json")]
    #[test]
    fn dirs_to_json() {
        let start = 0x188;        
        let dirs = parse_data_directories(&RAW_DATA_DIR_BYTES, 0x10, start).unwrap();
        let dirs_vo = dirs
            .iter()
            .filter(|dir| dir.value.size.value > 0)
            .map(|dir| DataDirValue::from(&dir.value))
            .collect::<Vec<DataDirValue>>();

        let jstr = serde_json::to_string_pretty(&dirs_vo).unwrap();

        //eprintln!("{jstr}");
        assert!(jstr.contains("\"type\": \"Import\","));
        assert!(jstr.contains("\"rva\": 75484,"));
        assert!(jstr.contains("\"type\": \"Resource\","));
        assert!(jstr.contains("\"type\": \"Security\","));
        assert!(jstr.contains("\"type\": \"Relocation\","));
        assert!(jstr.contains("\"type\": \"Debug\","));
        assert!(jstr.contains("\"type\": \"Configuration\","));
        assert!(jstr.contains("\"type\": \"ImportAddressTable\","));
    }

    //Relocs tests
    const RAW_RELOCS: [u8; 12] = [
        0x00, 0x10, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xC8, 0xA2, 0x38, 0xA4
    ];

    const RELOCS_OFFSET: u64 = 0x141fc;

    #[test]
    fn serealize_relocs() {
        let mut relocs = RelocBlock::parse_bytes(&RAW_RELOCS[..8], RELOCS_OFFSET).unwrap();
        relocs.parse_relocs(&RAW_RELOCS[8..], RELOCS_OFFSET + relocs::HEADER_LENGTH).unwrap();

        let reloc_vo = RelocBlockValue::from(&relocs);

        assert_ser_tokens(&reloc_vo, &[
            Token::Struct { name: "relocation_block", len: 3 },

            Token::String("virtual_address"),
            Token::U32(0x11000),

            Token::String("size"),
            Token::U32(12),

            Token::String("relocations"),
            Token::Seq { len: Some(2) },

            Token::Struct { name: "relocation", len: 2 },
            Token::String("type"),
            Token::UnitVariant { name: "RelocType", variant: "DIR64" },
            Token::String("offset"),
            Token::U16(0x2c8),
            Token::StructEnd,

            Token::Struct { name: "relocation", len: 2 },
            Token::String("type"),
            Token::UnitVariant { name: "RelocType", variant: "DIR64" },
            Token::String("offset"),
            Token::U16(0x438),
            Token::StructEnd,

            Token::SeqEnd,
            Token::StructEnd,
        ])
    }
    

    #[cfg(feature="json")]
    #[test]
    fn reloc_to_json() {
        let mut relocs = RelocBlock::parse_bytes(&RAW_RELOCS[..8], RELOCS_OFFSET).unwrap();
        relocs.parse_relocs(&RAW_RELOCS[8..], RELOCS_OFFSET + relocs::HEADER_LENGTH).unwrap();

        let reloc_vo = RelocBlockValue::from(&relocs);

        let jstr = serde_json::to_string_pretty(&reloc_vo).unwrap();
        //eprintln!("{jstr}");

        assert!(jstr.contains("\"offset\": 712"));
        assert!(jstr.contains("\"offset\": 1080"));
    }
}
