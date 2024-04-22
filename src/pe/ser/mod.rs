use serde::Serialize;

use crate::types::HeaderField;

use super::{
    import::{x64::ImportLookup64, x86::ImportLookup32, ImportLookup}, 
    optional::{DataDirectory, DirectoryType}
};

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

pub type DataDirVec = Vec<HeaderField<DataDirectory>>;

fn unwrap_data_dir_header(dirs: &DataDirVec) -> Vec<DataDirValue> {
    let mut res: Vec<DataDirValue> = vec![];
    
    for hdr in dirs { 
        let dir = &hdr.value;
        if dir.size.value != 0 {
            res.push(DataDirValue {
                member: dir.member,
                rva: dir.rva.value,
                size: dir.size.value,
            })
        }
    }

    res
}


/** **V**alue **O**nly variant of `ImportLookup`s.  
  For every member, takes only `value` form `HeaderField`. 
*/
#[derive(Debug, Serialize)]
#[serde(rename="ImportLookup")]
pub struct ImportLookupVO {
    #[serde(skip_serializing_if="Option::is_none")]
    pub ordinal: Option<u16>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub name: Option<String>
}

impl From<&ImportLookup32> for ImportLookupVO{
    fn from(value: &ImportLookup32) -> Self {
        Self { 
            ordinal: value.ordinal, 
            name: if let Some(iname)  = &value.iname {
                Some(iname.value.name.value.clone())
            }
            else {None}
        }
    }
}

impl From<&ImportLookup64> for ImportLookupVO{
    fn from(value: &ImportLookup64) -> Self {
        Self { 
            ordinal: value.ordinal, 
            name: if let Some(iname)  = &value.iname {
                Some(iname.value.name.value.clone())
            }
            else {None}
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


#[cfg(test)]
mod test {
    use serde_test::{assert_ser_tokens, Token};

    use crate::pe::optional::parse_data_directories;

    use super::unwrap_data_dir_header;

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
        let dirs_vo = unwrap_data_dir_header(&dirs);

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
        let dirs_vo = unwrap_data_dir_header(&dirs);

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
}
