use std::mem::size_of;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{pe::file::{self, FileHeader, MachineType}, types::HeaderField};

use super::{hf_to_hfx, HeaderFieldEx};

#[derive(Debug, Serialize)]
pub struct FileHeaderEx {
    pub(crate) magic: HeaderFieldEx<u32>,
    #[serde(rename="machine_type")]
    pub(crate) machine: HeaderFieldEx<MachineType>,
    #[serde(rename="number_of_sections")]
    pub(crate) sections: HeaderFieldEx<u16>,
    pub(crate) timestamp: HeaderFieldEx<DateTime<Utc>>,
    #[serde(rename="pointer_to_symbol_table")]
    pub(crate) symbol_table_ptr: HeaderFieldEx<u32>,
    #[serde(rename="number_of_symbols")]
    pub(crate) symbols: HeaderFieldEx<u32>,
    #[serde(rename="size_of_optional_header")]
    pub(crate) optional_header_size: HeaderFieldEx<u16>,
    pub(crate) charactristics: HeaderFieldEx<file::Flags>,
}

impl From<&FileHeader> for FileHeaderEx {
    fn from(value: &FileHeader) -> Self {
        Self { 
            magic: hf_to_hfx(&value.magic, super::ByteEndian::LE),
            machine: HeaderFieldEx { 
                raw: (value.machine.value as u16).to_le_bytes().to_vec(), 
                value: value.machine.clone() 
            },
            sections: hf_to_hfx(&value.sections, super::ByteEndian::LE),
            timestamp: HeaderFieldEx { 
                raw: ((value.timestamp.value.timestamp_millis() / 1000) as u32) //value was read from u32 in *seconds*, so should be safe to truncate.
                    .to_le_bytes()
                    .to_vec(), 
                value: value.timestamp.clone()
            },
            symbol_table_ptr: hf_to_hfx(&value.symbol_table_ptr, super::ByteEndian::LE), 
            symbols: hf_to_hfx(&value.symbols, super::ByteEndian::LE), 
            optional_header_size: hf_to_hfx(&value.optional_header_size, super::ByteEndian::LE), 
            charactristics: HeaderFieldEx { 
                raw: value.charactristics.value.to_le_bytes().to_vec(), 
                value: HeaderField { 
                    value: file::Flags::from_bits_truncate(value.charactristics.value),
                    offset: value.charactristics.offset, 
                    rva: value.charactristics.rva,
                    size: size_of::<u16>() as u64,
                } 
            },
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{pe::file::FileHeader, types::Header};

    use super::FileHeaderEx;

    const RAW_BYTES: [u8; 24] = [
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 
        0xA5, 0xE6, 0xE4, 0x61, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00 
    ];

    #[test]
    fn from_file() {
        let file = FileHeader::parse_bytes(RAW_BYTES.to_vec(), 0).unwrap();
        let file_ex = FileHeaderEx::from(&file);

        assert_eq!(file_ex.magic.value, file.magic);
        assert_eq!(file_ex.magic.raw, vec![0x50, 0x45, 0x00, 0x00]);

        assert_eq!(file_ex.machine.value, file.machine);
        assert_eq!(file_ex.machine.raw, vec![0x64, 0x86]);

        assert_eq!(file_ex.sections.value, file.sections);
        assert_eq!(file_ex.sections.raw, vec![0x05, 0x00]);

        assert_eq!(file_ex.timestamp.value, file.timestamp);
        assert_eq!(file_ex.timestamp.raw, vec![0xA5, 0xE6, 0xE4, 0x61]);

        assert_eq!(file_ex.symbol_table_ptr.value, file.symbol_table_ptr);
        assert_eq!(file_ex.symbol_table_ptr.raw, vec![0; 4]);

        assert_eq!(file_ex.symbols.value, file.symbols);
        assert_eq!(file_ex.symbols.raw, vec![0; 4]);

        assert_eq!(file_ex.optional_header_size.value, file.optional_header_size);
        assert_eq!(file_ex.optional_header_size.raw, vec![0xF0, 0x00]);

        //assert_eq!(file_ex.charactristics.value, file.charactristics);
        assert_eq!(file_ex.charactristics.raw, vec![0x22, 0x00]);
    }


    #[cfg(feature="json")]
    #[test]
    fn to_json() {
        let file = FileHeader::parse_bytes(RAW_BYTES.to_vec(), 0).unwrap();
        let file_ex = FileHeaderEx::from(&file);

        let json = serde_json::to_string_pretty(&file_ex).unwrap();
        eprintln!("{json}");
    }
}
