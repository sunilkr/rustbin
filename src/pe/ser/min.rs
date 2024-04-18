use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::pe::{dos::DosHeader as ParsedDos, file::{self, FileHeader as ParsedFileHeader, MachineType}};

#[derive(Debug, Serialize)]
#[serde(rename="DosHeader")]
struct MinDosHeader {
    pub magic: String,
    pub e_lfanew: u32,    
}

impl From<&ParsedDos> for MinDosHeader {
    fn from(value: &ParsedDos) -> Self {
        Self { 
            magic: format!("{}", std::str::from_utf8(&value.e_magic.value.to_le_bytes()).unwrap_or("ERR").trim_matches('\0')),
            e_lfanew: value.e_lfanew.value, 
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="FileHeader")]
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

impl From<&ParsedFileHeader> for MinFileHeader {
    fn from(value: &ParsedFileHeader) -> Self {
        Self { 
            magic: format!("{}", std::str::from_utf8(&value.magic.value.to_le_bytes()).unwrap_or("ERR").trim_matches('\0')),
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


#[cfg(test)]
mod tests {
    use serde_test::{assert_ser_tokens, Configure, Token};

    use crate::{pe::{dos::DosHeader as ParsedDos, file::{self}}, types::Header};

    const RAW_DOS_BYTES: [u8; 64] = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 
                                    0x00, 0x00, 0xB8, 0x00, 00, 00, 00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 0xF8, 00, 00, 00];
    #[test]
    fn serialize_dos(){
        let buf = RAW_DOS_BYTES;
        let dos_header = ParsedDos::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid());

        let min_dos = super::MinDosHeader::from(&dos_header);

        assert_ser_tokens(&min_dos, &[
            Token::Struct { name: "DosHeader", len: 2 },
            
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
        let dos_header = ParsedDos::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid());

        let min_dos = super::MinDosHeader::from(&dos_header);
        let jstr = serde_json::to_string_pretty(&min_dos).unwrap();
        //eprintln!("{jstr}");
        assert!(jstr.contains("\"magic\": \"MZ\""));
        assert!(jstr.contains("\"e_lfanew\": 248"));
    }

    const RAW_FILE_BYTES: [u8; file::HEADER_LENGTH as usize] = [
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 0xA5, 0xE6, 0xE4, 0x61, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00 ];

    #[test]
    fn serialize_file() {
        let file_hdr = file::FileHeader::parse_bytes(&RAW_FILE_BYTES, 0).unwrap();
        assert!(file_hdr.is_valid());

        let min_file = super::MinFileHeader::from(&file_hdr);

        assert_ser_tokens(&min_file.readable(), &[
            Token::Struct { name: "FileHeader", len: 8 },
            
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
        let file_hdr = file::FileHeader::parse_bytes(&RAW_FILE_BYTES, 0).unwrap();
        assert!(file_hdr.is_valid());

        let min_file = super::MinFileHeader::from(&file_hdr);
        let jstr = serde_json::to_string_pretty(&min_file).unwrap();
        //eprintln!("{jstr}");
        assert!(jstr.contains("\"charactristics\": \"EXECUTABLE | LARGE_ADDRESS_AWARE\""));
    }
}
