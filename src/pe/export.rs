use std::{fmt::Display, io::{Error, Cursor}, mem::size_of};

use byteorder::{ReadBytesExt, LittleEndian};
use chrono::{DateTime, Utc};

use crate::{new_header_field, types::{Header, HeaderField, BufReadExt}};

use super::{section::{self, offset_to_rva, SectionTable}, PeError};

#[derive(Debug, Default, PartialEq)]
pub struct Export {
    pub name: HeaderField<String>,
    pub address: HeaderField<u32>,
    pub ordinal: HeaderField<u16>,
}

impl Display for Export {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (Ord: {}) @ {:#08x}",
            self.name, self.ordinal, self.address.value
        )
    }
}

pub const HEADER_LENGTH: u64 = 40;

#[derive(Debug, Default)]
pub struct ExportDirectory {
    pub charatristics: HeaderField<u32>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub major_version: HeaderField<u16>,
    pub minor_version: HeaderField<u16>,
    pub name_rva: HeaderField<u32>,
    pub base: HeaderField<u32>,
    pub number_of_functions: HeaderField<u32>,
    pub number_of_names: HeaderField<u32>,
    pub address_of_functions: HeaderField<u32>,
    pub address_of_names: HeaderField<u32>,
    pub address_of_name_ordinals: HeaderField<u32>,
    pub name: String,
    pub exports: Vec<Export>
}

impl ExportDirectory {
    fn new() -> Self {
        Default::default()
    }

    pub fn parse_exports(&mut self, sections: &SectionTable, reader: &mut impl BufReadExt) -> crate::Result<()> {
        let mut offset = section::rva_to_offset(sections, self.name_rva.value)
            .ok_or(PeError::InvalidRVA(self.name_rva.value.into()))?;
        self.name = reader.read_string_at_offset(offset.into())?;

        offset = section::rva_to_offset(sections, self.address_of_names.value)
            .ok_or(PeError::InvalidRVA(self.address_of_names.value.into()))?;
        let name_table = reader.read_bytes_at_offset(offset.into(), 
            self.number_of_names.value as usize * size_of::<u32>())?;

        let fn_offset = section::rva_to_offset(sections, self.address_of_functions.value)
            .ok_or(PeError::InvalidRVA(self.address_of_functions.value.into()))?;
        let function_table = reader.read_bytes_at_offset(fn_offset.into(), 
            self.number_of_functions.value as usize * size_of::<u32>())?;

        let ord_offset = section::rva_to_offset(sections, self.address_of_name_ordinals.value)
            .ok_or(PeError::InvalidRVA(self.address_of_name_ordinals.value.into()))?;
        let ordinal_table = reader.read_bytes_at_offset(ord_offset.into(), 
            self.number_of_functions.value as usize * size_of::<u16>())?;
        

        self.exports = Vec::with_capacity(self.number_of_functions.value as usize);
        let mut name_cursor = Cursor::new(name_table);
        let mut fn_cursor = Cursor::new(function_table);
        let mut ord_cursor = Cursor::new(ordinal_table);

        for i in 0..self.number_of_names.value {
            let mut export = Export::default();
            let name_rva = name_cursor.read_u32::<LittleEndian>()?;
            let name_offset = section::rva_to_offset(sections, name_rva)
                .ok_or(PeError::InvalidRVA(name_rva.into()))?;
            let name = reader.read_string_at_offset(name_offset.into())?;
            export.name = HeaderField{ value: name, rva:name_rva.into(), offset:name_offset.into() };

            let mut offset = (i as usize * size_of::<u32>()) as u64;
            export.address = HeaderField {
                value: fn_cursor.read_u32::<LittleEndian>()?, 
                rva: self.address_of_functions.value as u64 + offset,
                offset: fn_offset as u64 + offset,
            };

            offset = (i as usize * size_of::<u16>()) as u64;
            export.ordinal = HeaderField {
                value: ord_cursor.read_u16::<LittleEndian>()?,
                rva: self.address_of_name_ordinals.value as u64 + offset,
                offset: ord_offset as u64 + offset,
            };

            self.exports.push(export);
        }

        if self.number_of_functions.value > self.number_of_names.value {
            for i in 0..self.number_of_names.value {
                let mut export = Export::default();
                export.name = HeaderField{ value: "NO_NAME".to_string(), rva:0, offset:0 };
    
                let mut offset = (i as usize * size_of::<u32>()) as u64;
                export.address = HeaderField {
                    value: fn_cursor.read_u32::<LittleEndian>()?, 
                    rva: self.address_of_functions.value as u64 + offset,
                    offset: fn_offset as u64 + offset,
                };
    
                offset = (i as usize * size_of::<u16>()) as u64;
                export.ordinal = HeaderField {
                    value: ord_cursor.read_u16::<LittleEndian>()?,
                    rva: self.address_of_name_ordinals.value as u64 + offset,
                    offset: ord_offset as u64 + offset,
                };
    
                self.exports.push(export);
            }
        }

        Ok(())
    }

    pub fn fix_rvas(&mut self, sections: &SectionTable) -> crate::Result<()> {
        self.charatristics.rva = offset_to_rva(sections, self.charatristics.offset as u32)
            .ok_or(PeError::InvalidOffset(self.charatristics.offset.into()))?
            .into();
        
        self.timestamp.rva = offset_to_rva(sections, self.timestamp.offset as u32)
            .ok_or(PeError::InvalidOffset(self.timestamp.offset.into()))?
            .into();

        self.major_version.rva = offset_to_rva(sections, self.major_version.offset as u32)
            .ok_or(PeError::InvalidOffset(self.major_version.offset.into()))?
            .into();
        
        self.minor_version.rva = offset_to_rva(sections, self.minor_version.offset as u32)
            .ok_or(PeError::InvalidOffset(self.minor_version.offset.into()))?
            .into();
        
        self.name_rva.rva = offset_to_rva(sections, self.name_rva.offset as u32)
            .ok_or(PeError::InvalidOffset(self.name_rva.offset.into()))?
            .into();
        
        self.base.rva = offset_to_rva(sections, self.base.offset as u32)
            .ok_or(PeError::InvalidOffset(self.base.offset.into()))?
            .into();

        self.number_of_functions.rva = offset_to_rva(sections, self.number_of_functions.offset as u32)
            .ok_or(PeError::InvalidOffset(self.number_of_functions.offset.into()))?
            .into();
        
        self.number_of_names.rva = offset_to_rva(sections, self.number_of_names.offset as u32)
            .ok_or(PeError::InvalidOffset(self.number_of_names.offset.into()))?
            .into();

        self.address_of_functions.rva = offset_to_rva(sections, self.address_of_functions.offset as u32)
            .ok_or(PeError::InvalidOffset(self.address_of_functions.offset.into()))?
            .into();

        self.address_of_names.rva = offset_to_rva(sections, self.address_of_names.offset as u32)
            .ok_or(PeError::InvalidOffset(self.address_of_names.offset.into()))?
            .into();

        self.address_of_name_ordinals.rva = offset_to_rva(sections, self.address_of_name_ordinals.offset as u32)
            .ok_or(PeError::InvalidOffset(self.address_of_name_ordinals.offset.into()))?
            .into();

        Ok(())
    }

}


impl Header for ExportDirectory {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err(
                Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Not enough data. Expected {HEADER_LENGTH}, Found {bytes_len}")
                ).into()
            );
        }

        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;
        
        let mut exdir = Self::new();
        exdir.charatristics = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        
        let dt = cursor.read_u32::<LittleEndian>()?;
        let ts = DateTime::<Utc>::from_timestamp(dt.into(), 0).ok_or(PeError::InvalidTimestamp(dt.into()))?; //TODO: map to header specific error?
        exdir.timestamp = HeaderField{ value: ts, rva: offset, offset };
        offset += size_of::<u32>() as u64;

        exdir.major_version = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        exdir.minor_version = new_header_field!(cursor.read_u16::<LittleEndian>()?, offset);
        exdir.name_rva = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.base = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.number_of_functions = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.number_of_names = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.address_of_functions = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.address_of_names = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        exdir.address_of_name_ordinals = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        Ok(exdir)
    }

    fn is_valid(&self) -> bool {
        self.number_of_functions.value != 0 && self.address_of_functions.value != 0
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }
}


#[cfg(test)]
mod tests {
    use crate::{pe::section::{parse_sections, SectionTable}, types::{Header, HeaderField}, utils::FragmentReader};

    use super::{ExportDirectory, Export};


    #[test]
    fn parse_export_directory() {
        let raw_export_data = &EXPORTS_RAW[0..40];
        let ed = ExportDirectory::parse_bytes(raw_export_data.to_vec(), 0x3A00).unwrap();
        
        assert_eq!(ed.charatristics.value, 0);
        assert_eq!(ed.timestamp.value.format("%Y-%m-%d %H:%M:%S").to_string(), "2018-01-12 10:16:01");
        assert_eq!(ed.major_version.value, 0);
        assert_eq!(ed.minor_version.value, 0);
        assert_eq!(ed.name_rva.value, 0x000090b4);
        assert_eq!(ed.base.value, 1);
        assert_eq!(ed.number_of_functions.value, 0x0000000e);
        assert_eq!(ed.number_of_names.value, 0x0000000e);
        assert_eq!(ed.address_of_functions.value, 0x00009028);
        assert_eq!(ed.address_of_names.value, 0x00009060);
        assert_eq!(ed.address_of_name_ordinals.value, 0x00009098);
    }

    #[test]
    fn fix_rvas() {
        let sections = parse_section_header();
        let raw_export_data = &EXPORTS_RAW[0..40];
        let mut ed = ExportDirectory::parse_bytes(raw_export_data.to_vec(), 0x3A00).unwrap();
        ed.fix_rvas(&sections).unwrap();

        assert_eq!(ed.charatristics.rva, 0x00009000);
        assert_eq!(ed.timestamp.rva, 0x00009004);
        assert_eq!(ed.major_version.rva, 0x00009008);
        assert_eq!(ed.minor_version.rva, 0x0000900a);
        assert_eq!(ed.name_rva.rva, 0x0000900c);
        assert_eq!(ed.base.rva, 0x00009010);
        assert_eq!(ed.number_of_functions.rva, 0x00009014);
        assert_eq!(ed.number_of_names.rva, 0x00009018);
        assert_eq!(ed.address_of_functions.rva, 0x0000901c);
        assert_eq!(ed.address_of_names.rva, 0x00009020);
        assert_eq!(ed.address_of_name_ordinals.rva, 0x00009024);
    }

    #[test]
    fn parse_exports() {
        let exported_names = [
            Export {
                name: HeaderField { value: "__chk_fail".to_string(), offset: 0x3ac1, rva: 0x90c1 },
                address: HeaderField { value: 0x14b0, offset: 0x3a28, rva:0x9028 },
                ordinal: HeaderField { value: 0, offset: 0x3a98, rva: 0x9098 },
            },

            Export {
                name: HeaderField { value: "__gets_chk".to_string(), offset: 0x3acc, rva: 0x90cc },
                address: HeaderField { value: 0x14e0, offset: 0x3a2c, rva: 0x902c },
                ordinal: HeaderField { value: 1, offset: 0x3a9a, rva: 0x909a },
            },

            Export {
                name: HeaderField { value: "__memcpy_chk".to_string(), offset: 0x3ad7, rva: 0x90d7 },
                address: HeaderField { value: 0x1610, offset: 0x3a30, rva: 0x9030 },
                ordinal: HeaderField { value: 2, offset: 0x3a9c, rva: 0x909c },
            },

            Export {
                name: HeaderField { value: "__memmove_chk".to_string(), offset: 0x3ae4, rva: 0x90e4 },
                address: HeaderField { value: 0x1630, offset: 0x3a34, rva: 0x9034 },
                ordinal: HeaderField { value: 3, offset: 0x3a9e, rva: 0x909e },
            },
           
            Export {
                name: HeaderField { value: "__mempcpy_chk".to_string(), offset: 0x3af2, rva: 0x90f2 },
                address: HeaderField { value: 0x1650, offset: 0x3a38, rva: 0x9038 },
                ordinal: HeaderField { value: 4, offset: 0x3aa0, rva: 0x90a0 },
            },
           
            Export {
                name: HeaderField { value: "__memset_chk".to_string(), offset: 0x3b00, rva: 0x9100 },
                address: HeaderField { value: 0x1680, offset: 0x3a3c, rva: 0x903c },
                ordinal: HeaderField { value: 5, offset: 0x3aa2, rva: 0x90a2 },
            },

            Export {
                name: HeaderField { value: "__stack_chk_fail".to_string(), offset: 0x3b0d, rva: 0x910d },
                address: HeaderField { value: 0x1490, offset: 0x3a40, rva: 0x9040 },
                ordinal: HeaderField { value: 6, offset: 0x3aa4, rva: 0x90a4 },
            },

            Export {
                name: HeaderField { value: "__stack_chk_fail_local".to_string(), offset: 0x3b1e, rva: 0x911e },
                address: HeaderField { value: 0x14d0, offset: 0x3a44, rva: 0x9044 },
                ordinal: HeaderField { value: 7, offset: 0x3aa6, rva: 0x90a6 },
            },

            Export {
                name: HeaderField { value: "__stack_chk_guard".to_string(), offset: 0x3b35, rva: 0x9135 },
                address: HeaderField { value: 0x8020, offset: 0x3a48, rva: 0x9048 },
                ordinal: HeaderField { value: 8, offset: 0x3aa8, rva: 0x90a8 },
            },

            Export {
                name: HeaderField { value: "__stpcpy_chk".to_string(), offset: 0x3b47, rva: 0x9147 },
                address: HeaderField { value: 0x16a0, offset: 0x3a4c, rva: 0x904c },
                ordinal: HeaderField { value: 9, offset: 0x3aaa, rva: 0x90aa },
            },

            Export {
                name: HeaderField { value: "__strcat_chk".to_string(), offset: 0x3b54, rva: 0x9154 },
                address: HeaderField { value: 0x16f0, offset: 0x3a50, rva: 0x9050 },
                ordinal: HeaderField { value: 10, offset: 0x3aac, rva: 0x90ac },
            },

            Export {
                name: HeaderField { value: "__strcpy_chk".to_string(), offset: 0x3b61, rva: 0x9161 },
                address: HeaderField { value: 0x1750, offset: 0x3a54, rva: 0x9054 },
                ordinal: HeaderField { value: 11, offset: 0x3aae, rva: 0x90ae },
            },

            Export {
                name: HeaderField { value: "__strncat_chk".to_string(), offset: 0x3b6e, rva: 0x916e },
                address: HeaderField { value: 0x1790, offset: 0x3a58, rva: 0x9058 },
                ordinal: HeaderField { value: 12, offset: 0x3ab0, rva: 0x90b0 },
            },

            Export {
                name: HeaderField { value: "__strncpy_chk".to_string(), offset: 0x3b7c, rva: 0x917c },
                address: HeaderField { value: 0x18d0, offset: 0x3a5c, rva: 0x905c },
                ordinal: HeaderField { value: 13, offset: 0x3ab2, rva: 0x90b2 },
            },
        ];

        let sections = parse_section_header();
        let raw_export_data = &EXPORTS_RAW[0..40];
        let mut reader = FragmentReader::new(EXPORTS_RAW.to_vec(), 0x3A00);

        let mut ed = ExportDirectory::parse_bytes(raw_export_data.to_vec(), 0x3A00).unwrap();
        ed.parse_exports(&sections, &mut reader).unwrap();

        assert_eq!(ed.name, "libssp-0.dll");

        for i in 0..ed.exports.len() {
            let known = &exported_names[i];
            let parsed = &ed.exports[i];

            assert_eq!(parsed.name.value, known.name.value);
            assert_eq!(parsed.name.offset, known.name.offset);
            assert_eq!(parsed.name.rva, known.name.rva);

            assert_eq!(parsed.address.value, known.address.value);
            assert_eq!(parsed.address.offset, known.address.offset);
            assert_eq!(parsed.address.rva, known.address.rva);

            assert_eq!(parsed.ordinal.value, known.ordinal.value);
            assert_eq!(parsed.ordinal.offset, known.ordinal.offset);
            assert_eq!(parsed.ordinal.rva, known.ordinal.rva);

            assert_eq!(parsed.name, known.name);
            assert_eq!(parsed.address, known.address);
            assert_eq!(parsed.ordinal, known.ordinal);

            assert_eq!(parsed, known);
        }

    }

    fn parse_section_header() -> SectionTable {
        parse_sections(&SECTION_RAW, 11, 0x188).unwrap()
    }

    //Raw data used for test
    const SECTION_RAW: [u8; 440] = [
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x22, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x50, 0x60, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x50, 0xC0,
        0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0xA0, 0x09, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00,
        0x00, 0x0A, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x60, 0x40, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xD0, 0x02, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40,
        0x2E, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x48, 0x02, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40, 0x2E, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x09, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x60, 0xC0,
        0x2E, 0x65, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x8A, 0x01, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xA4, 0x07, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0xC0,
        0x2E, 0x43, 0x52, 0x54, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xC0, 0x2E, 0x74, 0x6C, 0x73, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xC0,
        0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x42
    ];

    const EXPORTS_RAW: [u8; 400] = [
        0x00, 0x00, 0x00, 0x00, 0xE1, 0x8A, 0x58, 0x5A, 0x00, 0x00, 0x00, 0x00, 0xB4, 0x90, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x28, 0x90, 0x00, 0x00,
        0x60, 0x90, 0x00, 0x00, 0x98, 0x90, 0x00, 0x00, 0xB0, 0x14, 0x00, 0x00, 0xE0, 0x14, 0x00, 0x00,
        0x10, 0x16, 0x00, 0x00, 0x30, 0x16, 0x00, 0x00, 0x50, 0x16, 0x00, 0x00, 0x80, 0x16, 0x00, 0x00,
        0x90, 0x14, 0x00, 0x00, 0xD0, 0x14, 0x00, 0x00, 0x20, 0x80, 0x00, 0x00, 0xA0, 0x16, 0x00, 0x00,
        0xF0, 0x16, 0x00, 0x00, 0x50, 0x17, 0x00, 0x00, 0x90, 0x17, 0x00, 0x00, 0xD0, 0x18, 0x00, 0x00,
        0xC1, 0x90, 0x00, 0x00, 0xCC, 0x90, 0x00, 0x00, 0xD7, 0x90, 0x00, 0x00, 0xE4, 0x90, 0x00, 0x00,
        0xF2, 0x90, 0x00, 0x00, 0x00, 0x91, 0x00, 0x00, 0x0D, 0x91, 0x00, 0x00, 0x1E, 0x91, 0x00, 0x00,
        0x35, 0x91, 0x00, 0x00, 0x47, 0x91, 0x00, 0x00, 0x54, 0x91, 0x00, 0x00, 0x61, 0x91, 0x00, 0x00,
        0x6E, 0x91, 0x00, 0x00, 0x7C, 0x91, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00,
        0x0C, 0x00, 0x0D, 0x00, 0x6C, 0x69, 0x62, 0x73, 0x73, 0x70, 0x2D, 0x30, 0x2E, 0x64, 0x6C, 0x6C,
        0x00, 0x5F, 0x5F, 0x63, 0x68, 0x6B, 0x5F, 0x66, 0x61, 0x69, 0x6C, 0x00, 0x5F, 0x5F, 0x67, 0x65,
        0x74, 0x73, 0x5F, 0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F, 0x6D, 0x65, 0x6D, 0x63, 0x70, 0x79, 0x5F,
        0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F, 0x6D, 0x65, 0x6D, 0x6D, 0x6F, 0x76, 0x65, 0x5F, 0x63, 0x68,
        0x6B, 0x00, 0x5F, 0x5F, 0x6D, 0x65, 0x6D, 0x70, 0x63, 0x70, 0x79, 0x5F, 0x63, 0x68, 0x6B, 0x00,
        0x5F, 0x5F, 0x6D, 0x65, 0x6D, 0x73, 0x65, 0x74, 0x5F, 0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F, 0x73,
        0x74, 0x61, 0x63, 0x6B, 0x5F, 0x63, 0x68, 0x6B, 0x5F, 0x66, 0x61, 0x69, 0x6C, 0x00, 0x5F, 0x5F,
        0x73, 0x74, 0x61, 0x63, 0x6B, 0x5F, 0x63, 0x68, 0x6B, 0x5F, 0x66, 0x61, 0x69, 0x6C, 0x5F, 0x6C,
        0x6F, 0x63, 0x61, 0x6C, 0x00, 0x5F, 0x5F, 0x73, 0x74, 0x61, 0x63, 0x6B, 0x5F, 0x63, 0x68, 0x6B,
        0x5F, 0x67, 0x75, 0x61, 0x72, 0x64, 0x00, 0x5F, 0x5F, 0x73, 0x74, 0x70, 0x63, 0x70, 0x79, 0x5F,
        0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F, 0x73, 0x74, 0x72, 0x63, 0x61, 0x74, 0x5F, 0x63, 0x68, 0x6B,
        0x00, 0x5F, 0x5F, 0x73, 0x74, 0x72, 0x63, 0x70, 0x79, 0x5F, 0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F,
        0x73, 0x74, 0x72, 0x6E, 0x63, 0x61, 0x74, 0x5F, 0x63, 0x68, 0x6B, 0x00, 0x5F, 0x5F, 0x73, 0x74,
        0x72, 0x6E, 0x63, 0x70, 0x79, 0x5F, 0x63, 0x68, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
}