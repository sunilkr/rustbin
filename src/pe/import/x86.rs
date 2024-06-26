use std::fmt::Display;

use byteorder::{LittleEndian, ByteOrder};

use crate::{pe::{section::{self, SectionTable}, PeError}, types::{BufReadExt, HeaderField}};

use super::ImportName;

#[derive(Debug, Default)]
pub struct ImportLookup32 {
    pub value: HeaderField<u32>,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub iname: Option<HeaderField<ImportName>>,
}

impl Display for ImportLookup32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {        
        if self.is_ordinal {
            write!(f, "{}", self.ordinal.unwrap_or(u16::MAX))
        }
        else {
            let name = if let Some(name_hdr) = &self.iname {
                format!("{}", name_hdr.value)
            }
            else {
                String::from("ERR")
            };

            write!(f, "{}", name)
        }
    }
}

impl ImportLookup32 {
    pub fn new(value: HeaderField<u32>) -> Self {
        let val = value.value;
        let is_ordinal = (val & (1<<31)) != 0;
        let mut ordinal = None;
        let mut name = None;

        if is_ordinal {
            ordinal = Some(val as u16);
        }
        else {
            let iname_rva = (val as u32) & 0x7FFFFFFF;
            name = Some(HeaderField{value: Default::default(), offset: 0, rva: iname_rva as u64});
        }

        Self { 
            value: value, 
            is_ordinal: is_ordinal,
            ordinal: ordinal,
            iname: name,
        }
    }

    pub fn update_name(&mut self, sections: &SectionTable, reader: &mut dyn BufReadExt) -> crate::Result<()> {
        if let Some(iname) = &mut self.iname {
            let offset = section::rva_to_offset(sections, iname.rva as u32).ok_or(PeError::InvalidRVA(iname.rva))?;
            let hint = reader.read_bytes_at_offset(offset.into(), 2)?;
            let hint = LittleEndian::read_u16(&hint);
            let name = reader.read_string_at_offset((offset+2).into())?;
            iname.offset = offset.into();
            iname.value = ImportName {
                hint: HeaderField { value: hint, offset: offset.into(), rva: iname.rva },
                name: HeaderField { value: name, offset: (offset+2).into(), rva: iname.rva+2 }
            };
        }
        Ok(())
    }
}
