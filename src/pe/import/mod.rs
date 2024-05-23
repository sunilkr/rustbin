use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};
use chrono::{DateTime, Utc};

use crate::{errors::InvalidTimestamp, new_header_field, types::{Header, HeaderField, BufReadExt}, Result};
use std::{io::Cursor, fmt::Display, mem::size_of};
use self::{x86::ImportLookup32, x64::ImportLookup64};

use super::{section::{SectionTable, offset_to_rva, rva_to_offset, self, BadOffsetError, BadRvaError}, optional::ImageType};

pub(crate) mod x86;
pub(crate) mod x64;

#[derive(Debug, Default)]
pub struct ImportName {
    pub hint: HeaderField<u16>,
    pub name: HeaderField<String>,
}

impl Display for ImportName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name.value)
    }
}


#[derive(Debug)]
pub enum ImportLookup {
    X86(ImportLookup32),
    X64(ImportLookup64),
}

impl From<HeaderField<u32>> for ImportLookup {
    fn from(value: HeaderField<u32>) -> Self {
        Self::X86(ImportLookup32::new(value))
    }
}

impl From<HeaderField<u64>> for ImportLookup{
    fn from(value: HeaderField<u64>) -> Self {
        Self::X64(ImportLookup64::new(value))
    }
}

impl ImportLookup {
    pub fn update_name(&mut self, sections: &SectionTable, reader: &mut impl BufReadExt) -> Result<()> {
        match self {
            ImportLookup::X86(il) => {
                il.update_name(sections, reader)?;
            },

            ImportLookup::X64(il) => {
                il.update_name(sections, reader)?;
            },
        }

        Ok(())
    }
}

impl Display for ImportLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportLookup::X86(i) => write!(f, "{}", i),
            ImportLookup::X64(i) => write!(f, "{}", i),
        }
    }
}


pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;

#[derive(Debug, Default)]
pub struct ImportDescriptor {
    pub ilt: HeaderField<u32>,
    pub timestamp: HeaderField<DateTime<Utc>>,
    pub forwarder_chain: HeaderField<u32>,
    pub name_rva: HeaderField<u32>,
    pub first_thunk: HeaderField<u32>,
    pub name: Option<String>,
    pub imports: Vec<ImportLookup>,
}


impl Display for ImportDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ {}, ILT: {:#08x}, Imports: {}, Timestamp: {} }}",
            self.name.as_ref().unwrap_or(&String::from("ERR")), self.ilt.value, self.imports.len(), self.timestamp.value.to_rfc3339()
        )
    }
}


impl ImportDescriptor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_imports(&mut self, sections: &SectionTable, image_type: ImageType, reader: &mut impl BufReadExt) -> Result<()> {
        let mut rva = self.ilt.value;
        let mut offset = section::rva_to_offset(sections, rva).ok_or(BadRvaError(rva.into()))?;

        match image_type {            
            ImageType::PE32 => {                
                loop {
                    let val = reader.read_bytes_at_offset(offset.into(), 4)?;
                    let value = LittleEndian::read_u32(&val);
                    if value == 0 {
                        break;
                    }
                    
                    let mut import = ImportLookup::from(HeaderField { value, offset: offset.into(), rva: rva.into() });
                    import.update_name(sections, reader)?;

                    self.imports.push(import);

                    offset += 4;
                    rva += 4;
                }
            }
            
            ImageType::PE64 => {
                loop {
                    let val = reader.read_bytes_at_offset(offset.into(), 8)?;
                    let value = LittleEndian::read_u64(&val);
                    if value == 0 {
                        break;
                    }
                    
                    let mut import = ImportLookup::from(HeaderField { value, offset: offset.into(), rva: rva.into() });
                    import.update_name(sections, reader)?;

                    self.imports.push(import);

                    offset += 8;
                    rva += 8;
                }
            }

            _ => unimplemented!(), //TODO: Needs to change
        }
        Ok(())
    }


    pub fn fix_rvas(&mut self, sections: &SectionTable) -> Result<()> {
        self.ilt.rva = offset_to_rva(sections, self.ilt.offset as u32).ok_or(BadOffsetError(self.ilt.offset))? as u64;
        self.timestamp.rva = offset_to_rva(sections, self.timestamp.offset as u32).ok_or(BadOffsetError(self.timestamp.offset))? as u64;
        self.forwarder_chain.rva = offset_to_rva(sections, self.forwarder_chain.offset as u32).ok_or(BadOffsetError(self.forwarder_chain.offset))? as u64;
        self.name_rva.rva = offset_to_rva(sections, self.name_rva.offset as u32).ok_or(BadOffsetError(self.name_rva.offset))? as u64;
        self.first_thunk.rva = offset_to_rva(sections, self.first_thunk.offset as u32).ok_or(BadOffsetError(self.first_thunk.offset))? as u64;
        Ok(())
    }


    pub fn update_name(&mut self, sections: &SectionTable, reader: &mut impl BufReadExt) -> Result<()> {
        let offset = rva_to_offset(sections, self.name_rva.value).ok_or(BadRvaError(self.name_rva.value.into()))?;
        self.name = Some(reader.read_string_at_offset(offset as u64)?);
        Ok(())
    }

    pub fn get_imports_str(&self) -> Vec<String> {
        self.imports.iter().map(|imp| format!("{}", imp)).collect()
    }
}
 

impl Header for ImportDescriptor {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        let mut id = Self::new();
        id.ilt = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        let dt = cursor.read_u32::<LittleEndian>()?;
        let ts = DateTime::<Utc>::from_timestamp(dt.into(), 0).ok_or(InvalidTimestamp{ data: dt.into() })?;
        id.timestamp = HeaderField {value: ts, offset: offset, rva: offset};
        offset += size_of::<u32>() as u64;

        id.forwarder_chain = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        id.name_rva = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        id.first_thunk = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        Ok(id)
    }

    fn is_valid(&self) -> bool {
        self.ilt.value != 0 || self.name_rva.value != 0 || self.first_thunk.value != 0
    }

    fn length() -> usize {
        IMPORT_DESCRIPTOR_SIZE
    }
}


pub type ImportDirectory = Vec<HeaderField<ImportDescriptor>>;

impl Header for ImportDirectory {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut imp_dir = Self::new();
        let mut curr_pos = pos;
        let mut slice_start = 0 as usize;
        let mut slice_end = slice_start + (IMPORT_DESCRIPTOR_SIZE as usize);

        loop {
            let buf = &bytes[slice_start..slice_end];
            
            let idesc = ImportDescriptor::parse_bytes(buf.to_vec(), curr_pos)?;
            if !idesc.is_valid(){
                break;
            }
            imp_dir.push(HeaderField { value: idesc, offset: curr_pos, rva: curr_pos });

            curr_pos += IMPORT_DESCRIPTOR_SIZE as u64;
            slice_start = slice_end;
            slice_end += IMPORT_DESCRIPTOR_SIZE as usize;
        }

        Ok(imp_dir)
    }

    fn parse_buf(reader: &mut impl BufReadExt, pos: u64, offset: u64) -> crate::Result<Self> where Self: Sized {
        let mut imp_dir = Self::new();
        let mut delta = 0;

        loop {
            let bytes = reader.read_bytes_at_offset(offset + delta, IMPORT_DESCRIPTOR_SIZE)?;

            let idesc = ImportDescriptor::parse_bytes(bytes, pos + delta)?;
            
            let old_offset = offset;
            delta += IMPORT_DESCRIPTOR_SIZE as u64;

            if !idesc.is_valid() {                
                break; 
            }

            imp_dir.push(HeaderField { value: idesc, offset: old_offset, rva: old_offset });
        }

        Ok(imp_dir)
    }

    fn is_valid(&self) -> bool {
        self.len() > 0
    }

    // fn length(&self) -> usize {
    //     if self.len() == 0 { 0 } else { (self.len() +1) * IMPORT_DESCRIPTOR_SIZE}
    // }

    fn length() -> usize {
        unimplemented!()
    }
}


#[cfg(test)]
mod test {

    use crate::{pe::{import::ImportLookup, optional::ImageType, section::{parse_sections, rva_to_offset, SectionTable}}, types::Header, utils::{read_string_at_offset, FragmentReader}};

    use super::{ImportDescriptor, ImportDirectory};

    fn parse_section_header() -> SectionTable {
        parse_sections(&SECTION_RAW, 11, 0x188).unwrap()
    }

    #[test]
    fn test_parse_import_desc() {
        let id = ImportDescriptor::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        assert_eq!(id.ilt.value, 0xA050);
        assert_eq!(id.ilt.offset, 0x3C00);
        assert_eq!(id.timestamp.offset, 0x3C04);
        assert_eq!(id.timestamp.value.to_rfc3339(), "1970-01-01T00:00:00+00:00");
        assert_eq!(id.forwarder_chain.value, 0);
        assert_eq!(id.forwarder_chain.offset, 0x3C08);
        assert_eq!(id.name_rva.value, 0xA6BC);
        assert_eq!(id.name_rva.offset, 0x3C0C);
        assert_eq!(id.first_thunk.value, 0xA1F8);
        assert_eq!(id.first_thunk.offset, 0x3C10);
    }

    #[test]
    fn test_parse_import_desc_with_fixes() {
        let sections = parse_section_header();
        
        let mut id = ImportDescriptor::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        id.fix_rvas(&sections).unwrap();

        assert_eq!(id.ilt.value, 0xA050);
        assert_eq!(id.ilt.rva, 0xA000);
        assert_eq!(id.timestamp.rva, 0xA004);
        assert_eq!(id.timestamp.value.to_rfc3339(), "1970-01-01T00:00:00+00:00");
        assert_eq!(id.forwarder_chain.value, 0);
        assert_eq!(id.forwarder_chain.rva, 0xA008);
        assert_eq!(id.name_rva.value, 0xA6BC);
        assert_eq!(id.name_rva.rva, 0xA00C);
        assert_eq!(id.first_thunk.value, 0xA1F8);
        assert_eq!(id.first_thunk.rva, 0xA010);

        let name_offset = rva_to_offset(&sections, id.name_rva.value).unwrap() - sections[7].value.raw_data_ptr.value;
        id.name = Some(read_string_at_offset(&IDATA_RAW, name_offset as u64).unwrap());
        assert_eq!(id.name.unwrap(), "ADVAPI32.dll");
    }

    #[test]
    fn test_parse_sections() {
        let sections = parse_section_header();
        assert_eq!(sections[7].value.name_str().unwrap(), ".idata");
    }

    #[test]
    fn test_update_name() {
        let sections = parse_section_header();
        let mut reader = FragmentReader::new(IDATA_RAW.to_vec(), IDATA_RAW_OFFSET as usize);
        let mut id = ImportDescriptor::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        
        id.update_name(&sections, &mut reader).unwrap();
        assert_eq!(id.name.unwrap(), "ADVAPI32.dll");
        
        drop(reader);
    }

    #[test]
    fn test_parse_idir() {
        let idir = ImportDirectory::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        assert_eq!(idir.len(), 3);
    }

    #[test]
    fn test_parse_idir_with_names() {
        let sections = parse_section_header();
        let mut reader = FragmentReader::new(IDATA_RAW.to_vec(), IDATA_RAW_OFFSET as usize);
        let mut idir = ImportDirectory::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        
        for i in 0..idir.len() {
            let idesc = &mut idir[i].value;
            idesc.update_name(&sections, &mut reader).unwrap();
        }

        let dll_names = [
            "ADVAPI32.dll",
            "KERNEL32.dll",
            "msvcrt.dll"
        ];

        for i in 0..idir.len() {
            assert_eq!(idir[i].value.name.as_ref().unwrap(), dll_names[i]);
        }
    }

    #[test]
    fn test_parse_import_fn_names() {
        let dll_names = [
            "ADVAPI32.dll",
            "KERNEL32.dll",
            "msvcrt.dll"
        ];

        let import_nums = [3, 22, 25];
        
        let first_imports = [
            "CryptAcquireContextA",
            "DeleteCriticalSection",
            "__iob_func",
        ];

        let last_imports = [
            "CryptReleaseContext",
            "VirtualQuery",
            "vfprintf",
        ];

        let sections = parse_section_header();
        let mut reader = FragmentReader::new(IDATA_RAW.to_vec(), IDATA_RAW_OFFSET as usize);
        let mut idir = ImportDirectory::parse_bytes(IDATA_RAW.to_vec(), 0x3C00).unwrap();
        
        for i in 0..idir.len() {
            let idesc = &mut idir[i].value;
            idesc.update_name(&sections, &mut reader).unwrap();
            idesc.parse_imports(&sections, ImageType::PE64, &mut reader).unwrap();
        }

        for i in 0..idir.len() {
            let idesc = &idir[i].value;
            assert_eq!(idesc.name.as_ref().unwrap(), dll_names[i]);
            assert_eq!(idesc.imports.len(), import_nums[i]);
            match &idesc.imports[0] {
                ImportLookup::X64(il) => {
                    if let Some(iname) = &il.iname {
                        assert_eq!(iname.value.name.value, first_imports[i]);
                    }
                }                
                ImportLookup::X86(_) => assert!(false, "32 bit imports were not expected")
            }

            let imp_len = &idesc.imports.len();
            match &idesc.imports[imp_len-1] {
                ImportLookup::X64(il) => {
                    if let Some(iname) = &il.iname {
                        assert_eq!(iname.value.name.value, last_imports[i]);
                    }
                }                
                ImportLookup::X86(_) => assert!(false, "32 bit imports were not expected")
            }
        }
    }

    //Raw data used for test
    const SECTION_RAW:[u8; 440] = [
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

    const IDATA_RAW_OFFSET: u64 = 0x3C00;

    const IDATA_RAW:[u8; 0x800] = [
        0x50, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0xA6, 0x00, 0x00,
        0xF8, 0xA1, 0x00, 0x00, 0x70, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0xA7, 0x00, 0x00, 0x18, 0xA2, 0x00, 0x00, 0x28, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x98, 0xA7, 0x00, 0x00, 0xD0, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA0, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xCA, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE0, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x60, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x8A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA6, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xBE, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD8, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xEE, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1C, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4E, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6A, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x94, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA6, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB6, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC4, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD2, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xDC, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF0, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x26, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x36, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5C, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x70, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x84, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8E, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x98, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA2, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCA, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF8, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8A, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA6, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xD8, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x56, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA6, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB6, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xD2, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE4, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF8, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0A, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1C, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2E, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x52, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5C, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x66, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7A, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x8E, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA2, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA8, 0x04, 0x43, 0x72, 0x79, 0x70, 0x74, 0x41, 0x63, 0x71, 0x75, 0x69, 0x72, 0x65, 0x43, 0x6F,
        0x6E, 0x74, 0x65, 0x78, 0x74, 0x41, 0x00, 0x00, 0xB9, 0x04, 0x43, 0x72, 0x79, 0x70, 0x74, 0x47,
        0x65, 0x6E, 0x52, 0x61, 0x6E, 0x64, 0x6F, 0x6D, 0x00, 0x00, 0xC3, 0x04, 0x43, 0x72, 0x79, 0x70,
        0x74, 0x52, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x00,
        0x0D, 0x01, 0x44, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C,
        0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x31, 0x01, 0x45, 0x6E, 0x74, 0x65, 0x72, 0x43,
        0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00,
        0x18, 0x02, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x63,
        0x65, 0x73, 0x73, 0x00, 0x19, 0x02, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74,
        0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x49, 0x64, 0x00, 0x1D, 0x02, 0x47, 0x65, 0x74, 0x43,
        0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x49, 0x64, 0x00, 0x00,
        0x62, 0x02, 0x47, 0x65, 0x74, 0x4C, 0x61, 0x73, 0x74, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x00, 0x00,
        0xEB, 0x02, 0x47, 0x65, 0x74, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x54, 0x69, 0x6D, 0x65, 0x41,
        0x73, 0x46, 0x69, 0x6C, 0x65, 0x54, 0x69, 0x6D, 0x65, 0x00, 0x07, 0x03, 0x47, 0x65, 0x74, 0x54,
        0x69, 0x63, 0x6B, 0x43, 0x6F, 0x75, 0x6E, 0x74, 0x00, 0x00, 0x60, 0x03, 0x49, 0x6E, 0x69, 0x74,
        0x69, 0x61, 0x6C, 0x69, 0x7A, 0x65, 0x43, 0x72, 0x69, 0x74, 0x69, 0x63, 0x61, 0x6C, 0x53, 0x65,
        0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0xB8, 0x03, 0x4C, 0x65, 0x61, 0x76, 0x65, 0x43, 0x72, 0x69,
        0x74, 0x69, 0x63, 0x61, 0x6C, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x46, 0x04,
        0x51, 0x75, 0x65, 0x72, 0x79, 0x50, 0x65, 0x72, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x6E, 0x63, 0x65,
        0x43, 0x6F, 0x75, 0x6E, 0x74, 0x65, 0x72, 0x00, 0x9C, 0x04, 0x52, 0x74, 0x6C, 0x41, 0x64, 0x64,
        0x46, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x54, 0x61, 0x62, 0x6C, 0x65, 0x00, 0x9D, 0x04,
        0x52, 0x74, 0x6C, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78,
        0x74, 0x00, 0xA4, 0x04, 0x52, 0x74, 0x6C, 0x4C, 0x6F, 0x6F, 0x6B, 0x75, 0x70, 0x46, 0x75, 0x6E,
        0x63, 0x74, 0x69, 0x6F, 0x6E, 0x45, 0x6E, 0x74, 0x72, 0x79, 0x00, 0x00, 0xAB, 0x04, 0x52, 0x74,
        0x6C, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x55, 0x6E, 0x77, 0x69, 0x6E, 0x64, 0x00, 0x00,
        0x43, 0x05, 0x53, 0x65, 0x74, 0x55, 0x6E, 0x68, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x64, 0x45, 0x78,
        0x63, 0x65, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72, 0x00, 0x51, 0x05,
        0x53, 0x6C, 0x65, 0x65, 0x70, 0x00, 0x60, 0x05, 0x54, 0x65, 0x72, 0x6D, 0x69, 0x6E, 0x61, 0x74,
        0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0x00, 0x74, 0x05, 0x54, 0x6C, 0x73, 0x47,
        0x65, 0x74, 0x56, 0x61, 0x6C, 0x75, 0x65, 0x00, 0x82, 0x05, 0x55, 0x6E, 0x68, 0x61, 0x6E, 0x64,
        0x6C, 0x65, 0x64, 0x45, 0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x46, 0x69, 0x6C, 0x74,
        0x65, 0x72, 0x00, 0x00, 0xA4, 0x05, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x50, 0x72, 0x6F,
        0x74, 0x65, 0x63, 0x74, 0x00, 0x00, 0xA6, 0x05, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x51,
        0x75, 0x65, 0x72, 0x79, 0x00, 0x00, 0x54, 0x00, 0x5F, 0x5F, 0x69, 0x6F, 0x62, 0x5F, 0x66, 0x75,
        0x6E, 0x63, 0x00, 0x00, 0x7B, 0x00, 0x5F, 0x61, 0x6D, 0x73, 0x67, 0x5F, 0x65, 0x78, 0x69, 0x74,
        0x00, 0x00, 0xAB, 0x00, 0x5F, 0x63, 0x6C, 0x6F, 0x73, 0x65, 0x00, 0x00, 0xF9, 0x00, 0x5F, 0x65,
        0x78, 0x69, 0x74, 0x00, 0x4B, 0x01, 0x5F, 0x69, 0x6E, 0x69, 0x74, 0x74, 0x65, 0x72, 0x6D, 0x00,
        0xB8, 0x01, 0x5F, 0x6C, 0x6F, 0x63, 0x6B, 0x00, 0x6B, 0x02, 0x5F, 0x6F, 0x70, 0x65, 0x6E, 0x00,
        0x2D, 0x03, 0x5F, 0x75, 0x6E, 0x6C, 0x6F, 0x63, 0x6B, 0x00, 0xDA, 0x03, 0x5F, 0x77, 0x72, 0x69,
        0x74, 0x65, 0x00, 0x00, 0x07, 0x04, 0x61, 0x62, 0x6F, 0x72, 0x74, 0x00, 0x1A, 0x04, 0x63, 0x61,
        0x6C, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x31, 0x04, 0x66, 0x67, 0x65, 0x74, 0x73, 0x00, 0x41, 0x04,
        0x66, 0x72, 0x65, 0x65, 0x00, 0x00, 0x4D, 0x04, 0x66, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00,
        0x54, 0x04, 0x67, 0x65, 0x74, 0x73, 0x00, 0x00, 0x7C, 0x04, 0x6D, 0x61, 0x6C, 0x6C, 0x6F, 0x63,
        0x00, 0x00, 0x84, 0x04, 0x6D, 0x65, 0x6D, 0x63, 0x70, 0x79, 0x00, 0x00, 0x85, 0x04, 0x6D, 0x65,
        0x6D, 0x6D, 0x6F, 0x76, 0x65, 0x00, 0x86, 0x04, 0x6D, 0x65, 0x6D, 0x73, 0x65, 0x74, 0x00, 0x00,
        0x98, 0x04, 0x72, 0x65, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x00, 0xA2, 0x04, 0x73, 0x69, 0x67, 0x6E,
        0x61, 0x6C, 0x00, 0x00, 0xB7, 0x04, 0x73, 0x74, 0x72, 0x6C, 0x65, 0x6E, 0x00, 0x00, 0xBA, 0x04,
        0x73, 0x74, 0x72, 0x6E, 0x63, 0x6D, 0x70, 0x00, 0xBB, 0x04, 0x73, 0x74, 0x72, 0x6E, 0x63, 0x70,
        0x79, 0x00, 0xDA, 0x04, 0x76, 0x66, 0x70, 0x72, 0x69, 0x6E, 0x74, 0x66, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xA0, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x41, 0x44, 0x56, 0x41,
        0x50, 0x49, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00, 0x14, 0xA0, 0x00, 0x00,
        0x14, 0xA0, 0x00, 0x00, 0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C,
        0x00, 0x00, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00,
        0x28, 0xA0, 0x00, 0x00, 0x28, 0xA0, 0x00, 0x00, 0x6D, 0x73, 0x76, 0x63, 0x72, 0x74, 0x2E, 0x64,
        0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
}