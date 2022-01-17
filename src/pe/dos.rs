use super::super::types::HeaderField;

use std::{fs::File, io::{BufReader, Seek, Result, Error, Cursor, Read}, mem::size_of, fmt::Display};

use byteorder::{LittleEndian, ReadBytesExt};

//#[allow(unused)]

pub const HEADER_LENGTH: usize = 64;

#[derive(Debug)]
pub struct DosHeader {
    pub e_magic: HeaderField<u16>,    // Magic number
    e_cblp: HeaderField<u16>,         // Bytes on last page of file
    e_cp: HeaderField<u16>,           // Pages in file
    e_crlc: HeaderField<u16>,         // Relocations
    e_cparhdr: HeaderField<u16>,      // Size of header in paragraphs
    e_minalloc: HeaderField<u16>,     // Minimum extra paragraphs needed
    e_maxalloc: HeaderField<u16>,     // Maximum extra paragraphs needed
    e_ss: HeaderField<u16>,           // Initial (relative) SS value
    e_sp: HeaderField<u16>,           // Initial SP value
    e_csum: HeaderField<u16>,         // Checksum
    e_ip: HeaderField<u16>,           // Initial IP value
    e_cs: HeaderField<u16>,           // Initial (relative) CS value
    e_lfarlc: HeaderField<u16>,       // File address of relocation table
    e_ovno: HeaderField<u16>,         // Overlay number
    e_res: HeaderField<[u16; 4]>,     // Reserved words
    e_oemid:  HeaderField<u16>,       // OEM identifier (for e_oeminfo)
    e_oeminfo: HeaderField<u16>,      // OEM information; e_oemid specific
    e_res2: HeaderField<[u16; 10]>,   // Reserved words
    pub e_lfanew: HeaderField<u32>,       // File address of new exe header
}

impl DosHeader {
    pub fn new() -> Self {
        DosHeader {
            e_magic: Default::default(),     
            e_cblp: Default::default(),      
            e_cp: Default::default(),        
            e_crlc: Default::default(),      
            e_cparhdr: Default::default(),   
            e_minalloc: Default::default(),  
            e_maxalloc: Default::default(),  
            e_ss: Default::default(),        
            e_sp: Default::default(),        
            e_csum: Default::default(),      
            e_ip: Default::default(),        
            e_cs: Default::default(),        
            e_lfarlc: Default::default(),    
            e_ovno: Default::default(),      
            e_res: Default::default(),  
            e_oemid: Default::default(),     
            e_oeminfo: Default::default(),   
            e_res2: Default::default(),
            e_lfanew: Default::default(),
        }
    }

    pub fn parse(f: &mut BufReader<File>) -> Result<Self> {
        let offset = f.stream_position()?;
        let mut buf = vec![0x00; 64];
        f.read_exact(&mut buf)?;

        Ok(Self::parse_bytes(buf, offset)?)
    }

    pub fn parse_bytes(bytes: Vec<u8>, start: u64) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::new(std::io::ErrorKind::InvalidData, format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes.len())));
        }

        let mut cursor = Cursor::new(bytes);
        let mut offset = start;
        let mut dos_header = Self::new();

        dos_header.e_magic = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_cblp = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);    
        dos_header.e_cp = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_crlc = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);        
        dos_header.e_cparhdr = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_minalloc = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_maxalloc = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_ss = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_sp = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_csum = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_ip = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_cs = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_lfarlc = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_ovno = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        
        let mut tmp_buff: [u16; 4] = [0; 4];
        cursor.read_u16_into::<LittleEndian>(&mut tmp_buff)?;
        dos_header.e_res = Self::new_header_field(tmp_buff, &mut offset);
        dos_header.e_oemid = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        dos_header.e_oeminfo = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        
        let mut tmp_buff: [u16; 10] = [0; 10];
        cursor.read_u16_into::<LittleEndian>(&mut tmp_buff)?;
        dos_header.e_res2 = Self::new_header_field(tmp_buff, &mut offset);

        dos_header.e_lfanew = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        Ok(dos_header)
    }

    pub fn is_valid(&self) -> bool {
        self.e_magic.value == 0x5A4D
    }

    fn new_header_field<T>(value: T, offset: &mut u64) -> HeaderField<T> {
        let old_offset = *offset;
        *offset = *offset + (size_of::<T>() as u64);
        
        HeaderField::<T>{
            value: value,
            offset: old_offset,
            rva: old_offset,
        }
    }
}

impl Display for DosHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ e_magic: {:X?}, e_lfanew: {}(0x{:X})}}", self.e_magic.value.to_be_bytes(), self.e_lfanew.value, self.e_lfanew.value)
    }
}
