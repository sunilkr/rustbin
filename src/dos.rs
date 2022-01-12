use super::types::HeaderField;
use std::{fs::File, io::{BufReader, Result, Seek}, mem::size_of};

use byteorder::{LittleEndian, ReadBytesExt};

//#[allow(unused)]

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
        let mut dos_header = DosHeader::new();
        let mut size_of_u16: u64  = size_of::<u16>() as u64;

        dos_header.set_field_value(&mut dos_header.e_magic, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);     
        dos_header.set_field_value( &mut dos_header.e_cblp, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_cp, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_crlc, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_cparhdr, f.read_u16::<LittleEndian>()?,f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_minalloc, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_maxalloc, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_ss, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_sp, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_csum, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_ip, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_cs, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_lfarlc, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        dos_header.set_field_value(&mut dos_header.e_ovno, f.read_u16::<LittleEndian>()?, f.stream_position()? - size_of_u16);
        
        let mut tmp_buff: [u16; 4];
        f.read_u16_into::<LittleEndian>(&mut tmp_buff)?;
        
        // dos_header.e_oemid    = f.read_u16::<LittleEndian>()?;
        // dos_header.e_oeminfo  = f.read_u16::<LittleEndian>()?;
        // f.read_u16_into::<LittleEndian>(&mut dos_header.e_res2)?;
        // dos_header.e_lfanew   = f.read_u32::<LittleEndian>()?;
        f.read_u16_into::<LittleEndian>(dos_header.e_magic.value);
        Ok(dos_header)
    }

    pub fn is_valid(&self) -> bool {
        self.e_magic == 0x5A4D
    }

    fn set_field_value<T>(&self, field: &mut HeaderField<T>, value: T, offset: u64) {
        field.value = value;
        field.offset = offset;
        field.rva = offset;
    }
}
