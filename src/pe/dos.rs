use crate::types::{Header, HeaderField};

use std::{io::{Result, Error, Cursor}, mem::size_of, fmt::Display};

use byteorder::{LittleEndian, ReadBytesExt};

//#[allow(unused)]

pub const HEADER_LENGTH: u64 = 64;

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
    pub e_lfanew: HeaderField<u32>,   // File address of new exe header
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

    //TODO: Make a macro
    fn new_header_field<T>(value: T, offset: &mut u64) -> HeaderField<T> {
        let old_offset = *offset;
        *offset = *offset + (size_of::<T>() as u64);
        
        HeaderField::<T>{
            value,
            offset: old_offset,
            rva: old_offset,
        }
    } 
}

impl Header for DosHeader {
    fn parse_bytes(bytes: &[u8], pos: u64) -> Result<Self> {
        let bytes_available = (bytes.len() as u64) - pos;

        if bytes_available < HEADER_LENGTH {
            return Err ( 
                Error::new (
                    std::io::ErrorKind::InvalidData, 
                    format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes_available)
                )
            );
        }

        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;
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

    fn is_valid(&self) -> bool {
        self.e_magic.value == 0x5A4D
    }
    
    fn length() -> usize { HEADER_LENGTH as usize}
}

impl Display for DosHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{e_magic: '{}', e_lfanew: {}(0x{:X})}}", std::str::from_utf8(&self.e_magic.value.to_le_bytes()).unwrap(), self.e_lfanew.value, self.e_lfanew.value)
    }
}


#[cfg(test)]
mod tests {
    use crate::types::Header;

    use super::DosHeader;    
    const RAW_DOS_BYTES: [u8; 64] = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 
                                    0x00, 0x00, 0xB8, 0x00, 00, 00, 00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
                                    00, 00, 00, 00, 00, 00, 00, 0xF8, 00, 00, 00];
    #[test]
    fn parse_valid_header(){
        let buf = RAW_DOS_BYTES;
        let dos_header = DosHeader::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid());
        assert_eq!(dos_header.e_magic.value, 0x5A4D);
        assert_eq!(dos_header.e_magic.offset, 0);
        assert_eq!(dos_header.e_magic.rva, 0);
        assert_eq!(dos_header.e_lfanew.value, 0x000000F8);
        assert_eq!(dos_header.e_lfanew.offset, 60);
        assert_eq!(dos_header.e_lfanew.rva, 60);
    }

    #[test]
    fn parse_invalid_header(){
        let mut buf = RAW_DOS_BYTES.to_vec();
        buf[0] = 0x4E;
        let dos_header = DosHeader::parse_bytes(&buf, 0).unwrap();
        assert!(dos_header.is_valid() == false);
    }
}