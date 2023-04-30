use std::{io::{Cursor, SeekFrom, Seek, BufRead, Read}, error::Error};

use byteorder::{ReadBytesExt, LittleEndian};

pub trait Reader {
    #[allow(unused_variables)]
    fn read_string_at_offset(&mut self, offset: u64) -> Result<String, Box<dyn Error>>{
        Ok(String::new())
    }

    #[allow(unused_variables)]
    fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(vec![0x00])
    }

    #[allow(unused_variables)]
    fn read_wchar_string_at_offset(&mut self, offset: u64) -> Result<String, Box<dyn Error>> {
        Ok(String::new())
    }
}

pub struct ContentBase<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> ContentBase<'a> {
    pub fn new(content: &'a[u8]) -> Self {
        let cursor = Cursor::new(content);
        Self { cursor }
    }
}

impl Reader for ContentBase<'_> {
    fn read_string_at_offset(&mut self, offset: u64) -> Result<String, Box<dyn Error>> {
        let mut buf:Vec<u8> = Vec::new();
        self.cursor.seek(SeekFrom::Start(offset))?;
        self.cursor.read_until(b'\0', &mut buf)?;
        Ok(String::from_utf8(buf[..(buf.len()-1)].to_vec())?)
    }

    fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf:Vec<u8> = vec![0; size];
        self.cursor.seek(SeekFrom::Start(offset))?;
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_wchar_string_at_offset(&mut self, offset: u64) -> Result<String, Box<dyn Error>> {
        self.cursor.seek( SeekFrom::Start(offset))?;
        let len = self.cursor.read_u16::<LittleEndian>()?;
        let mut buf = vec![0u16; len.into()];
        self.cursor.read_u16_into::<LittleEndian>(&mut buf)?;
        Ok(String::from_utf16(&buf)?)
    }
}

pub fn read_string_at_offset(content: &[u8], offset: u64) -> Option<String> {
    let mut cursor = Cursor::new(content);
    let mut buf:Vec<u8> = Vec::new();
    cursor.seek(SeekFrom::Start(offset)).unwrap();
    cursor.read_until(b'\0', &mut buf).unwrap();
    Some(String::from_utf8(buf[..(buf.len()-1)].to_vec()).unwrap())
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ContentBase, Reader};

    #[test]
    fn test_read_wchar_string_at_offset() {
        let mut reader = ContentBase::new(&[0x04u8, 0x00, 0x41, 0x00, 0x41, 0x00,0x41, 0x00, 0x41, 0x00]);
        let str = reader.read_wchar_string_at_offset(0).unwrap();
        assert_eq!(str, String::from_str("AAAA").unwrap());
    }
}
