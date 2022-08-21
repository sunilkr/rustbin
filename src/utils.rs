use std::io::{Cursor, SeekFrom, Seek, BufRead, Result};

use byteorder::ByteOrder;

pub trait Reader {
    fn read_string_at_offset(&mut self, offset: u64) -> Result<String>;
    fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> Result<Vec<u8>>;
}

struct ContentBase<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> ContentBase<'a> {
    pub fn new(content: &'a[u8]) -> Self {
        let cursor = Cursor::new(content);
        Self { cursor }
    }
}

impl Reader for ContentBase<'_> {
    fn read_string_at_offset(&mut self, offset: u64) -> Result<String> {
        let mut buf:Vec<u8> = Vec::new();
        self.cursor.seek(SeekFrom::Start(offset)).unwrap();
        self.cursor.read_until(b'\0', &mut buf).unwrap();
        Ok(String::from_utf8(buf[..(buf.len()-1)].to_vec()).unwrap())
    }

    fn read_bytes_at_offset(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        todo!()
    }
}

pub fn read_string_at_offset(content: &[u8], offset: u64) -> Option<String> {
    let mut cursor = Cursor::new(content);
    let mut buf:Vec<u8> = Vec::new();
    cursor.seek(SeekFrom::Start(offset)).unwrap();
    cursor.read_until(b'\0', &mut buf).unwrap();
    Some(String::from_utf8(buf[..(buf.len()-1)].to_vec()).unwrap())
}
