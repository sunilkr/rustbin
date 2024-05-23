use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use bitflags::Flags;

use crate::types::BufReadExt;

pub struct FragmentReader {
    cursor: Cursor<Vec<u8>>,
    pub base: usize,
}

impl FragmentReader {
    pub fn new(content: Vec<u8>, base: usize) -> Self {
        let cursor = Cursor::new(content);
        Self { cursor, base }
    }
}

impl Read for FragmentReader{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl BufRead for FragmentReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.cursor.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.cursor.consume(amt)
    }
}

impl Seek for FragmentReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl BufReadExt for FragmentReader { }


pub fn read_string_at_offset(content: &[u8], offset: u64) -> Option<String> {
    let mut cursor = Cursor::new(content);
    let mut buf:Vec<u8> = Vec::new();
    cursor.seek(SeekFrom::Start(offset)).unwrap();
    cursor.read_until(b'\0', &mut buf).unwrap();
    Some(String::from_utf8(buf[..(buf.len()-1)].to_vec()).unwrap())
}


#[inline]
pub(crate) fn flags_to_str<T>(value: &T) -> String
    where T: Flags
{
    let names: Vec<String> = value.iter_names().map(|(s, _)| String::from(s)).collect();
    format!("{}", names.join(" | ").as_str())
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{FragmentReader, BufReadExt};

    #[test]
    fn test_read_wchar_string_at_offset() {
        let mut reader = FragmentReader::new([0x04u8, 0x00, 0x41, 0x00, 0x41, 0x00,0x41, 0x00, 0x41, 0x00].to_vec(), 0);
        let str = reader.read_wchar_string_at_offset(0).unwrap();
        assert_eq!(str, String::from_str("AAAA").unwrap());
    }
}
