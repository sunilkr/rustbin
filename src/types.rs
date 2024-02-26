use std::{
        fmt::{Debug, Display}, 
        io::{BufReader, Read, Seek, SeekFrom}, 
        fs::File
    };

use serde::Serialize;

#[derive(Serialize)]
#[derive(Debug, Default, PartialEq)]
pub struct HeaderField<T> {
    pub value: T,
    pub offset: u64,
    pub rva: u64,
}


impl<T> Display for HeaderField<T> where T: Display {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}


pub trait Header {
    fn parse_bytes(bytes: &[u8], pos: u64) -> crate::Result<Self> where Self: Sized;
    fn is_valid(&self) -> bool;
    fn length() -> usize;

    fn parse_file(f: &mut BufReader<File>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let offset = f.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0x00; Self::length() as usize];
        f.read_exact(&mut buf)?;

        Self::parse_bytes(&buf, offset)
    }
}
