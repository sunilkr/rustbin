use std::{fmt::{Debug, Display}, io::{BufReader, Result, Read, Seek, SeekFrom}, fs::File};

#[derive(Debug, Default)]
pub struct HeaderField<T>{
    pub value: T,
    pub offset: u64,
    pub rva: u64,
}

// impl<T> Debug for HeaderField<T> where T: Debug {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{:?}(0x{:x?}])@{{0x{:x?}, 0x{:?}}}", self.value, self.value, self.offset, self.rva)
//     }
// }

impl<T> Display for HeaderField<T> where T: Display {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

pub trait Header {
    fn parse_file(f: &mut BufReader<File>, pos: u64) -> Result<Self> where Self: Sized {
        let offset = f.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0x00; Self::length() as usize];
        f.read_exact(&mut buf)?;

        Ok(Self::parse_bytes(&buf, offset)?)
    }
    fn parse_bytes(bytes: &[u8], pos: u64) -> Result<Self> where Self: Sized;
    fn is_valid(&self) -> bool;
    fn length() -> usize;
}