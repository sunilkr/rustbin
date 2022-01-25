use std::{io::{BufReader, Result, Seek, SeekFrom}, fs::File};

use crate::types::{HeaderField, Header};

use self::{dos::DosHeader, file::FileHeader};

pub mod dos;
pub mod section;
pub mod file;
pub mod optional;

#[derive(Debug)]
pub struct PeImage{
    pub dos: HeaderField<DosHeader>,
    pub file: HeaderField<FileHeader>,
}

impl Header for PeImage {
    fn parse_file(f: &mut BufReader<File>, pos: u64) -> Result<Self> where Self: Sized {
        f.seek(SeekFrom::Start(pos))?;
        let dos_header = DosHeader::parse_file(f, pos)?;
        let mut new_pos = pos + dos::HEADER_LENGTH;
        let file_header = FileHeader::parse_file(f, new_pos)?;

        Ok( Self {
            dos: HeaderField{value: dos_header, offset: pos, rva: pos},
            file: HeaderField { value: file_header, offset: new_pos, rva: new_pos }
        })
    }

    fn parse_bytes(bytes: &Vec<u8>, pos: u64) -> Result<Self> where Self: Sized {
        let dos_header = DosHeader::parse_bytes(&bytes, pos)?;
        let mut new_pos = pos + dos::HEADER_LENGTH;
        let file_header = FileHeader::parse_bytes(&bytes, new_pos)?;

        Ok( Self {
            dos: HeaderField{value: dos_header, offset: pos, rva: pos},
            file: HeaderField { value: file_header, offset: new_pos, rva: new_pos }
        })
    }

    fn is_valid(&self) -> bool {
        self.dos.value.is_valid()
    }

    fn length() -> usize {
        todo!()
    }
}
