pub(crate) mod dos;
pub(crate) mod file;

use dos::DosHeaderEx;
use file::FileHeaderEx;
use num_traits::ToBytes;
use serde::Serialize;

use crate::{pe::PeImage, types::HeaderField};

#[derive(Debug, Default, Serialize)]
pub struct HeaderFieldEx<T> {
    raw: Vec<u8>,

    #[serde(flatten)]
    value: HeaderField<T>,
}

#[allow(unused)]
pub(crate) enum ByteEndian {
    ///Big endian
    BE,
    ///Little endian
    LE,
    /// Native endian
    NE,
}

fn hf_to_hfx<T>(value: &HeaderField<T>, endian: ByteEndian) -> HeaderFieldEx<T> where T: ToBytes + Clone {
    let raw = match endian {
        ByteEndian::BE => ToBytes::to_be_bytes(&value.value),
        ByteEndian::LE => ToBytes::to_le_bytes(&value.value),
        ByteEndian::NE => ToBytes::to_ne_bytes(&value.value),
    }.as_ref().to_vec(); 

    HeaderFieldEx { raw, value: value.clone()}
}

#[derive(Debug, Serialize)]
pub struct FullPeImage {
    pub(crate) dos: HeaderField<DosHeaderEx>,
    pub(crate) file: HeaderField<FileHeaderEx>,
}

impl From<&PeImage> for FullPeImage {
    fn from(value: &PeImage) -> Self {
        Self { 
            dos: HeaderField{ 
                value: DosHeaderEx::from(&value.dos.value), 
                offset: value.dos.offset, 
                rva: value.dos.rva,
                size: value.dos.size,
            },
            file: HeaderField{
                value: FileHeaderEx::from(&value.file.value), 
                offset: value.file.offset,
                rva: value.file.rva,
                size: value.file.size,
            }
        }
    }
}
