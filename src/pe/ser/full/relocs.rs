use crate::pe::relocs::{Reloc, RelocBlock};

use super::{hf_to_hfx, HeaderFieldEx, ByteEndian};

pub struct RelocBlockEx {
    pub virtual_address: HeaderFieldEx<u32>,
    pub size: HeaderFieldEx<u32>,
    pub relocations: Vec<HeaderFieldEx<Reloc>>
}

impl From<&RelocBlock> for RelocBlockEx {
    fn from(value: &RelocBlock) -> Self {
        Self { 
            virtual_address: hf_to_hfx(&value.va, ByteEndian::LE), 
            size: hf_to_hfx(&value.size, ByteEndian::LE), 
            relocations: value.relocs
                .iter()
                .map(|reloc| {
                    let val = u16::from(reloc.value.rtype) << 12 | reloc.value.rva;
                    HeaderFieldEx {
                        raw: val.to_le_bytes().to_vec(),
                        value: reloc.clone()
                    }
                })
                .collect()
        }
    }
}