use serde::Serialize;

use crate::{pe::relocs::{Reloc, RelocBlock, Relocations}, types::HeaderField};

use super::{hf_to_hfx, HeaderFieldEx, ByteEndian};

#[derive(Debug, Serialize)]
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
                    let val = (u8::from(reloc.value.rtype) as u16) << 12 | reloc.value.rva;
                    HeaderFieldEx {
                        raw: val.to_le_bytes().to_vec(),
                        value: reloc.clone()
                    }
                })
                .collect()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RelocationsEx {
    pub blocks: Vec<HeaderField<RelocBlockEx>>
}

impl From<&Relocations> for RelocationsEx {
    fn from(value: &Relocations) -> Self {
        Self{
            blocks: value.blocks
                .iter()
                .map(|reloc| HeaderField {
                    value: RelocBlockEx::from(&reloc.value),
                    rva: reloc.rva, 
                    offset: reloc.offset, 
                    size: reloc.size,
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{pe::{relocs::RelocBlock, ser::full::relocs::RelocBlockEx}, types::Header};

    #[test]
    fn reloc_block_full_json() {
        let rb_bytes = [0x00 as u8, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00];
        let rbytes = [0xB8 as u8, 0xA0, 0xC0, 0xA0];
        
        let mut rb = RelocBlock::parse_bytes(rb_bytes.to_vec(), 0x4800).unwrap();
        rb.parse_relocs(&rbytes, 0x4808).unwrap();
        rb.fix_rvas(0x0000d000);
        
        let relocx = RelocBlockEx::from(&rb);
        assert_eq!(relocx.virtual_address.raw, vec![0x00, 0x30, 0x00, 0x00]);
        assert_eq!(relocx.size.raw, vec![0x0c, 0x00, 0x00, 0x00]);
        assert_eq!(relocx.relocations.len(), 2);

        assert_eq!(relocx.relocations[0].raw, vec![0xb8, 0xa0]);

    }
}
