use std::{io::{Error, Cursor, Read}, fmt::Display};
use byteorder::{ReadBytesExt, LittleEndian};
use serde::Serialize;

use crate::types::{Header, HeaderField, new_header_field};

pub const HEADER_LENGTH: u64 = 8;

#[repr(u8)]
#[derive(Debug, Default)]
pub enum I86Type {
    ABSOLUTE = 0x00,
    DIR16 = 0x01,
    REL16 = 0x02,
    DIR32 = 0x06,
    DIR32NB = 0x07,
    SEG12 = 0x09,
    SECTION = 0x0A,
    SECREL = 0x0B,
    TOKEN = 0x0C,
    SECREL7 = 0x0D,
    REL32 = 0x14,
    #[default]
    UNKNOWN = 0xFF,
}

impl From<u8> for I86Type {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::ABSOLUTE,
            0x01 => Self::DIR16,
            0x02 => Self::REL16,
            0x06 => Self::DIR32,
            0x07 => Self::DIR32NB,
            0x09 => Self::SEG12,
            0x0A => Self::SECTION,
            0x0B => Self::SECREL,
            0x0C => Self::TOKEN,
            0x0D => Self::SECREL7,
            0x14 => Self::REL32,
            _ => Self::UNKNOWN
        }
    }
}

#[repr(u8)]
#[derive(Debug, Default)]
pub enum X64Type {
    ABSOLUTE = 0x00,
    ADDR64 = 0x01,
    ADDR32 = 0x02,
    ADDR32NB = 0x03,
    REL32 = 0x04,
    REL32_1 = 0x05,
    REL32_2 = 0x06,
    REL32_3 = 0x07,
    REL32_4 = 0x08,
    REL32_5 = 0x09,
    SECTION = 0x0A,
    SECREL = 0x0B,
    SECREL7 = 0x0C,
    TOKEN = 0x0D,
    SREL32 = 0x0E,
    PAIR = 0x0F,
    SSPAN32 = 0x10,
    #[default]
    UNKNOWN = 0xFF,
}

impl From<u8> for X64Type {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::ABSOLUTE,
            0x01 => Self::ADDR64,
            0x02 => Self::ADDR32,
            0x03 => Self::ADDR32NB,
            0x04 => Self::REL32,
            0x05 => Self::REL32_1,
            0x06 => Self::REL32_2,
            0x07 => Self::REL32_3,
            0x08 => Self::REL32_4,
            0x09 => Self::REL32_5,
            0x0A => Self::SECTION,
            0x0B => Self::SECREL,
            0x0C => Self::SECREL7,
            0x0D => Self::TOKEN,
            0x0E => Self::SREL32,
            0x0F => Self::PAIR,
            0x10 => Self::SSPAN32,
            _ => Self::UNKNOWN,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy, Serialize)]
pub enum RelocType {
    // The base relocation is skipped.
    ABSOLUTE = 0x00,

    // The base relocation adds the high 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the high value of a 32-bit word.
    HIGH = 0x01,
    
    // The base relocation adds the low 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the low half of a 32-bit word.
    LOW = 0x02,
    
    // The base relocation applies all 32 bits of the difference to the 32-bit
	// field at offset.
    HIGHLOW = 0x03,
    
    // The base relocation adds the high 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the high value of a 32-bit
	// word. The low 16 bits of the 32-bit value are stored in the 16-bit word
	// that follows this base relocation. This means that this base relocation
	// occupies two slots.
    HIGHADJ = 0x04,
    
    // The relocation interpretation is dependent on the machine type.
	// When the machine type is MIPS, the base relocation applies to a MIPS jump
	// instruction.
    //MIPSJMPADDR = 0x05,
    
    // This relocation is meaningful only when the machine type is ARM or Thumb.
	// The base relocation applies the 32-bit address of a symbol across a
	// consecutive MOVW/MOVT instruction pair.
    ARM_MOV_32 = 0x05,

    // This relocation is only meaningful when the machine type is RISC-V. The
	// base relocation applies to the high 20 bits of a 32-bit absolute address.
	//ImageRelBasedRISCVHigh20 = 5

	// Reserved, must be zero.
	RESERVED = 0x06,

	// This relocation is meaningful only when the machine type is Thumb.
	// The base relocation applies the 32-bit address of a symbol to a
	// consecutive MOVW/MOVT instruction pair.
	THUMB_MOV_32 = 0x07,

	// This relocation is only meaningful when the machine type is RISC-V.
	// The base relocation applies to the low 12 bits of a 32-bit absolute
	// address formed in RISC-V I-type instruction format.
	//ImageRelBasedRISCVLow12i = 7

	// This relocation is only meaningful when the machine type is RISC-V.
	// The base relocation applies to the low 12 bits of a 32-bit absolute
	// address formed in RISC-V S-type instruction format.
	RISCV_LOW12 = 0x08,

	// The relocation is only meaningful when the machine type is MIPS.
	// The base relocation applies to a MIPS16 jump instruction.
	MIPS_JMP_ADDR16 = 0x09,

	// The base relocation applies the difference to the 64-bit field at offset.
	DIR64 = 0x0A,

    UNKNOWN(u8),
}

impl Default for RelocType {
    fn default() -> Self {
        Self::UNKNOWN(0)
    }
}

impl From<u8> for RelocType {
    fn from(value: u8) -> Self {
        //Not matching all values.
        match value {
            0x00 => Self::ABSOLUTE,
            0x01 => Self::HIGH,
            0x02 => Self::LOW,
            0x03 => Self::HIGHLOW,
            0x04 => Self::HIGHADJ,
            0x0A => Self::DIR64,
               _ => Self::UNKNOWN(value),
        }
    }
}

impl From<RelocType> for u8 {
    fn from(value: RelocType) -> u8 {
        match value {
            RelocType::ABSOLUTE => 0x00,
            RelocType::HIGH => 0x01,
            RelocType::LOW => 0x02,
            RelocType::HIGHLOW => 0x03,
            RelocType::HIGHADJ => 0x04,
            RelocType::ARM_MOV_32 => 0x05,
            RelocType::RESERVED => 0x06,
            RelocType::THUMB_MOV_32 => 0x07,
            RelocType::RISCV_LOW12 => 0x08,
            RelocType::MIPS_JMP_ADDR16 => 0x09,
            RelocType::DIR64 => 0x0A,
            RelocType::UNKNOWN(val) => val,
        }
    }
}

impl Display for RelocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
#[serde(rename="relocation")]
pub struct Reloc {
    //pub(crate) raw : u16,
    #[serde(rename="type")]
    pub rtype : RelocType,
    #[serde(rename="offset")]
    pub rva : u16,
}

impl Reloc {
    pub fn new (value: u16) -> Self {
        let rtype = ((value & 0xF000) >> 12) as u8;
        let offset = (value & 0x0FFF) as u16;
        Self {
            //raw: value,
            rtype: RelocType::from(rtype),
            rva: offset.into()
        }
    }

    pub fn fix_rvas(&mut self, _va: u32) { }
}

impl Display for Reloc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} @ {:#08X}", self.rtype, self.rva)
    }
}


#[derive(Debug, Default, Serialize)]
pub struct RelocBlock {
    #[serde(rename="virtual_address")]
    pub va : HeaderField<u32>,
    pub size : HeaderField<u32>,
    #[serde(rename="relocations")]
    pub relocs : Vec<HeaderField<Reloc>>,
}

impl Display for RelocBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{VA: {:#08X}, Size: {:#04X}}}", self.va.value, self.size.value)
    }
}

impl RelocBlock {
    pub fn fix_rvas(&mut self, rva: u64) {
        self.va.rva = Some(rva);
        self.size.rva = Some(rva + 4);

        let mut reloc_rva = rva + 8;

        for i in 0..self.relocs.len() {
            self.relocs[i].rva = Some(reloc_rva);
            reloc_rva += 2;
        }
    }

    pub fn parse_relocs(&mut self, bytes: &[u8], pos: u64) -> crate::Result<()> {
        let bytes_len = bytes.len() as u64;
        let rb_size = self.size.value as u64 - HEADER_LENGTH;
        if bytes_len < rb_size {
            return Err(
                Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Not enough data. Expected {}, Found {}", rb_size, bytes_len)
                ).into()
            );
        }

        let mut cursor = Cursor::new(bytes);

        let mut reloc_pos = pos;
        let reloc_count = rb_size / 2;

        for _ in 0..reloc_count {
            let val = cursor.read_u16::<LittleEndian>()?;            

            let mut reloc = Reloc::new(val);
            reloc.fix_rvas(self.va.value);

            self.relocs.push(HeaderField { value: reloc, offset: reloc_pos, rva: Some(reloc_pos), size: 2 });
            reloc_pos += 2;
        }
        
        Ok(())
    }
}

impl Header for RelocBlock {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err(
                Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Not enough data. Expected {}, Found {}", HEADER_LENGTH, bytes_len)
                ).into()
            );
        }

        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        let mut rb = RelocBlock::default();
        
        rb.va = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
        rb.size = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);

        Ok(rb)
    }

    fn is_valid(&self) -> bool {
        let items = ((self.size.value - 8) / 2) as usize;
        self.relocs.len() == items
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }
}


#[derive(Debug, Default, Serialize)]
pub struct Relocations {
    pub blocks: Vec<HeaderField<RelocBlock>>
}

impl Relocations {
    pub fn fix_rvas(&mut self, rva: u64) -> crate::Result<()> {
        let mut rb_rva = rva;
        
        for i in 0..self.blocks.len(){
            let rb = &mut self.blocks[i];
            rb.rva = Some(rb_rva);
            rb.value.fix_rvas(rva);
            rb_rva += rb.value.size.value as u64;
        }

        Ok(())
    }
}

impl Header for Relocations {
    fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err(
                Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Not enough data. Expected {HEADER_LENGTH}, Found {bytes_len}")
                ).into()
            );
        }

        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        let mut relocs = Relocations::default();
        let mut consumed = 0u64;

        while consumed < bytes_len {            
            let mut rb = RelocBlock::default();
            rb.va = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
            rb.size = new_header_field!(cursor.read_u32::<LittleEndian>()?, offset);
    
            let r_size = (rb.size.value as u64  - HEADER_LENGTH) as usize;
            let mut rbytes = vec![0 as u8; r_size];
            cursor.read_exact(&mut rbytes)?;

            consumed += rb.size.value as u64;

            rb.parse_relocs(&rbytes, offset + HEADER_LENGTH)?;
            let rb_size = rb.size.value;
            relocs.blocks.push(HeaderField { value: rb, offset: offset, rva: Some(offset), size: (rb_size + 8).into() }); //TODO: Check the size
            offset += r_size as u64;
        }

        Ok(relocs)
    }

    fn is_valid(&self) -> bool {
        self.blocks.len() > 0
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }
}

#[cfg(test)]
mod tests {
    use crate::{types::Header, pe::relocs::RelocType};

    use super::{RelocBlock, Relocations};

    #[test]
    fn parse_reloc_block() {
        let rb_bytes = [0x00 as u8, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00];
        //let rbytes = [0xB8 as u8, 0xA0, 0xC0, 0xA0];
        let rb = RelocBlock::parse_bytes(rb_bytes.to_vec(), 0x4800).unwrap();
        assert_eq!(rb.va.value, 0x00003000);
        assert_eq!(rb.size.value, 0x0C);
    }

    #[test]
    fn parse_reloc_block_full() {
        let rb_bytes = [0x00 as u8, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00];
        let rbytes = [0xB8 as u8, 0xA0, 0xC0, 0xA0];
        
        let mut rb = RelocBlock::parse_bytes(rb_bytes.to_vec(), 0x4800).unwrap();
        rb.parse_relocs(&rbytes, 0x4808).unwrap();
        
        assert_eq!(rb.va.value, 0x00003000);
        assert_eq!(rb.size.value, 0x0c);

        assert_eq!(rb.relocs.len(), 2);
        
        assert_eq!(rb.relocs[0].offset, 0x4808);
        assert_eq!(rb.relocs[0].value.rtype, RelocType::DIR64);
        assert_eq!(rb.relocs[0].value.rva, 0x00b8);

        assert_eq!(rb.relocs[1].offset, 0x480A);
        assert_eq!(rb.relocs[1].value.rtype, RelocType::DIR64);
        assert_eq!(rb.relocs[1].value.rva, 0x00c0);
    }

    #[test]
    fn parse_reloc_block_full_with_rva() {
        let rb_bytes = [0x00 as u8, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00];
        let rbytes = [0xB8 as u8, 0xA0, 0xC0, 0xA0];
        
        let mut rb = RelocBlock::parse_bytes(rb_bytes.to_vec(), 0x4800).unwrap();
        rb.parse_relocs(&rbytes, 0x4808).unwrap();
        rb.fix_rvas(0x0000d000);

        assert_eq!(rb.va.value, 0x00003000);
        assert_eq!(rb.va.rva, Some(0x0000d000));
        assert_eq!(rb.va.offset, 0x4800);
        
        assert_eq!(rb.size.value, 0x0C);
        assert_eq!(rb.size.rva, Some(0x0000d004));
        assert_eq!(rb.size.offset, 0x4804);
        
        assert_eq!(rb.relocs.len(), 2);

        assert_eq!(rb.relocs[0].rva, Some(0x0000d008));
        assert_eq!(rb.relocs[0].offset, 0x4808);
        assert_eq!(rb.relocs[0].value.rtype, RelocType::DIR64);
        assert_eq!(rb.relocs[0].value.rva, 0x00b8);

        assert_eq!(rb.relocs[1].rva, Some(0x0000d00a));
        assert_eq!(rb.relocs[1].offset, 0x480a);
        assert_eq!(rb.relocs[1].value.rtype, RelocType::DIR64);
        assert_eq!(rb.relocs[1].value.rva, 0x00c0);
    }

    #[test]
    fn parse_all_relocs() {
        let bytes = [
            0x00u8, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xB8, 0xA0, 0xC0, 0xA0, 0x00, 0x40, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x30, 0xA0, 0x38, 0xA0, 0x40, 0xA0, 0x50, 0xA0, 0x00, 0x00,
            0x00, 0x50, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x70, 0xA0, 0x78, 0xA0, 0x80, 0xA0, 0xA0, 0xA0,
            0xA8, 0xA0, 0xB0, 0xA0, 0xB8, 0xA0, 0x00, 0xA2, 0x10, 0xA2, 0x20, 0xA2, 0x30, 0xA2, 0x40, 0xA2,
            0x50, 0xA2, 0x60, 0xA2, 0x70, 0xA2, 0x80, 0xA2, 0x90, 0xA2, 0xA0, 0xA2, 0xB0, 0xA2, 0xC0, 0xA2,
            0xD0, 0xA2, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x18, 0xA0, 0x30, 0xA0,
            0x38, 0xA0, 0x00, 0x00
        ];
        
        let mut relocs = Relocations::parse_bytes(bytes.to_vec(), 0x4800).unwrap();
        relocs.fix_rvas(0x0000d000).unwrap();

        assert_eq!(relocs.blocks.len(), 4);
        assert_eq!(relocs.blocks[0].value.relocs.len(), 2);
        assert_eq!(relocs.blocks[1].value.relocs.len(), 6);
        assert_eq!(relocs.blocks[2].value.relocs.len(), 22);
        assert_eq!(relocs.blocks[3].value.relocs.len(), 4);

        let rb4 = &relocs.blocks[3].value;
        assert_eq!(rb4.va.value, 0x0000b000);

        assert_eq!(rb4.relocs[0].value.rtype, RelocType::DIR64);
        assert_eq!(rb4.relocs[0].value.rva, 0x00000018);
        
        assert_eq!(rb4.relocs[1].value.rtype, RelocType::DIR64);
        assert_eq!(rb4.relocs[1].value.rva, 0x00000030);

        assert_eq!(rb4.relocs[2].value.rtype, RelocType::DIR64);
        assert_eq!(rb4.relocs[2].value.rva, 0x00000038);

        assert_eq!(rb4.relocs[3].value.rtype, RelocType::ABSOLUTE);
        assert_eq!(rb4.relocs[3].value.rva, 0x00000000);
    }
}
