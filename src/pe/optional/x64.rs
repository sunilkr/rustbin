use std::{mem::size_of, io::{Cursor, Result}};

use byteorder::{ReadBytesExt, LittleEndian};
use derivative::Derivative;

use crate::types::{HeaderField, Header};

use super::{ImageType, SubSystem, Flags};

pub const HEADER_LENGTH: u64 = 112;

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct OptionalHeader64{
    #[derivative(Default(value="HeaderField{value: Default::default(), offset: 0, rva: 0}"))]
    pub magic: HeaderField<ImageType>,
    #[derivative(Default(value="Default::default()"))]
    pub major_linker_ver: HeaderField<u8>,
    #[derivative(Default(value="Default::default()"))]
    pub minor_linker_ver: HeaderField<u8>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_code: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_initiailized_data: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_uninitiailized_data: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub address_of_entry_point: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub base_of_code: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub image_base: HeaderField<u64>,
    #[derivative(Default(value="Default::default()"))]
    pub section_alignment: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub file_alignment: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub major_os_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub minor_os_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub major_image_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub minor_image_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub major_subsystem_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub minor_subsystem_version: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub win32_version: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_image: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_headers: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub checksum: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub subsystem: HeaderField<SubSystem>,
    #[derivative(Default(value="Default::default()"))]
    pub dll_charactristics: HeaderField<u16>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_stack_reserve: HeaderField<u64>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_stack_commit: HeaderField<u64>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_heap_reserve: HeaderField<u64>,
    #[derivative(Default(value="Default::default()"))]
    pub sizeof_heap_commit: HeaderField<u64>,
    #[derivative(Default(value="Default::default()"))]
    pub loader_flags: HeaderField<u32>,
    #[derivative(Default(value="Default::default()"))]
    pub number_of_rva_and_sizes: HeaderField<u32>,
}

impl OptionalHeader64 {
    fn new_header_field<T>(value: T, offset: &mut u64) -> HeaderField<T> {
        let old_offset = *offset;
        *offset = *offset + (size_of::<T>() as u64);
        
        HeaderField::<T>{
            value,
            offset: old_offset,
            rva: old_offset,
        }
    }

    pub fn flags(&self) -> Option<Flags> {
        Flags::from_bits(self.dll_charactristics.value)
    }
}

impl Header for OptionalHeader64 {
    fn parse_bytes(bytes: &[u8], pos: u64) -> Result<Self> where Self: Sized {
        let mut hdr = Self {..Default::default() };
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;
        
        hdr.magic = Self::new_header_field(ImageType::from(cursor.read_u16::<LittleEndian>()?), &mut offset);
        hdr.major_linker_ver = Self::new_header_field(cursor.read_u8()?, &mut offset);
        hdr.minor_linker_ver = Self::new_header_field(cursor.read_u8()?, &mut offset);
        hdr.sizeof_code = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_initiailized_data = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_uninitiailized_data = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.address_of_entry_point = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.base_of_code = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        //hdr.base_of_data = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.image_base = Self::new_header_field(cursor.read_u64::<LittleEndian>()?, &mut offset);
        hdr.section_alignment = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.file_alignment = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.major_os_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_os_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.major_image_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_image_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.major_subsystem_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_subsystem_version = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.win32_version = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_image = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_headers = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.checksum = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);        
        hdr.subsystem = Self::new_header_field( SubSystem::from(cursor.read_u16::<LittleEndian>()?), &mut offset);
        offset += 1; //sizeof(SubSystem) is 1!!??
        hdr.dll_charactristics = Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.sizeof_stack_reserve = Self::new_header_field(cursor.read_u64::<LittleEndian>()?, &mut offset);
        hdr.sizeof_stack_commit = Self::new_header_field(cursor.read_u64::<LittleEndian>()?, &mut offset);
        hdr.sizeof_heap_reserve = Self::new_header_field(cursor.read_u64::<LittleEndian>()?, &mut offset);
        hdr.sizeof_heap_commit = Self::new_header_field(cursor.read_u64::<LittleEndian>()?, &mut offset);
        hdr.loader_flags = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.number_of_rva_and_sizes = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        
        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        self.magic.value == ImageType::PE64
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }
}



#[cfg(test)]
mod tests {
    use crate::{types::Header, pe::optional::{SubSystem, Flags, ImageType}};

    use super::OptionalHeader64;


    const  RAW_BYTES: [u8; 112] = [
                                                        0x0B, 0x02, 0x0E, 0x1C, 0x00, 0x7E, 0x03, 0x00,
        0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x71, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xF0, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x60, 0x81,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_valid_x64() {
        let opt = OptionalHeader64::parse_bytes(&RAW_BYTES, 0x108).unwrap();
        assert!(opt.is_valid());
        assert_eq!(opt.magic.value, ImageType::PE64);
        assert_eq!(opt.magic.offset, 0x108);
        assert_eq!(opt.major_linker_ver.value, 0x0e);
        assert_eq!(opt.minor_linker_ver.value, 0x1c);
        assert_eq!(opt.sizeof_code.value, 0x37e00);
        assert_eq!(opt.sizeof_initiailized_data.value, 0x14000);
        assert_eq!(opt.sizeof_uninitiailized_data.value, 0);
        assert_eq!(opt.address_of_entry_point.value, 0x37174);
        assert_eq!(opt.base_of_code.value, 0x1000);
        assert_eq!(opt.image_base.value, 0x0000000140000000);
        assert_eq!(opt.section_alignment.value, 0x1000);
        assert_eq!(opt.file_alignment.value, 0x200);
        assert_eq!(opt.major_os_version.value, 6);
        assert_eq!(opt.minor_os_version.value, 0);
        assert_eq!(opt.major_image_version.value, 0);
        assert_eq!(opt.minor_image_version.value, 0);
        assert_eq!(opt.major_subsystem_version.value, 6);
        assert_eq!(opt.minor_subsystem_version.value, 0);
        assert_eq!(opt.win32_version.value, 0);
        assert_eq!(opt.sizeof_image.value, 0x4f000);
        assert_eq!(opt.sizeof_headers.value, 0x400);
        assert_eq!(opt.checksum.value, 0);
        assert_eq!(opt.subsystem.value, SubSystem::WINDOWS_CUI);
        assert_eq!(opt.flags().unwrap(), Flags::DYNAMIC_BASE | Flags::NX_COMPAT | Flags::TERMINAL_SERVER_AWARE | Flags::HIGH_ENTROPY_VA);
        assert_eq!(opt.sizeof_stack_reserve.value, 0x0000000000100000);
        assert_eq!(opt.sizeof_stack_commit.value,  0x0000000000001000);
        assert_eq!(opt.sizeof_heap_reserve.value, 0x0000000000100000);
        assert_eq!(opt.sizeof_heap_commit.value,  0x0000000000001000);
        assert_eq!(opt.loader_flags.value, 0);
        assert_eq!(opt.number_of_rva_and_sizes.value, 0x10);
        assert_eq!(opt.number_of_rva_and_sizes.offset, 0x174);
        assert_eq!(opt.number_of_rva_and_sizes.rva, 0x174);
    }
}