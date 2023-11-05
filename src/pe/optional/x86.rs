use std::{
    fmt::Display,
    io::{Cursor, Error},
};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::types::{Header, HeaderField};

use super::{Flags, ImageType, SubSystem};

pub const HEADER_LENGTH: u64 = 96;

#[derive(Debug, Default)]
pub struct OptionalHeader32 {
    pub magic: HeaderField<ImageType>,
    pub major_linker_ver: HeaderField<u8>,
    pub minor_linker_ver: HeaderField<u8>,
    pub sizeof_code: HeaderField<u32>,
    pub sizeof_initiailized_data: HeaderField<u32>,
    pub sizeof_uninitiailized_data: HeaderField<u32>,
    pub address_of_entry_point: HeaderField<u32>,
    pub base_of_code: HeaderField<u32>,
    pub base_of_data: HeaderField<u32>,
    pub image_base: HeaderField<u32>,
    pub section_alignment: HeaderField<u32>,
    pub file_alignment: HeaderField<u32>,
    pub major_os_version: HeaderField<u16>,
    pub minor_os_version: HeaderField<u16>,
    pub major_image_version: HeaderField<u16>,
    pub minor_image_version: HeaderField<u16>,
    pub major_subsystem_version: HeaderField<u16>,
    pub minor_subsystem_version: HeaderField<u16>,
    pub win32_version: HeaderField<u32>,
    pub sizeof_image: HeaderField<u32>,
    pub sizeof_headers: HeaderField<u32>,
    pub checksum: HeaderField<u32>,
    pub subsystem: HeaderField<SubSystem>,
    pub dll_charactristics: HeaderField<u16>,
    pub sizeof_stack_reserve: HeaderField<u32>,
    pub sizeof_stack_commit: HeaderField<u32>,
    pub sizeof_heap_reserve: HeaderField<u32>,
    pub sizeof_heap_commit: HeaderField<u32>,
    pub loader_flags: HeaderField<u32>,
    pub number_of_rva_and_sizes: HeaderField<u32>,
}

impl OptionalHeader32 {
    pub fn flags(&self) -> Option<Flags> {
        Flags::from_bits(self.dll_charactristics.value)
    }
}

impl Header for OptionalHeader32 {
    fn parse_bytes(bytes: &[u8], pos: u64) -> crate::Result<Self> where Self: Sized {
        let bytes_len = bytes.len() as u64;

        if bytes_len < HEADER_LENGTH {
            return Err ( 
                Box::new(Error::new (
                    std::io::ErrorKind::InvalidData, 
                    format!("Not enough data; Expected {}, Found {}", HEADER_LENGTH, bytes_len)
                ))
            );
        }
        
        let mut hdr = Self {
            ..Default::default()
        };
        let mut cursor = Cursor::new(bytes);
        let mut offset = pos;

        hdr.magic = Self::new_header_field(
            ImageType::from(cursor.read_u16::<LittleEndian>()?),
            &mut offset,
        );
        hdr.major_linker_ver = Self::new_header_field(cursor.read_u8()?, &mut offset);
        hdr.minor_linker_ver = Self::new_header_field(cursor.read_u8()?, &mut offset);
        hdr.sizeof_code = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_initiailized_data =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_uninitiailized_data =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.address_of_entry_point =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.base_of_code = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.base_of_data = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.image_base = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.section_alignment =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.file_alignment =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.major_os_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_os_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.major_image_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_image_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.major_subsystem_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.minor_subsystem_version =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.win32_version = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_image = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_headers =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.checksum = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.subsystem = Self::new_header_field(
            SubSystem::from(cursor.read_u16::<LittleEndian>()?),
            &mut offset,
        );
        offset += 1; //sizeof(SubSystem) is 1!!
        hdr.dll_charactristics =
            Self::new_header_field(cursor.read_u16::<LittleEndian>()?, &mut offset);
        hdr.sizeof_stack_reserve =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_stack_commit =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_heap_reserve =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.sizeof_heap_commit =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.loader_flags = Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);
        hdr.number_of_rva_and_sizes =
            Self::new_header_field(cursor.read_u32::<LittleEndian>()?, &mut offset);

        Ok(hdr)
    }

    fn is_valid(&self) -> bool {
        (self.magic.value == ImageType::PE32) | (self.magic.value == ImageType::ROM)
    }

    fn length() -> usize {
        HEADER_LENGTH as usize
    }

    // fn parse_file(f: &mut std::io::BufReader<std::fs::File>, pos: u64) -> std::io::Result<Self> where Self: Sized {
    //     let offset = f.seek(std::io::SeekFrom::Start(pos))?;
    //     let mut buf = vec![0x00; Self::length() as usize];
    //     f.read_exact(&mut buf)?;

    //     Ok(Self::parse_bytes(&buf, offset)?)
    // }
}

impl Display for OptionalHeader32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ImageType: {:?}, EntryPoint: {:08x}, ImageBase: {:08x}, Subsystem: {:?}, DLL Charactristics: {:?}, NumberOfRvaAndSizes: {}}}",
                    self.magic.value, self.address_of_entry_point.value, self.image_base.value, self.subsystem.value, self.flags().unwrap_or(Flags::UNKNOWN), self.number_of_rva_and_sizes.value)
    }
}

#[cfg(test)]
mod test {
    use crate::types::Header;

    use super::super::{Flags, ImageType, SubSystem};
    use super::OptionalHeader32;

    const RAW_BYTES: [u8; 460] = [
        0x0B, 0x01, 0x0E, 0x00, 0x00, 0xBC, 0x00, 0x00, 0x00, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x9B, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x01, 0x00,
        0x00, 0x04, 0x00, 0x00, 0xF1, 0xE2, 0x01, 0x00, 0x02, 0x00, 0x40, 0x81, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC,
        0x26, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0xE8, 0x64, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x01, 0x00, 0xB8, 0x1E, 0x00,
        0x00, 0x00, 0xD0, 0x01, 0x00, 0x98, 0x0F, 0x00, 0x00, 0x80, 0x1D, 0x01, 0x00, 0x70, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x1D, 0x01, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x00,
        0x00, 0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E,
        0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xEB, 0xBB, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xBC, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61,
        0x00, 0x00, 0x8E, 0x5F, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x40, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x78, 0x13, 0x00,
        0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E,
        0x67, 0x66, 0x69, 0x64, 0x73, 0x00, 0x00, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x00,
        0x00, 0x00, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
        0x2A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x98, 0x0F, 0x00,
        0x00, 0x00, 0xD0, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_valid_header() {
        let opt = OptionalHeader32::parse_bytes(&RAW_BYTES, 0x128).unwrap();
        assert!(opt.is_valid());
        assert_eq!(opt.magic.value, ImageType::PE32);
        assert_eq!(opt.magic.offset, 0x128);
        assert_eq!(opt.major_linker_ver.value, 0x0e);
        assert_eq!(opt.minor_linker_ver.value, 0x00);
        assert_eq!(opt.sizeof_code.value, 0xbc00);
        assert_eq!(opt.sizeof_initiailized_data.value, 0xec00);
        assert_eq!(opt.sizeof_uninitiailized_data.value, 0);
        assert_eq!(opt.address_of_entry_point.value, 0x209b);
        assert_eq!(opt.base_of_code.value, 0x1000);
        assert_eq!(opt.base_of_data.value, 0xd000);
        assert_eq!(opt.image_base.value, 0x00400000);
        assert_eq!(opt.section_alignment.value, 0x1000);
        assert_eq!(opt.file_alignment.value, 0x200);
        assert_eq!(opt.major_os_version.value, 6);
        assert_eq!(opt.minor_os_version.value, 0);
        assert_eq!(opt.major_image_version.value, 0);
        assert_eq!(opt.minor_image_version.value, 0);
        assert_eq!(opt.major_subsystem_version.value, 6);
        assert_eq!(opt.minor_subsystem_version.value, 0);
        assert_eq!(opt.win32_version.value, 0);
        assert_eq!(opt.sizeof_image.value, 0x1e000);
        assert_eq!(opt.sizeof_headers.value, 0x400);
        assert_eq!(opt.checksum.value, 0x1e2f1);
        assert_eq!(opt.subsystem.value, SubSystem::WINDOWS_GUI);
        assert_eq!(
            opt.flags().unwrap(),
            Flags::DYNAMIC_BASE | Flags::NX_COMPAT | Flags::TERMINAL_SERVER_AWARE
        );
        assert_eq!(opt.sizeof_stack_reserve.value, 0x00100000);
        assert_eq!(opt.sizeof_stack_commit.value, 0x00001000);
        assert_eq!(opt.sizeof_heap_reserve.value, 0x00100000);
        assert_eq!(opt.sizeof_heap_commit.value, 0x00001000);
        assert_eq!(opt.loader_flags.value, 0);
        assert_eq!(opt.number_of_rva_and_sizes.value, 0x10);
        assert_eq!(opt.number_of_rva_and_sizes.offset, 0x184);
        assert_eq!(opt.number_of_rva_and_sizes.rva, 0x184);
    }
}
