pub(crate) mod dos;
pub(crate) mod file;
pub(crate) mod optional;
pub(crate) mod import;

use dos::DosHeaderEx;
use file::FileHeaderEx;
use import::ImportDescriptorEx;
use num_traits::ToBytes;
use optional::OptionalHeaderEx;
use serde::Serialize;

use crate::{pe::{optional::{DataDirectory, DirectoryType}, section::{self, SectionHeader}, PeImage}, types::HeaderField};

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
    pub dos: HeaderField<DosHeaderEx>,
    pub file: HeaderField<FileHeaderEx>,
    pub optional: HeaderField<OptionalHeaderEx>,
    pub data_dirs: HeaderField<Vec<HeaderField<DataDirectoryEx>>>,
    pub sections: HeaderField<Vec<HeaderField<SectionHeaderEx>>>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub imports: Option<HeaderField<Vec<HeaderField<ImportDescriptorEx>>>>,
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
            },

            optional: HeaderField { 
                value: OptionalHeaderEx::from(&value.optional.value), 
                offset: value.optional.offset, 
                rva: value.optional.rva, 
                size: value.optional.size,
            },

            data_dirs: HeaderField{
                value: value.data_dirs.value
                    .iter()
                    .map(|dir| HeaderField {
                        value: DataDirectoryEx::from(&dir.value),
                        offset: dir.offset,
                        rva: dir.rva,
                        size: dir.size,
                    })
                    .collect(),
                offset: value.data_dirs.offset,
                rva: value.data_dirs.rva,
                size: value.data_dirs.size,
            },

            sections: HeaderField {
                value: value.sections.value
                    .iter()
                    .map(|section| HeaderField{
                        value: SectionHeaderEx::from(&section.value),
                        offset: section.offset,
                        rva: section.rva,
                        size: section.size,
                    })
                    .collect(),
                offset: value.sections.offset,
                rva: value.sections.rva,
                size: value.sections.size,
            },

            imports: if value.has_imports() {
                Some(
                    HeaderField{
                        value: value.imports.value
                            .iter()
                            .map(|id| HeaderField{
                                value: ImportDescriptorEx::from(&id.value),
                                offset: id.offset,
                                rva: id.rva,
                                size: id.size,
                            })
                            .collect(),
                        offset: value.imports.offset,
                        rva: value.imports.rva,
                        size: value.imports.size
                })
            }
            else { None },

        }
    }
}

#[derive(Debug, Serialize)]
pub struct DataDirectoryEx {
    pub member: DirectoryType,
    pub rva: HeaderFieldEx<u32>,
    pub size: HeaderFieldEx<u32>,
}

impl From<&DataDirectory> for DataDirectoryEx {
    fn from(value: &DataDirectory) -> Self {
        Self { 
            member: value.member, 
            rva: hf_to_hfx(&value.rva, ByteEndian::LE), 
            size: hf_to_hfx(&value.size, ByteEndian::LE)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SectionHeaderEx {
    pub name: HeaderFieldEx<String>,
    pub virtual_size: HeaderFieldEx<u32>, //Not using Misc.PhysicalAddress
    pub virtual_address: HeaderFieldEx<u32>,
    #[serde(rename="size_of_raw_data")]
    pub sizeof_raw_data: HeaderFieldEx<u32>,
    #[serde(rename="pointer_to_raw_data")]
    pub raw_data_ptr: HeaderFieldEx<u32>,
    #[serde(rename="pointer_to_relocations")]
    pub relocs_ptr: HeaderFieldEx<u32>,
    #[serde(rename="pointer_to_line_numbers")]
    pub line_num_ptr: HeaderFieldEx<u32>,
    #[serde(rename="number_of_relocations")]
    pub relocs_count: HeaderFieldEx<u16>,
    #[serde(rename="number_of_line_numbers")]
    pub line_num_count: HeaderFieldEx<u16>,
    pub charactristics: HeaderFieldEx<section::Flags>,
}

impl From<&SectionHeader> for SectionHeaderEx {
    fn from(value: &SectionHeader) -> Self {
        Self { 
            name: HeaderFieldEx { 
                raw: value.name.value.to_vec(), 
                value: HeaderField { 
                    value: value.name_str().unwrap_or("ERR".into()), 
                    offset: value.name.offset, 
                    rva: value.name.rva, 
                    size: value.name.size, 
                }
            },

            virtual_size: hf_to_hfx(&value.virtual_size, ByteEndian::LE),
            virtual_address: hf_to_hfx(&value.virtual_address, ByteEndian::LE),
            sizeof_raw_data: hf_to_hfx(&value.sizeof_raw_data, ByteEndian::LE),
            raw_data_ptr: hf_to_hfx(&value.raw_data_ptr, ByteEndian::LE),
            relocs_ptr: hf_to_hfx(&value.relocs_ptr, ByteEndian::LE),
            line_num_ptr: hf_to_hfx(&value.line_num_ptr, ByteEndian::LE), 
            relocs_count: hf_to_hfx(&value.relocs_count, ByteEndian::LE),
            line_num_count: hf_to_hfx(&value.line_num_count, ByteEndian::LE),
            charactristics: HeaderFieldEx { 
                raw: value.charactristics.value.to_le_bytes().to_vec(), 
                value: HeaderField { 
                    value: section::Flags::from_bits_truncate(value.charactristics.value), 
                    offset: value.charactristics.offset, 
                    rva: value.charactristics.rva, 
                    size: value.charactristics.size 
                }
            }
        }
    }
}


#[cfg(test)]
mod test {
    use crate::pe::section::{self, parse_sections};
    use super::SectionHeaderEx;

    //Tests for section header.
    const RAW_SECTION_BYTES: [u8; 240] = [
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x54, 0xAC, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0xAE, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xEC, 0x64, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0xB2, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0xB8, 0x39, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00,
        0x00, 0x16, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xB8, 0x08, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x2E, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0xA8, 0x05, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3E, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42
    ];

    const SECTION_POS: u64 = 0x200;
    const SECTION_COUNT: u16 = 6;

    #[test]
    fn ser_sections() {
        let sections = parse_sections(&RAW_SECTION_BYTES, SECTION_COUNT, SECTION_POS).unwrap();
        assert_eq!(sections.len(), 6);

        let full_sections = sections.iter()
            .map(|section| SectionHeaderEx::from(&section.value))
            .collect::<Vec<SectionHeaderEx>>();

        assert_eq!(full_sections.len(), 6);

        let s1 = &full_sections[0];
        assert_eq!(s1.name.raw.len(), 8);
        assert_eq!(s1.name.raw, vec![0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,]);
        assert_eq!(
            s1.charactristics.raw,
            (section::Flags::CODE | section::Flags::MEM_READ | section::Flags::MEM_EXECUTE)
            .bits()
            .to_le_bytes()
            .to_vec()
        );

        let s2 = &full_sections[1];
        assert_eq!(s2.name.raw.len(), 8);
        assert_eq!(s2.name.raw, vec![0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,]);
        assert_eq!(
            s2.charactristics.raw,
            (section::Flags::INITIALIZED_DATA | section::Flags::MEM_READ)
            .bits()
            .to_le_bytes()
            .to_vec()
        );
    }
}
