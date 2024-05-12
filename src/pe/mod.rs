pub mod dos;
pub mod file;
pub mod optional;
pub mod section;
pub mod import;
pub mod export;
pub mod relocs;
pub mod rsrc;
pub mod ser;

use std::{
    fmt::Write, fs::File, io::{BufReader, Error, Read, Seek, SeekFrom}
};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::{types::{Header, HeaderField}, utils::{self, ContentBase, Reader}, Result};

use self::{
    dos::DosHeader,
    file::FileHeader,
    optional::{
        parse_data_directories, x64::OptionalHeader64, x86::OptionalHeader32, DataDirectory,
        ImageType, OptionalHeader, DATA_DIRS_LENGTH, DirectoryType,
    }, 
    section::{SectionHeader, SectionTable, BadRvaError}, import::ImportDirectory, export::ExportDirectory, relocs::Relocations, rsrc::ResourceDirectory,
};

/**
Returns a `HeaderField` with `value`, `offset` and `rva` from parameters.  
`offset` is incremented by `size_of_val` of the **value**.  
If `rva` is not given `rva = offset` is assumed.
*/
#[macro_export]
macro_rules! new_header_field {
    ($value:expr, $offset:ident, $rva:expr) => {
        #[allow(unused_assignments)]
        {
            use std::mem::size_of_val;

            let old_offset = $offset;
            let v = $value;

            $offset += size_of_val(&v) as u64;
            
            HeaderField{
                value: v,
                offset: old_offset,
                rva: $rva
            }
        }
    };
    
    ($value:expr, $offset:ident) => {
        {
            let old_offset = $offset;
            new_header_field!($value, $offset, old_offset)
        }
    };
}

pub const SECTION_HEADER_LENGTH: u64 = section::HEADER_LENGTH;

#[derive(Debug)]
pub struct PeImage {
    pub dos: HeaderField<DosHeader>,
    pub file: HeaderField<FileHeader>,
    pub optional: HeaderField<OptionalHeader>,
    pub data_dirs: HeaderField<Vec<HeaderField<DataDirectory>>>,
    pub sections: HeaderField<SectionTable>,
    pub imports: HeaderField<ImportDirectory>,
    pub exports: HeaderField<ExportDirectory>,
    pub relocations: HeaderField<Relocations>,
    pub resources: HeaderField<ResourceDirectory>,
    content: Vec<u8>,
}

impl PeImage {
    pub fn directory_offset(&self, dir: DirectoryType) -> Option<u32> {
        if let Some(dir) = self.directory(dir) {
            let rva = dir.rva.value;
            section::rva_to_offset(&self.sections.value, rva)
        }
        else {
            None
        }
    }

    pub fn directory_section(&self, dir: DirectoryType) -> Option<&SectionHeader> {
        if let Some(dir) = self.directory(dir) {
            let rva = dir.rva.value;
            section::rva_to_section(&self.sections.value, rva)
        }
        else {
            None
        }
    }

    #[inline]
    pub fn directory(&self, dir: DirectoryType) -> Option<&DataDirectory> {
        let dir = &self.data_dirs.value[dir as usize].value;
        if dir.rva.value == 0 {None} else {Some(&dir)}
    }

    #[inline]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        section::rva_to_offset(&self.sections.value, rva)
    }

    #[inline]
    pub fn offset_to_rva(&self, offset: u64) -> Option<u32> {
        section::offset_to_rva(&self.sections.value, offset as u32)
    }

    pub fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        utils::read_string_at_offset(&self.content, offset as u64)
    }

    #[inline]
    pub fn has_imports(&self) -> bool {
        self.data_dirs.value[DirectoryType::Import as usize].value.rva.value != 0
    }

    pub fn parse_import_directory(&mut self) -> Result<()> {
        if !self.has_imports() {
            return Ok(());
        }

        let import_dd = &self.data_dirs.value[DirectoryType::Import as usize].value;
        let import_rva = import_dd.rva.value;
        let import_size = import_dd.size.value;
        let import_offset = self.rva_to_offset(import_rva).ok_or(BadRvaError(import_rva.into()))?;
        
        let mut reader = ContentBase::new(&self.content);
        let bytes = reader.read_bytes_at_offset(import_offset as u64, import_size as usize)?;
    
        let mut imp_dir = ImportDirectory::parse_bytes(bytes.as_ref(), import_rva as u64)?;

        for i in 0..imp_dir.len() {
            let id = &mut imp_dir[i].value;
            id.update_name(&self.sections.value, &mut reader)?;
            id.parse_imports(&self.sections.value, self.optional.value.get_image_type(), &mut reader)?;
        }
        self.imports = HeaderField{ value: imp_dir, offset:import_offset as u64, rva:import_rva as u64};
        
        Ok(())
    }

    #[inline]
    pub fn has_exports(&self) -> bool {
        self.data_dirs.value[DirectoryType::Export as usize].value.rva.value != 0
    }

    pub fn parse_exports(&mut self) -> Result<()> {
        let dd_export = &self.data_dirs.value[DirectoryType::Export as usize].value;
        if !self.has_exports() {
            return Ok(());
        }

        let export_rva = dd_export.rva.value;
        let export_offset = self.rva_to_offset(export_rva).ok_or(BadRvaError(export_rva.into()))?;

        let mut reader = ContentBase::new(&self.content);
        let bytes = reader.read_bytes_at_offset(export_offset.into(), export::HEADER_LENGTH as usize)?;
        
        let mut export_dir = ExportDirectory::parse_bytes(&bytes, export_offset.into())?;
        if !export_dir.is_valid() {
            return Err(
                Box::new(
                    Error::new(
                        std::io::ErrorKind::InvalidData, 
                        format!("Invalid export directory structure at offset {:x}", export_offset)
                    )
                )
            );
        }

        export_dir.parse_exports(&self.sections.value, &mut reader)?;
        
        self.exports = HeaderField {
            value: export_dir, 
            offset: export_offset.into(), 
            rva: export_rva.into() 
        };

        Ok(())
    }

    #[inline]
    pub fn has_relocations(&self) -> bool{
        self.data_dirs.value[DirectoryType::Relocation as usize].value.rva.value != 0
    }

    pub fn parse_relocations(&mut self) -> Result<()> {
        if !self.has_relocations() {
            return Ok(());
        }

        let dd_relocs = &self.data_dirs.value[DirectoryType::Relocation as usize].value;
        let relocs_rva = dd_relocs.rva.value;
        let relocs_size = dd_relocs.size.value as usize;
        let relocs_offset = self.rva_to_offset(relocs_rva.into()).ok_or(BadRvaError(relocs_rva.into()))?;

        let mut reader = ContentBase::new(&self.content);
        let bytes = reader.read_bytes_at_offset(relocs_offset.into(), relocs_size)?;

        let mut relocs = Relocations::parse_bytes(&bytes, relocs_offset.into())?;
        relocs.fix_rvas(relocs_rva.into())?;
        self.relocations = HeaderField {value: relocs, offset: relocs_offset.into(), rva: relocs_rva.into()};

        Ok(())
    }

    #[inline]
    pub fn has_rsrc(&self) -> bool {
        self.data_dirs.value[DirectoryType::Resource as usize].value.rva.value != 0
    }

    pub fn parse_resources(&mut self) -> Result<()> {
        if !self.has_rsrc() {
            return Ok(())
        }

        let dd_rsrc = &self.data_dirs.value[DirectoryType::Resource as usize].value;
        let rsrc_rva = dd_rsrc.rva.value;
        let rsrc_size = dd_rsrc.size.value as usize;
        let rsrc_offset = self.rva_to_offset(rsrc_rva.into()).ok_or(BadRvaError(rsrc_rva.into()))?;

        let mut reader = ContentBase::new(&self.content);
        let bytes = reader.read_bytes_at_offset(rsrc_offset.into(), rsrc::DIR_LENGTH as usize)?;

        let mut rsrc_dir = ResourceDirectory::parse_bytes(&bytes, rsrc_offset.into())?;
        rsrc_dir.parse_rsrc(rsrc_rva.into(), rsrc_offset.into(), rsrc_size as u64, &mut reader)?;
        self.resources = HeaderField{value: rsrc_dir, offset: rsrc_offset.into(), rva: rsrc_rva.into()};

        Ok(())
    }

    pub fn dump_resource_tree(&self, f: &mut dyn Write, seperator: &String, level: u8) -> std::fmt::Result {
        rsrc::dump_rsrc_tree(&self.resources.value, f, seperator, level)
    }

}

impl Header for PeImage {
    fn parse_file(f: &mut BufReader<File>, pos: u64) -> crate::Result<Self> where Self: Sized {
        f.seek(SeekFrom::Start(pos))?;
        let mut bytes:Vec<u8> = Vec::new();
        let _read = f.read_to_end(&mut bytes)?;
        return Self::parse_bytes(&bytes, pos);
    }
    
    fn parse_bytes(bytes: &[u8], pos: u64) -> crate::Result<Self> where Self: Sized {
        let dos_header = DosHeader::parse_bytes(&bytes, pos)?;

        let mut slice_start = pos + dos_header.e_lfanew.value as u64;
        let mut slice_end = slice_start + file::HEADER_LENGTH;
        let hf_dos = HeaderField {
            value: dos_header,
            offset: pos,
            rva: pos,
        };
        let mut buf = &bytes[slice_start as usize..slice_end as usize];
        let file_header = FileHeader::parse_bytes(buf, slice_start)?;
        let hf_file = HeaderField {
            value: file_header,
            offset: slice_start,
            rva: slice_start,
        };

        slice_start = slice_end;
        slice_end = slice_start + 2;
        let opt_magic =
            (&bytes[slice_start as usize..slice_end as usize]).read_u16::<LittleEndian>()?;

        let opt_hdr = match ImageType::from(opt_magic) {
            ImageType::PE32 => {
                slice_end = slice_start + optional::x86::HEADER_LENGTH;
                buf = &bytes[slice_start as usize..slice_end as usize];
                OptionalHeader::X86(OptionalHeader32::parse_bytes(buf, slice_start)?)
            }

            ImageType::PE64 => {
                slice_end = slice_start + optional::x64::HEADER_LENGTH;
                buf = &bytes[slice_start as usize..slice_end as usize];
                OptionalHeader::X64(OptionalHeader64::parse_bytes(buf, slice_start)?)
            }

            _ => {
                return Err(Box::new(Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid Optional Header Magic; {:X}", opt_magic),
                )))
            }
        };
        let hf_opt = HeaderField {
            value: opt_hdr,
            offset: slice_start,
            rva: slice_start,
        };

        slice_start = slice_end;
        slice_end = slice_start + DATA_DIRS_LENGTH;
        buf = &bytes[slice_start as usize..slice_end as usize];
        let data_dirs = parse_data_directories(&buf, 16, slice_start)?;
        let data_dir_hdr = HeaderField {value: data_dirs, offset: slice_start, rva: slice_start};

        slice_start = slice_end;
        let sec_count = hf_file.value.sections.value;
        slice_end = slice_end + (sec_count as u64 * SECTION_HEADER_LENGTH);
        buf = &bytes[slice_start as usize..slice_end as usize];
        let sections = section::parse_sections(buf, sec_count, slice_start)?;
        let hf_sections = HeaderField {value: sections, offset: slice_start, rva: slice_start};

        //parse imports
        let mut image = Self {
            dos: hf_dos,
            file: hf_file,
            optional: hf_opt,
            data_dirs: data_dir_hdr,
            sections: hf_sections,
            imports: Default::default(),
            exports: Default::default(),
            relocations: Default::default(),
            resources: Default::default(),
            content: Vec::from(bytes),
        };

        image.parse_import_directory()?;
        image.parse_exports()?;
        image.parse_relocations()?;
        image.parse_resources()?;

        Ok(image)

    }

    fn is_valid(&self) -> bool {
        self.dos.value.is_valid() 
        && self.file.value.is_valid()
        && self.optional.value.is_valid()
    }

    fn length() -> usize {
        unimplemented!()
    }
}

impl std::fmt::Display for PeImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DosHeader: {}", self.dos.value)?;
        writeln!(f, "FileHeader: {}", self.file.value)?;
        writeln!(f, "OptionalHeader: {}", self.optional.value)?;
        
        //Data directories
        writeln!(f, "DataDirectories: [")?;
        for dir in &self.data_dirs.value {
            if dir.value.rva.value != 0 {
                write!(f, "  {}, ", dir)?;
                let section = self.directory_section(dir.value.member);
                if let Some(sec) = section {
                    writeln!(f, " Section: {},", sec.name_str().unwrap_or_else(|err| format!("{err}")))?;
                }
                println!("");
            }
        }
        writeln!(f, "]")?;

        //Sections
        writeln!(f, "Sections: [")?;
        for sec in &self.sections.value {
            write!(f, "  {sec}, ")?;
            let dirs = sec.value.directories(&self.data_dirs.value);
            if dirs.len() > 0 { writeln!(f, "Directories: {dirs:?},")?;} else {writeln!(f, "")?;}
        }
        writeln!(f, "]")?;

        //Imports
        if self.has_imports() && self.imports.value.is_valid() {
            writeln!(f, "Import Directory: [")?;
            let idir = &self.imports.value;
            for idesc in idir {
                writeln!(f, " {}\n [", idesc.value)?;
                for imp_name in idesc.value.get_imports_str() {
                    writeln!(f, "    {imp_name}",)?;
                }
                writeln!(f, "  ]")?;
            }
            writeln!(f, "]")?;
        }
        
        //Exports
        if self.has_exports() && self.exports.value.is_valid() {
            writeln!(f, "Export Directory: {{")?;
            let export_dir = &self.exports.value;
            writeln!(f, "  DLL Name: {}", export_dir.name)?;
            writeln!(f, "  Exports: [")?;
            
            for export in &export_dir.exports {
                writeln!(f, "    {export}")?;
            }
            
            writeln!(f, "  ]")?;
            writeln!(f, "}}")?;
        }
        
        //Relocations
        if self.has_relocations() && self.relocations.value.is_valid() {
            writeln!(f, "Relocation Directory: [")?;
            for rb in &self.relocations.value.blocks {
                writeln!(f, "  [{rb}")?;
                for rc in &rb.value.relocs {
                    writeln!(f, "    {}", rc.value)?;
                }
                writeln!(f, "  ]")?;
            }
            writeln!(f, "]")?;
        }

        //Resources
        if self.has_rsrc() && self.resources.value.is_valid() {
            self.dump_resource_tree(f, &String::from("  "), 1)?;
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    //use std::assert_matches::assert_matches;

    use crate::{
        pe::{optional::{DirectoryType, ImageType, OptionalHeader, MAX_DIRS}, section::Flags},
        types::Header, utils,
    };

    use super::PeImage;

    const RAW_BYTES_64: [u8; 704] = [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
        0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF0, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01,
        0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D,
        0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20,
        0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x93, 0xC1, 0x57, 0x47, 0xF2, 0xAF,
        0x04, 0x47, 0xF2, 0xAF, 0x04, 0x47, 0xF2, 0xAF, 0x04, 0x4E, 0x8A, 0x3C, 0x04, 0x4B, 0xF2,
        0xAF, 0x04, 0x2B, 0x86, 0xAE, 0x05, 0x45, 0xF2, 0xAF, 0x04, 0x2B, 0x86, 0xAA, 0x05, 0x51,
        0xF2, 0xAF, 0x04, 0x2B, 0x86, 0xAB, 0x05, 0x4E, 0xF2, 0xAF, 0x04, 0x2B, 0x86, 0xAC, 0x05,
        0x44, 0xF2, 0xAF, 0x04, 0x1C, 0x9A, 0xAE, 0x05, 0x4E, 0xF2, 0xAF, 0x04, 0x47, 0xF2, 0xAE,
        0x04, 0xEB, 0xF2, 0xAF, 0x04, 0x47, 0xF2, 0xAF, 0x04, 0xDD, 0xF2, 0xAF, 0x04, 0x91, 0x86,
        0xAD, 0x05, 0x46, 0xF2, 0xAF, 0x04, 0x52, 0x69, 0x63, 0x68, 0x47, 0xF2, 0xAF, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 0x91, 0xC0, 0x02, 0x62, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00, 0x0B, 0x02, 0x0E, 0x1C, 0x00, 0x2A,
        0x04, 0x00, 0x00, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x1D, 0x04, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x60, 0x81, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x42, 0x05, 0x00, 0xB4, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x05, 0x00, 0xFC,
        0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x05, 0x00,
        0xF8, 0x05, 0x00, 0x00, 0x40, 0xC7, 0x04, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC9,
        0x04, 0x00, 0x28, 0x00, 0x00, 0x00, 0xA0, 0xC7, 0x04, 0x00, 0x38, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0x00, 0x08, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00,
        0x00, 0x00, 0x47, 0x29, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x2A, 0x04, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0xD6, 0x0D, 0x01,
        0x00, 0x00, 0x40, 0x04, 0x00, 0x00, 0x0E, 0x01, 0x00, 0x00, 0x2E, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E,
        0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x68, 0x03, 0x00, 0x00, 0x00, 0x50, 0x05, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3C, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61,
        0x00, 0x00, 0xFC, 0x3F, 0x00, 0x00, 0x00, 0x60, 0x05, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x3E, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0xF8, 0x05, 0x00,
        0x00, 0x00, 0xA0, 0x05, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x7E, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42,
    ];

    #[test]
    fn parse_valid_header_x64() {
        let pe = PeImage::parse_bytes(&RAW_BYTES_64, 0).unwrap();
        assert!(pe.dos.value.is_valid());
        assert_eq!(pe.dos.offset, 0);
        assert_eq!(pe.dos.rva, 0);
        assert!(pe.file.value.is_valid());
        assert_eq!(pe.file.offset, 0xf0);
        assert_eq!(pe.file.rva, 0xf0);
        assert_eq!(pe.optional.offset, 0x108);
        assert_eq!(pe.optional.rva, 0x108);
        
        if let OptionalHeader::X64(opt) = pe.optional.value {
            assert_eq!(opt.magic.value, ImageType::PE64);
        }
        else {
            assert!(false, "Didn't expect OptionalHeader32");
        }

        assert_eq!(pe.data_dirs.offset, 0x178);
        assert_eq!(pe.data_dirs.value.len(), MAX_DIRS as usize);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].offset, 0x1d8);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].value.rva.value, 0x00044000);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].value.size.value, 0x00000308);
        /*
        Sections
        0@1f8: .text,  VS: 42947, VA: 1000,  RS: 42A00, RA: 400,   CH: 60000020
        1@220: .rdata, VS: 10dd6, VA: 44000, RS: 10E00, RA: 42E00, CH: 40000040
        2@248: .data,  VS: 368,   VA: 55000, RS: 200,   RA: 53C00, CH: C0000040
        3@270: .pdata, VS: 3FFC,  VA: 56000, RS: 4000,  RA: 53E00, CH: 40000040
        4@298: .reloc, VS: 5f8,   VA: 5A000, RS: 600,   RA: 57E00, CH: 42000040
        */

        assert_eq!(pe.sections.value.len(), 5);
        let sec_names = [
            ".text",
            ".rdata",
            ".data",
            ".pdata",
            ".reloc"
        ];
        
        let sec_flags = [
            Flags::CODE | Flags::MEM_READ | Flags::MEM_EXECUTE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_WRITE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_DISCARDABLE,
        ];

        for i in 0..5 {
            let sec = &pe.sections.value[i].value;
            assert_eq!(sec.name_str().unwrap(), sec_names[i]);
            assert_eq!(sec.flags().unwrap(), sec_flags[i]);
        }
    }

    #[test]
    fn read_string_at_offset() {
        let pe = PeImage::parse_bytes(&RAW_BYTES_64, 0).unwrap();
        assert_eq!(utils::read_string_at_offset(&pe.content, 0x1f8).unwrap().as_str(), ".text");
    }

    const RAW_BYTES_32: [u8; 784] = [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
        0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x01, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01,
        0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D,
        0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20,
        0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x96, 0x94, 0xCA, 0x72, 0xF7, 0xFA,
        0x99, 0x72, 0xF7, 0xFA, 0x99, 0x72, 0xF7, 0xFA, 0x99, 0xC6, 0x6B, 0x0B, 0x99, 0x78, 0xF7,
        0xFA, 0x99, 0xC6, 0x6B, 0x09, 0x99, 0xF6, 0xF7, 0xFA, 0x99, 0xC6, 0x6B, 0x08, 0x99, 0x6A,
        0xF7, 0xFA, 0x99, 0x49, 0xA9, 0xF9, 0x98, 0x60, 0xF7, 0xFA, 0x99, 0x49, 0xA9, 0xFF, 0x98,
        0x51, 0xF7, 0xFA, 0x99, 0x49, 0xA9, 0xFE, 0x98, 0x60, 0xF7, 0xFA, 0x99, 0xAF, 0x08, 0x34,
        0x99, 0x73, 0xF7, 0xFA, 0x99, 0xAF, 0x08, 0x31, 0x99, 0x75, 0xF7, 0xFA, 0x99, 0x72, 0xF7,
        0xFB, 0x99, 0x06, 0xF7, 0xFA, 0x99, 0xE5, 0xA9, 0xF3, 0x98, 0x77, 0xF7, 0xFA, 0x99, 0xE0,
        0xA9, 0x05, 0x99, 0x73, 0xF7, 0xFA, 0x99, 0x72, 0xF7, 0x6D, 0x99, 0x73, 0xF7, 0xFA, 0x99,
        0xE5, 0xA9, 0xF8, 0x98, 0x73, 0xF7, 0xFA, 0x99, 0x52, 0x69, 0x63, 0x68, 0x72, 0xF7, 0xFA,
        0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x4C, 0x01, 0x06, 0x00, 0xA0, 0x65, 0x08, 0x58, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x02, 0x01, 0x0B, 0x01, 0x0E, 0x00,
        0x00, 0xBC, 0x00, 0x00, 0x00, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9B, 0x20, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00,
        0xF1, 0xE2, 0x01, 0x00, 0x02, 0x00, 0x40, 0x81, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x26, 0x01, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x01, 0x00, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xD0, 0x01,
        0x00, 0x98, 0x0F, 0x00, 0x00, 0x80, 0x1D, 0x01, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x1D, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x74, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74,
        0x00, 0x00, 0x00, 0xEB, 0xBB, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xBC, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x8E, 0x5F,
        0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x78, 0x13, 0x00, 0x00, 0x00, 0x30, 0x01,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x67, 0x66, 0x69, 0x64,
        0x73, 0x00, 0x00, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x28, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0xE8, 0x64,
        0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x2A, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
        0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x98, 0x0F, 0x00, 0x00, 0x00, 0xD0, 0x01,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_valid_header_x86() {
        let pe = PeImage::parse_bytes(&RAW_BYTES_32, 0);
        let pe = pe.unwrap();
        assert!(pe.dos.value.is_valid());
        assert_eq!(pe.dos.offset, 0);
        assert_eq!(pe.dos.rva, 0);
        assert!(pe.file.value.is_valid());
        assert_eq!(pe.file.offset, 0x110);
        assert_eq!(pe.file.rva, 0x110);
        assert_eq!(pe.optional.offset, 0x128);
        assert_eq!(pe.optional.rva, 0x128);

        if let OptionalHeader::X86(opt) = pe.optional.value {
            assert!(opt.is_valid());
        }
        else {
            assert!(false, "Didn't expect OptionalHeader64");
        }

        assert_eq!(pe.data_dirs.offset, 0x188);
        assert_eq!(pe.data_dirs.value.len(), MAX_DIRS as usize);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].offset, 0x1e8);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].value.rva.value,  0x0000D000);
        assert_eq!(pe.data_dirs.value[DirectoryType::ImportAddressTable as usize].value.size.value, 0x00000174);

        let sections = pe.sections.value;
        assert_eq!(sections.len(), 6);
        let names = [".text", ".rdata", ".data", ".gfids", ".rsrc", ".reloc"];
        let sec_flags = [
            Flags::CODE | Flags::MEM_READ | Flags::MEM_EXECUTE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_WRITE,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ,
            Flags::INITIALIZED_DATA | Flags::MEM_READ | Flags::MEM_DISCARDABLE,
        ];
        for i in 0..6 {
            let hf_section = &sections[i];
            let sh = &hf_section.value;
            assert!(sh.is_valid());
            assert_eq!(sh.name_str().unwrap(), names[i]);
            assert_eq!(sh.flags().unwrap(), sec_flags[i]);
        }
    }

    #[test]
    fn section_of_directories() {
        let pe = PeImage::parse_bytes(&RAW_BYTES_32, 0).unwrap();
        assert_eq!(pe.directory_section(DirectoryType::Import).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::Resource).unwrap().name_str().unwrap(), ".rsrc");
        assert_eq!(pe.directory_section(DirectoryType::Security).unwrap().name_str().unwrap(), ".rsrc");
        assert_eq!(pe.directory_section(DirectoryType::Relocation).unwrap().name_str().unwrap(), ".reloc");
        assert_eq!(pe.directory_section(DirectoryType::Debug).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::Configuration).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::ImportAddressTable).unwrap().name_str().unwrap(), ".rdata");
    }
}
