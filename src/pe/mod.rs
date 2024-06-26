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
    fmt::{Display, Write}, fs::File, io::{BufReader, Cursor}, string::{FromUtf16Error, FromUtf8Error}
};

use derivative::Derivative;

use crate::{types::{BufReadExt, Header, HeaderField, ReadExtError}, Result};

use self::{
    dos::DosHeader, export::ExportDirectory, file::FileHeader, import::ImportDirectory, 
    optional::{ parse_data_directories, x64::OptionalHeader64, x86::OptionalHeader32, DataDirectory, DirectoryType, OptionalHeader },
    relocs::Relocations, 
    rsrc::ResourceDirectory, 
    section::{rva_to_section, SectionHeader, SectionTable}
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

#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("not enough data for {target}; expected {expected}, got {actual}")]
    #[non_exhaustive]
    BufferTooSmall {
        target: String,
        expected: u64,
        actual: u64,
    },

    #[error("invalid timestamp 0x{0:08x}")]
    #[non_exhaustive]
    InvalidTimestamp(u64),

    #[error("invalid rva 0x{0:08x}")]
    #[non_exhaustive]
    InvalidRVA(u64),

    #[error("invalid offset 0x{0:08x}")]
    #[non_exhaustive]
    InvalidOffset(u64),
    
    #[error("failed to parse {name} header at offset {offset:08x}; {reason}")]
    #[non_exhaustive]
    InvalidHeader {
        name: String,
        offset: u64,
        reason: String,
    },

    #[error("can't find section for rva {0:08x}")]
    #[non_exhaustive]
    NoSectionForRVA(u64),

    #[error("can't find section for offset {0:08x}")]
    #[non_exhaustive]
    NoSectionForOffset(u64),

    #[error(transparent)]
    ReadExt(#[from] ReadExtError),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("PE file must have optional header")]
    MustHaveOptional,

    #[error(transparent)]
    FromUtf8 (#[from] FromUtf8Error),

    #[error(transparent)]
    FromUtf16 (#[from] FromUtf16Error),

    #[error("{typ} {value:08x} is beyond {name} range [{start:08x}..{end:08x}]")]
    #[non_exhaustive]
    BeyondRange {
        name: String,
        typ: String,
        value: u64,
        start: u64,
        end: u64,
    }
}


pub const SECTION_HEADER_LENGTH: u64 = section::HEADER_LENGTH;

#[derive(Derivative)]
#[derivative(Debug)]
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

    #[derivative(Debug="ignore")]
    reader: Box<dyn BufReadExt>,
}

impl PeImage {
    pub fn new(reader: Box<dyn BufReadExt>) -> Self {
        Self { 
            dos: Default::default(), 
            file: Default::default(),
            optional: Default::default(),
            data_dirs: Default::default(),
            sections: Default::default(),
            imports: Default::default(),
            exports: Default::default(),
            relocations: Default::default(),
            resources: Default::default(),
            reader
        }
    }

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

    pub fn read_string_at_rva(&mut self, rva: u32) -> std::result::Result<String, PeError> {
        let offset = self.rva_to_offset(rva).ok_or(PeError::InvalidRVA(rva.into()))?;
        Ok(self.reader.read_string_at_offset(offset.into())?)
    }

    #[inline]
    pub fn has_imports(&self) -> bool {
        self.data_dirs.value[DirectoryType::Import as usize].value.rva.value != 0
    }

    pub fn parse_import_directory(&mut self) -> std::result::Result<(), PeError> {
        if !self.has_imports() {
            return Ok(());
        }

        let import_dd = &self.data_dirs.value[DirectoryType::Import as usize].value;
        let import_rva = import_dd.rva.value;
        let import_size = import_dd.size.value;
        let import_offset = self.rva_to_offset(import_rva).ok_or(PeError::InvalidRVA(import_rva.into()))?;
        
        //let mut reader = FragmentReader::new(&self.reader);
        let bytes = self.reader.read_bytes_at_offset(import_offset as u64, import_size as usize)?;
    
        let mut imp_dir = ImportDirectory::parse_bytes(bytes, import_rva as u64)?;

        for i in 0..imp_dir.len() {
            let id = &mut imp_dir[i].value;
            id.update_name(&self.sections.value, &mut self.reader)?;
            id.parse_imports(&self.sections.value, self.optional.value.get_image_type(), &mut self.reader)?;
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
        let export_offset = self.rva_to_offset(export_rva).ok_or(PeError::InvalidRVA(export_rva.into()))?;

        //let mut reader = FragmentReader::new(&self.reader);
        let bytes = self.reader.read_bytes_at_offset(export_offset.into(), export::HEADER_LENGTH as usize)?;
        
        let mut export_dir = ExportDirectory::parse_bytes(bytes, export_offset.into())?;
        if !export_dir.is_valid() {
            return Err(
                PeError::InvalidHeader { name: "Export".into(), offset: export_offset.into(), reason: "structure is invalid".into() }
            );
        }

        export_dir.parse_exports(&self.sections.value, &mut self.reader)?;
        
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
        let relocs_offset = self.rva_to_offset(relocs_rva.into()).ok_or(PeError::NoSectionForRVA(relocs_rva.into()))?;

        //let mut reader = FragmentReader::new(&self.reader);
        let bytes = self.reader.read_bytes_at_offset(relocs_offset.into(), relocs_size)?;

        let mut relocs = Relocations::parse_bytes(bytes, relocs_offset.into())?;
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
        let rsrc_offset = self.rva_to_offset(rsrc_rva.into()).ok_or(PeError::NoSectionForRVA(rsrc_rva.into()))?;
        let rsrc_section = rva_to_section(&self.sections.value, rsrc_rva)
            .ok_or(PeError::NoSectionForRVA(rsrc_rva.into()))?;
        
        let bytes = self.reader.read_bytes_at_offset(rsrc_offset.into(), rsrc::DIR_LENGTH as usize)?;

        let mut rsrc_dir = ResourceDirectory::parse_bytes(bytes, rsrc_offset.into())?;
        rsrc_dir.parse_rsrc(rsrc_section, &mut self.reader)?;
        self.resources = HeaderField{value: rsrc_dir, offset: rsrc_offset.into(), rva: rsrc_rva.into()};

        Ok(())
    }

    #[inline]
    pub fn format_resource_tree(&self, f: &mut dyn Write, seperator: &String, level: u8) -> std::fmt::Result {
        writeln!(f, "Resource Directory: {{")?;
        rsrc::display_rsrc_tree(&self.resources.value, f, seperator, level)?;
        writeln!(f, "}}")
    }

    pub fn format_basic_headers(&self, f: &mut dyn Write) -> std::fmt::Result {
        writeln!(f, "DosHeader: {}", self.dos.value)?;
        writeln!(f, "FileHeader: {}", self.file.value)?;
        writeln!(f, "OptionalHeader: {}", self.optional.value)?;

        Ok(())
    }

    pub fn format_data_dirs(&self, f: &mut dyn Write) -> std::fmt::Result {
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
        writeln!(f, "]")
    }

    pub fn format_sections(&self, f: &mut dyn Write) -> std::fmt::Result {
        writeln!(f, "Sections: [")?;
        for sec in &self.sections.value {
            write!(f, "  {sec}, ")?;
            let dirs = sec.value.directories(&self.data_dirs.value);
            if dirs.len() > 0 { writeln!(f, "Directories: {dirs:?},")?;} else {writeln!(f, "")?;}
        }
        writeln!(f, "]")
    }

    pub fn format_imports(&self, f: &mut dyn Write) -> std::fmt::Result {
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

        Ok(())
    }

    pub fn format_exports(&self, f: &mut dyn Write) -> std::fmt::Result {
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

        Ok(())
    }

    pub fn format_relocations(&self, f: &mut dyn Write) -> std::fmt::Result {
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

        Ok(())
    }

    ///Parse fixed sized header from `pos`.
    pub(crate) fn parse_fixed_headers(&mut self, pos: u64) -> Result<u64> {
        let mut offset = pos;

        let mut buf = self.reader.read_bytes_at_offset(pos, dos::HEADER_LENGTH as usize)?;
        self.dos = HeaderField{ value: DosHeader::parse_bytes(buf, pos)?, offset: offset, rva: offset };
        offset += self.dos.value.e_lfanew.value as u64;

        buf = self.reader.read_bytes_at_offset(offset, file::HEADER_LENGTH as usize)?;
        self.file = HeaderField{ value: FileHeader::parse_bytes(buf, offset)?, offset: offset, rva: offset};
        offset += file::HEADER_LENGTH;

        buf = self.reader.read_bytes_at_offset(offset, self.file.value.optional_header_size.value as usize)?;

        match buf.len() {
            //(optional::x86::HEADER_LENGTH + DATA_DIR_LENGTH * 16)
            0xE0 => {
                let opt = OptionalHeader32::parse_bytes(buf.clone(), offset)?;
                self.optional = HeaderField{ value: OptionalHeader::X86(opt), offset: offset, rva: offset};
                offset += optional::x86::HEADER_LENGTH;

                let dir_buf = &buf[optional::x86::HEADER_LENGTH as usize..];
                let dirs = parse_data_directories(&dir_buf, 16, offset)?;
                self.data_dirs = HeaderField{ value: dirs, offset: offset, rva: offset};
                offset += 16 * 8;
            },

            //(optional::x64::HEADER_LENGTH + DATA_DIR_LENGTH * 16)
            0xF0 => {
                let opt = OptionalHeader64::parse_bytes(buf.clone(), offset)?;
                self.optional = HeaderField {value: OptionalHeader::X64(opt), offset: offset, rva: offset};
                offset += optional::x64::HEADER_LENGTH;

                let dir_buf = &buf[optional::x64::HEADER_LENGTH as usize..];
                let dirs = parse_data_directories(&dir_buf, 16, offset)?;
                self.data_dirs = HeaderField{ value: dirs, offset: offset, rva: offset};
                offset += 16 * 8;
            },

            _ => {
                return Err(PeError::MustHaveOptional)
            }
        }

        Ok(offset)
    }

    /// Parse section headers. 
    /// These are fixed sized contigious values, and size is known from OptionalHeader.
    pub(crate) fn parse_sections(&mut self, pos: u64) -> Result<u64> {
        let mut offset = pos;
        let sec_count = self.file.value.sections.value;
        let size = section::HEADER_LENGTH * sec_count as u64;
        
        let buf = self.reader.read_bytes_at_offset(offset, size as usize)?;
        let sections = section::parse_sections(&buf, sec_count, offset)?;
        self.sections = HeaderField{ value:sections, offset: offset, rva: offset};
        
        offset += size;

        Ok(offset)
    }

    /// Parse headers whose contents may be scattered.
    /// Content offsets are derived from parsed header values.
    pub(crate) fn parse_dynamic_headers(&mut self) -> Result<()> {
        self.parse_import_directory()?;
        self.parse_exports()?;
        self.parse_relocations()?;
        self.parse_resources()?;
        Ok(())
    }

    pub(crate) fn parse_all_headers(&mut self, pos: u64) -> Result<()> {
        let offset = self.parse_fixed_headers(pos)?;
        self.parse_sections(offset)?;
        self.parse_dynamic_headers()?;
        Ok(())
    }

    ///Parse a 'readable' file from disk into PE Image.  
    /// In case of error while reading or parsing file, a `dyn Error` is returned.  
    /// Params:
    /// - `f`: input file handle
    /// - `pos`: starting `pos`ition of PE content in file. Use `0` (other values are not tested).
    pub fn parse_file(file: File, pos: u64) -> crate::Result<Self> where Self: Sized {
        let reader = Box::new(BufReader::new(file));
        let mut pe = Self::new(reader);
        
        pe.parse_all_headers(pos)?;

        Ok(pe)
    }
    
    ///Parse an in-memory `[u8]` buffer into PE Image. The buffer must contain content for entire PE image.
    /// In case of error while reading or parsing, a `dyn Error` is returned.
    /// Params:
    /// - `bytes`: `Vec` of `u8`
    /// - `pos`: starting `pos`ition of PE content in `bytes`. Use `0` (other values are not tested).
    pub fn parse_bytes(bytes: Vec<u8>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let reader = Box::new(Cursor::new(bytes));
        let mut pe = Self::new(reader);

        pe.parse_all_headers(pos)?;

        Ok(pe)
    }


    ///Parse a PE Image from a `readable` type.  
    /// In case of error while reading or parsing, a `dyn Error` is returned.  
    /// **Params:**
    /// - `reader`: readable source in `Box`, must implement `BuffReadExt` from this crate.
    /// - `pos`: starting `pos`ition of PE content. Use `0` (other values are not tested).
    pub fn parse_readable(reader: Box<dyn BufReadExt>, pos: u64) -> crate::Result<Self> where Self: Sized {
        let mut pe = Self::new(reader);
        
        pe.parse_all_headers(pos)?;
        
        Ok(pe)
    }
}


impl TryFrom<File> for PeImage{
    type Error = PeError;

    fn try_from(value: File) -> Result<Self> {
        Self::parse_file(value, 0)
    }
}

impl TryFrom<Vec<u8>> for PeImage {
    type Error = PeError;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::parse_bytes(value, 0)
    }
}

impl TryFrom<Box<dyn BufReadExt>> for PeImage{
    type Error = PeError;

    fn try_from(value: Box<dyn BufReadExt>) -> Result<Self> {
        Self::parse_readable(value, 0)
    }
}


impl Display for PeImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
       
        //Basic headers
        self.format_basic_headers(f)?;
        //Data dirs
        self.format_data_dirs(f)?;
        //Sections
        self.format_sections(f)?;
        //Imports
        if self.has_imports() { self.format_imports(f)?; }
        //Exports
        if self.has_exports() { self.format_exports(f)?; }
        //Relocations
        if self.has_relocations() { self.format_relocations(f)?; }
        //Resources
        if self.has_rsrc() && self.resources.value.is_valid() {
            self.format_resource_tree(f, &String::from("  "), 1)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //use std::assert_matches::assert_matches;

    use std::io::Cursor;

    use crate::{
        pe::{optional::{DirectoryType, ImageType, OptionalHeader, MAX_DIRS}, section::Flags},
        types::{Header, BufReadExt},
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
        let reader = Box::new(Cursor::new(RAW_BYTES_64.to_vec()));
        let mut pe = PeImage::new(reader);
        let offset = pe.parse_fixed_headers(0).unwrap();
        pe.parse_sections(offset).unwrap();
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
        //let pe = PeImage::parse_bytes(RAW_BYTES_64.to_vec(), 0).unwrap();
        let mut cursor = Cursor::new(&RAW_BYTES_64);
        assert_eq!(cursor.read_string_at_offset(0x1f8).unwrap().as_str(), ".text");
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
        let reader = Box::new(Cursor::new(RAW_BYTES_32.to_vec()));
        let mut pe = PeImage::new(reader);
        
        let offset = pe.parse_fixed_headers(0).unwrap();
        pe.parse_sections(offset).unwrap();

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
        let reader = Box::new(Cursor::new(RAW_BYTES_32.to_vec()));
        let mut pe = PeImage::new(reader);
        let offset = pe.parse_fixed_headers(0).unwrap();
        pe.parse_sections(offset).unwrap();

        assert_eq!(pe.directory_section(DirectoryType::Import).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::Resource).unwrap().name_str().unwrap(), ".rsrc");
        assert_eq!(pe.directory_section(DirectoryType::Security).unwrap().name_str().unwrap(), ".rsrc");
        assert_eq!(pe.directory_section(DirectoryType::Relocation).unwrap().name_str().unwrap(), ".reloc");
        assert_eq!(pe.directory_section(DirectoryType::Debug).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::Configuration).unwrap().name_str().unwrap(), ".rdata");
        assert_eq!(pe.directory_section(DirectoryType::ImportAddressTable).unwrap().name_str().unwrap(), ".rdata");
    }
}
