use std::{fs::{File, OpenOptions}, path::Path};

use pe::{PeImage, PeError};
pub mod pe;
pub mod types;
pub mod utils;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[non_exhaustive]
    #[error("failed to read file")]
    Read(#[from] std::io::Error),

    #[error("failed to parse")]
    Parse(#[from] ParseError)
}


#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    PE(#[from] pe::PeError)
}

pub type Result<T> = std::result::Result<T, PeError>;

pub enum ParsedAs {
    PE(PeImage),
}

pub enum ParseAs {
    PE,
}

pub fn parse_file(f: File, parse_as: ParseAs) -> Result<ParsedAs>{
    match parse_as {
        ParseAs::PE => Ok(ParsedAs::PE(pe::PeImage::parse_file(f, 0)?)),
    }
}

pub fn parse_path(path: &Path, parse_as: ParseAs) -> Result<ParsedAs>{
    let f = OpenOptions::new()
        .read(true)
        .open(path)?;
    
    parse_file(f, parse_as)
}

#[cfg(test)]
mod tests {

}
