use std::{fs::File, io::BufReader};

use pe::PeImage;
use types::Header;
pub mod pe;
pub mod types;
pub mod errors;
pub mod utils;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub enum ParsedAs {
    PE(PeImage),
}

pub enum ParseAs {
    PE,
}

pub fn parse_file(f: &mut BufReader<File>, parse_as: ParseAs) -> Result<ParsedAs>{
    match parse_as {
        ParseAs::PE => Ok(ParsedAs::PE(pe::PeImage::parse_file(f, 0)?)),
    }
}

#[cfg(test)]
mod tests {

}
