use std::{fmt::Display, error::Error};

pub mod length;

#[derive(Debug)]
pub struct InvalidTimestamp{
    pub data: i64,
}

impl Display for InvalidTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid timestamp {:#08x}", self.data)
    }
}

impl Error for InvalidTimestamp { }
