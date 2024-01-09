use core::fmt;
use std::error::Error;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LengthError {
    details: String,
    expected: i64,
    actual: i64
}

impl LengthError {
    pub fn new(msg: &str, expected: i64, actual: i64) -> LengthError {
        LengthError {
            details: msg.to_string(),
            expected: expected,
            actual: actual
        }
    }
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; Expected {}, Actual {}", self.details, self.expected, self.actual)
    }
}

impl Error for LengthError {
    fn description(&self) -> &str {
        &self.details
    }
}
