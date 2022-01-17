use std::{fs::File, io::{BufReader, Read, Result}};
pub mod pe;
pub mod types;
pub mod errors;

fn is_valid_magic(f: &mut BufReader<File>, magic: &str) -> Result<bool> {
    let magic_len = magic.len();
    let mut read_data: Vec<u8> = Vec::with_capacity(magic_len);

    {
        f.by_ref().take(magic_len as u64).read_exact(&mut read_data)?;
    }

    if magic.as_bytes() == read_data.as_slice() {
        Ok(true)
    } else {
        Ok(false)
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
