use std::io::{Cursor, SeekFrom, Seek, BufRead};

pub fn read_string_at_offset(content: &[u8], offset: u64) -> Option<String> {
    let mut cursor = Cursor::new(content);
    let mut buf:Vec<u8> = Vec::new();
    cursor.seek(SeekFrom::Start(offset)).unwrap();
    cursor.read_until(b'\0', &mut buf).unwrap();
    Some(String::from_utf8(buf[..(buf.len()-1)].to_vec()).unwrap())
}
