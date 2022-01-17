use std::{env, fs::OpenOptions, io::{BufReader, Read, Result}, path::Path};

use librustbin::pe::dos::DosHeader;

fn is_mz(path: &Path) -> Result<bool> {
    let f = OpenOptions::new()
        .read(true)
        .open(path)?;
    
    let mut reader = BufReader::new(f);
    //let m = reader.read_u8()?;
    //let z = reader.read_u8()?;
    let mut data: Vec<u8> = Vec::with_capacity(2);
    {
        reader.by_ref().take(2).read_to_end(&mut data)?;
    }
    
    //let mut result = false;
    let magic = String::from_utf8(data).unwrap();
    let dos_magic = String::from("MZ");

    if dos_magic == magic {
        Ok(true)
    } else {
        eprintln!("unexpected values {}", &magic);
        Ok(false)
    }

    //Ok(result)
}


fn main() {

    let args:Vec<String> = env::args().collect();
    let exe_name = args.get(0).unwrap();
    let binpath = Path::new(&exe_name);

    println!("exe_name: {}", exe_name);

    if binpath.exists() {
        println!("This should work");
    } else {
        panic!("Not what expected");
    }

    //let res = is_mz(&binpath).unwrap();
    let f = OpenOptions::new()
        .read(true)
        .open(binpath).unwrap();
    
    let mut reader = BufReader::new(f);
    let dos_header = DosHeader::parse(&mut reader).unwrap();

    eprintln!("{:?}", dos_header);
    
    if dos_header.is_valid() {
        println!("this can work");
        println!("DosHeader: {}", dos_header);
    } else {
        println!("not DOS");
    }
}
