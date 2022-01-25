use std::{env, fs::OpenOptions, io::BufReader, path::Path};

use librustbin::{pe::dos::DosHeader, types::Header};

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
    let dos_header = DosHeader::parse_file(&mut reader, 0).unwrap();

    eprintln!("{:?}", dos_header);
    
    if dos_header.is_valid() {
        println!("this can work");
        println!("DosHeader: {}", dos_header);
    } else {
        println!("not DOS");
    }
}
