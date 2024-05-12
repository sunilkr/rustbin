extern crate rustbin;

use std::{env, fs::OpenOptions, io::BufReader, path::Path};

use rustbin::{pe::PeImage, types::Header};

fn main() {

    let args:Vec<String> = env::args().collect();
    let exe_name = args.get(0).unwrap();
    let binpath = Path::new(&exe_name);

    println!("exe_name: {exe_name}");

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

    let pe_image = PeImage::parse_file(&mut reader, 0).unwrap();

    let dos_header = &pe_image.dos.value;
    let file_header = &pe_image.file.value;

    eprintln!("{dos_header:?}");
    eprintln!("--");
    eprintln!("{file_header:?}");
    eprintln!("--");
    eprintln!("{:?}", pe_image.optional.value);
    eprintln!("--");
    eprintln!("{:?}", pe_image.data_dirs.value);
    eprintln!("--");
    eprintln!("{:?}", pe_image.sections.value);
    eprintln!("--");
    //eprintln!("{:?}", pe_image.)

    println!("___Parsed Image___");
    println!("{pe_image}");
}
