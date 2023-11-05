extern crate librustbin;

use std::{env, fs::OpenOptions, io::BufReader, path::Path};

use librustbin::{pe::PeImage, types::Header};

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

    let mut pe_image = PeImage::parse_file(&mut reader, 0).unwrap();

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
    println!("DosHeader: {dos_header}");
    println!("FileHeader: {file_header}");
    println!("OptionalHeader: {}", pe_image.optional.value);
    println!("DataDirectories: [");
    for dir in &pe_image.data_dirs.value {
        if dir.value.rva.value != 0 {
            print!("  {}, ", dir);
            let section = pe_image.directory_section(dir.value.member);
            if let Some(sec) = section {
                print!(" Section: {},", sec.name_str().unwrap());
            }
            println!("");
        }
    }
    println!("]");
    println!("Sections: [");
    for sec in &pe_image.sections.value {
        print!("  {sec}, ");
        let dirs = sec.value.directories(&pe_image.data_dirs.value);
        if dirs.len() > 0 {println!("Directories: {dirs:?},");} else {println!();}
    }
    println!("]");

    pe_image.parse_import_directory().unwrap();
    println!("Import Directory: [");
    let idir = &pe_image.imports.value;
    for idesc in idir {
        println!(" {}\n [", idesc.value);
        for imp_name in idesc.value.get_imports_str() {
            println!("    {imp_name}",);
        }
        println!("  ]");
    }
    println!("]");

    pe_image.parse_exports().unwrap();
    if pe_image.exports.value.is_valid() {
        println!("Export Directory: {{");
        let export_dir = &pe_image.exports.value;
        println!("  Binary: {}", export_dir.name);
        println!("  Exports: [");
        
        for export in &export_dir.exports {
            println!("    {export}");
        }
        
        println!("  ]");
        println!("}}");
    }

    pe_image.parse_relocations().unwrap();
    if pe_image.relocations.value.is_valid() {
        println!("Relocation Directory: [");
        for rb in &pe_image.relocations.value.blocks {
            println!("  [{rb}");
            // for rc in &rb.value.relocs {
            //     println!("    {}", rc.value);
            // }
            println!("  ]");
        }
        println!("]");
    }

    pe_image.parse_resources().unwrap();
    if pe_image.resources.value.is_valid() {
        println!("Resource Directory: [");
        let rsrc_dir = &pe_image.resources.value;
        //println!("[?] Names: {}, IDs: {}", rsrc_dir.named_entry_count, rsrc_dir.id_entry_count);
        librustbin::pe::rsrc::print_rsrc_tree(rsrc_dir, &String::from("  "), 1);
        println!("]");
    }
}
