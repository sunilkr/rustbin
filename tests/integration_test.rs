 //Test full image
 #[cfg(feature="json")]
 #[test]
 fn pe_to_min_json() {
    use std::{env, fs::OpenOptions};

    use rustbin::pe::{ser::min::MinPeImage, PeImage};

     let path = env::current_dir()
         .unwrap()
         .join("test-data")
         .join("test.dll");

     eprintln!("TargetPath: {path:?}");
     assert!(path.is_file());

     let file = OpenOptions::new()
         .read(true)
         .open(path)
         .unwrap();

     let mut pe = PeImage::parse_file(file, 0).unwrap();
     pe.parse_import_directory().unwrap();
     pe.parse_exports().unwrap();
     pe.parse_relocations().unwrap();
     pe.parse_resources().unwrap();

     let min_pe = MinPeImage::from(&pe);
     
     let jstr = serde_json::to_string_pretty(&min_pe).unwrap();
     //eprintln!("{jstr}");
     assert!(jstr.contains("dos_header"));
 }
 