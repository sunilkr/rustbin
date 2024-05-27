# RUSTBIN

[![Build Status](https://github.com/sunilkr/rustbin/actions/workflows/build.yml/badge.svg?event=push)](https://github.com/sunilkr/rustbin/actions/workflows/build.yml)

This is a learning project to understand Rust language and create fairly complex file parsers.

---

## Structure

Rustbin is created as a library which shall add more file parsers.

Every value which is part of a header is wrapped in `HeaderField` struct. `HeaderField` struct provides 3 values:

- value: The value of the field read from file
- offset: Offset of the the value in file. Structs have same offset as the offset of their first member
- rva: Relative Virtual Address
  - Applicable only to PE file format
  - Shall be same as offset wherever not applicable

## Supported Now

### PE (WIP)

#### Usage:

>Note: This example works only if built on Windows OS.

```rust
extern crate rustbin;
extern crate serde_json;

use std::{env, fs::OpenOptions, io::BufReader, path::Path};

use rustbin::{pe::{PeImage, ser::min::MinPeImage}, types::Header};

//Parse itself (on Windows only)
fn main() {
  //Create PathBuf for self.
  let args:Vec<String> = env::args().collect();
  let exe_name = args.get(0).unwrap();
  let binpath = Path::new(&exe_name);

  //Open file handle and create a redaer.
  let Ok(f) = OpenOptions::new()
    .read(true)
    .open(binpath)
  else {
    panic!("Failed to open file in read mode.");
  };
  
  //Parse the file from offset 0.
  let Ok(parsed) = parse_file(f, ParseAs::PE) else {
    println!("Failed to parse as `PE`.");
    return ExitCode::from(4);
  };

  let ParsedAs::PE(pe_image) = parsed;

  //Convert parsed image to a minimal set of `serde::Serialize`able values without metadata.
  let min_pe = MinPeImage::from(&pe_image);

  //Serialize minimal pe image to indented json.
  let json_str = serde_json::to_string_pretty(&min_pe).unwrap();

  println!("{}", json_str);
}

```

#### Parsing:

- [x] DOS Header
- [x] File Header
- [x] Optional Header x64
- [x] Optional Header x86
- [x] Data Directories
- [x] Section Headers
- [x] Imports
- [x] Exports
- [x] Relocations
- [x] Resources

#### Serialize (Minimal format)

- [x] DOS Header
- [x] File Header
- [x] Optional Header x64
- [x] Optional Header x86
- [x] Data Directories
- [x] Section Headers
- [x] Imports
- [x] Exports
- [x] Relocations
- [x] Resources

