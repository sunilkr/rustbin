# RUSTBIN

This is a learning project to understand Rust language to create comples file parsers.

---

## Structure

Rustbin is created as a library which shall add more file parsers.

Every value which is part of an header is wrapped in `HeaderField` struct. `HeaderField` struct provides 3 values:

- value: The value of the field read from file
- offset: Offset of the the value in file
- rva: Relative Virtual Address
    - Applicable only to PE file format
    - Shall be same as offset wherever not applicable

## Supported Now

### PE (incomplete)

Working:

- [x] DOS Header
- [x] File Header
- [x] Optional Header x64
- [] Optional Header x32
