use crate::{pe::{rsrc::{display_rsrc_tree, ResourceNode, ResourceType, DATA_LENGTH, ENTRY_LENGTH}, section::{parse_sections, section_by_name, SectionHeader}}, types::{Header, HeaderField}, utils::FragmentReader};

use crate::pe::rsrc::{ResourceDirectory, ResourceData, ResourceEntry, ResourceString};

#[test]
fn parse_rsrc_table() {
    let rsrc_tbl_bytes = [
        0x00 as u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00,
    ];

    let rst = ResourceDirectory::parse_bytes(rsrc_tbl_bytes.to_vec(), 0).unwrap();

    assert_eq!(rst.charactristics.value, 0);
    assert_eq!(rst.charactristics.offset, 0);
    assert_eq!(rst.timestamp.value.format("%Y-%m-%d %H:%M:%S").to_string(), "1970-01-01 00:00:00");
    assert_eq!(rst.timestamp.offset, 0x04);
    assert_eq!(rst.major_version.value, 0x0004);
    assert_eq!(rst.major_version.offset, 0x08);
    assert_eq!(rst.minor_version.value, 0);
    assert_eq!(rst.minor_version.offset, 0x0a);
    assert_eq!(rst.named_entry_count.value, 0x0000);
    assert_eq!(rst.named_entry_count.offset, 0x0c);
    assert_eq!(rst.id_entry_count.value, 0x000a);
    assert_eq!(rst.id_entry_count.offset, 0x0e);
}

#[test]
fn parse_rsrc_string() {
    let bytes = [0x04u8, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00];
    
    let rstr = ResourceString::parse_bytes(bytes.to_vec(), 0).unwrap();
    
    assert_eq!(rstr.length.value, 4);
    assert_eq!(rstr.length.offset, 0x0);
    assert_eq!(rstr.value.value, "ABCD");
    assert_eq!(rstr.value.offset, 0x2);
}

#[test]
fn rstr_fix_rva() {
    let bytes = [0x04u8, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00];
    let sections = parse_sections(&RAW_SECTIONS, 6, RAW_SECTION_OFFSET).unwrap();
    let mut rstr = ResourceString::parse_bytes(bytes.to_vec(), 0x00013802).unwrap();

    rstr.fix_rvas(&sections).unwrap();

    assert_eq!(rstr.length.rva, 0x00018002);
    assert_eq!(rstr.value.rva, 0x00018004);
}

#[test]
fn parse_rsrc_data() {
    let pos = 0x080;
    let bytes: &[u8] = &RAW_BYTES[pos as usize.. (pos + DATA_LENGTH) as usize];

    let data = ResourceData::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();
    
    assert_eq!(data.rva.value, 0x000180a0);
    assert_eq!(data.rva.offset, 0x00013880);
    assert_eq!(data.size.value, 0x388);
    assert_eq!(data.size.offset, 0x00013884);
    assert_eq!(data.code_page.value, 0x0);
    assert_eq!(data.code_page.offset, 0x00013888);
    assert_eq!(data.reserved.value, 0);
    assert_eq!(data.reserved.offset, 0x0001388c);
}

#[test]
fn load_data() {
    let data_start = [0x88u8, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45, 0x00];
    let pos = 0x80;
    let bytes: &[u8] = &RAW_BYTES[pos as usize.. (pos + DATA_LENGTH) as usize];
    let mut data = ResourceData::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();

    let mut reader = FragmentReader::new(RAW_BYTES.to_vec(), SECTION_OFFSET);
    data.load_data(&get_rsrc_section(), &mut reader).unwrap();

    assert_eq!(data.value.offset, 0x000138a0);
    assert_eq!(data.value.rva, data.rva.value as u64);
    
    let value16 = &data.value.value[0..16];
    assert_eq!(value16, data_start);
}

#[test]
fn rdata_fix_rvas() {
    let pos = 0x090;
    let bytes: &[u8] = &RAW_BYTES[pos as usize.. (pos + DATA_LENGTH) as usize];
    let sections = parse_sections(&RAW_SECTIONS, 6, RAW_SECTION_OFFSET).unwrap();
    let mut data = ResourceData::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();

    data.fix_rvas(&sections).unwrap();

    assert_eq!(data.rva.rva, 0x00018090);
    assert_eq!(data.size.rva, 0x00018094);
    assert_eq!(data.code_page.rva, 0x00018098);
    assert_eq!(data.reserved.rva, 0x0001809c);
}

#[test]
fn parse_rsrc_entry() {
    let pos = 0x10;
    let bytes = &RAW_BYTES[pos as usize..(pos+ENTRY_LENGTH) as usize];

    let entry = ResourceEntry::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();

    assert_eq!(entry.is_string, false);
    assert_eq!(entry.is_data, false);
    assert_eq!(entry.id, ResourceType::VERSION);
    assert_eq!(entry.data_offset.value, 0x80000020);
    assert_eq!(entry.name_offset.value, 0x00000010);
    assert_eq!(entry.name_offset.offset, 0x00013810);
    assert_eq!(entry.data_offset.offset, 0x00013814)
}

#[test]
fn parse_rsrc_entry_with_data() {
    let pos = 0x78;
    let bytes = &RAW_BYTES[pos as usize..(pos+ENTRY_LENGTH) as usize];

    let mut entry = ResourceEntry::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();

    assert_eq!(entry.is_string, false);
    assert_eq!(entry.is_data, true);
    assert_eq!(entry.id, ResourceType::UNKNOWN(1033));

    let mut reader = FragmentReader::new(RAW_BYTES.to_vec(), SECTION_OFFSET);
    entry.parse_rsrc(&get_rsrc_section(), &mut reader).unwrap();
    
    if let ResourceNode::Data(data) = entry.data {
        assert_eq!(data.rva.value, 0x00018428);
        assert_eq!(data.size.value, 0x17d);
        assert_eq!(data.code_page.value, 0x0);
    }
    else {
        assert!(false, "Unexpected type");
    }
}

#[test]
fn rsrc_entry_fix_rvas() {
    let pos = 0x78;
    let bytes = &RAW_BYTES[pos as usize..(pos + ENTRY_LENGTH) as usize];
    let mut reader = FragmentReader::new(RAW_BYTES.to_vec(), SECTION_OFFSET);

    let mut entry = ResourceEntry::parse_bytes(bytes.to_vec(), SECTION_OFFSET + pos).unwrap();
    let sections = parse_sections(&RAW_SECTIONS, 6, RAW_SECTION_OFFSET).unwrap();
    let rsrc_section = section_by_name(&sections, ".rsrc".into()).unwrap().unwrap();
    entry.parse_rsrc(&rsrc_section, &mut reader).unwrap();
    
    entry.fix_rvas(&sections).unwrap();

    assert_eq!(entry.name_offset.rva, 0x00018078);
    assert_eq!(entry.data_offset.rva, 0x0001807c);

    if let ResourceNode::Data(data) = &entry.data {
        assert_eq!(data.rva.rva, 0x00018090);
        assert_eq!(data.size.rva, 0x00018094);
        assert_eq!(data.code_page.rva, 0x00018098);
        assert_eq!(data.reserved.rva, 0x0001809c);
    }
}

#[test]
fn parse_rsrc_tree() {
    let section = get_rsrc_section();
    let mut reader = FragmentReader::new(RAW_BYTES.to_vec(), SECTION_OFFSET);
    let mut rsrc_tbl = ResourceDirectory::parse_bytes(RAW_BYTES.to_vec(), SECTION_OFFSET).unwrap();
    assert_eq!(rsrc_tbl.id_entry_count.value, 2);

    rsrc_tbl.parse_rsrc(&get_rsrc_section(), &mut reader).unwrap();
    assert_eq!(rsrc_tbl.entries.len(), 2);

    //1st tree
    let e1 = &mut rsrc_tbl.entries[0];
    assert_eq!(e1.id, ResourceType::VERSION);
    if let ResourceNode::Dir(dir) = &mut e1.data {
        assert_eq!(dir.id_entry_count.value, 1);
        assert_eq!(dir.entries.len(), 1);
        let e = &mut dir.entries[0];
        assert_eq!(e.id, ResourceType::CURSOR);
        if let ResourceNode::Dir(dir) = &mut e.data {
            assert_eq!(dir.id_entry_count.value, 1);
            assert_eq!(dir.entries.len(), 1);
            let e = &mut dir.entries[0];
            assert_eq!(e.id, ResourceType::UNKNOWN(1033));
            if let ResourceNode::Data(data) = &mut e.data {
                data.load_data(&section, &mut reader).unwrap();
                assert_eq!(data.value.value.len(), data.size.value as usize);
                let data_start = [0x88u8, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45, 0x00];
                let value16 = &data.value.value[0..16];
                assert_eq!(value16, data_start);
            }
            else {
                assert!(false, "Unexpected type at L12. DATA was expected; Found: {:?}", &e.data);
            }
        }
        else {
            assert!(false, "Unexpected type at L11. DIR was expected; Found: {:?}", &e.data);
        }
    }
    else {
        assert!(false, "Unexpected type at L1. DIR was expected; Found: {:?}", &e1.data);
    }

    //2nd tree
    let e2 = &mut rsrc_tbl.entries[1];
    assert_eq!(e2.id, ResourceType::MANIFEST);
    if let ResourceNode::Dir(dir) = &mut e2.data {
        assert_eq!(dir.id_entry_count.value, 1);
        assert_eq!(dir.entries.len(), 1);
        let e = &mut dir.entries[0];
        assert_eq!(e.id, ResourceType::BITMAP);
        if let ResourceNode::Dir(dir) = &mut e.data {
            assert_eq!(dir.id_entry_count.value, 1);
            assert_eq!(dir.entries.len(), 1);
            let e = &mut dir.entries[0];
            assert_eq!(e.id, ResourceType::UNKNOWN(1033));
            if let ResourceNode::Data(data) = &mut e.data {
                data.load_data(&section, &mut reader).unwrap();
                assert_eq!(data.value.value.len(), data.size.value as usize);
                let data_start = [0x3Cu8, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x27, 0x31];
                let value16 = &data.value.value[0..16];
                assert_eq!(value16, data_start);
            }
            else {
                assert!(false, "Unexpected type at L22. DATA was expected; Found: {:?}", &e.data);
            }
        }
        else {
            assert!(false, "Unexpected type at L21. DIR was expected; Found: {:?}", &e.data);
        }
    }
    else {
        assert!(false, "Unexpected type at L2. DIR was expected; Found: {:?}", &e2.data);
    }
}

#[test]
fn print_tree() {
    let mut reader = FragmentReader::new(RAW_BYTES.to_vec(), SECTION_OFFSET);
    let mut rsrc_tbl = ResourceDirectory::parse_bytes(RAW_BYTES.to_vec(), SECTION_OFFSET).unwrap();
    assert_eq!(rsrc_tbl.id_entry_count.value, 2);

    rsrc_tbl.parse_rsrc(&get_rsrc_section(), &mut reader).unwrap();
    assert_eq!(rsrc_tbl.entries.len(), 2);

    let mut rsrc_buf = String::new();
    display_rsrc_tree(&rsrc_tbl, &mut rsrc_buf, &" ".to_string(), 0).unwrap();
    println!("{rsrc_buf}");
}

const SECTION_VA: u64 = 0x00018000;
const SECTION_OFFSET: u64 = 0x00013800;
const SECTION_RAW_SIZE: u64 = 0x00000600;
const SECTION_VSIZE: u64 = 0x00005a8;


fn get_rsrc_section() -> SectionHeader {
    SectionHeader {
        raw_data_ptr: HeaderField { value: SECTION_OFFSET as u32, ..Default::default() },
        virtual_address: HeaderField { value: SECTION_VA as u32, ..Default::default() },
        virtual_size: HeaderField { value: SECTION_VSIZE as u32, ..Default::default() },
        sizeof_raw_data: HeaderField { value: SECTION_RAW_SIZE as u32, ..Default::default() },
        ..Default::default()
    }
}

const RAW_BYTES: [u8; 0x600] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0x18, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x09, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x04, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
	0xA0, 0x80, 0x01, 0x00, 0x88, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x28, 0x84, 0x01, 0x00, 0x7D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x88, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45, 0x00,
	0x52, 0x00, 0x53, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x4E, 0x00, 0x5F, 0x00, 0x49, 0x00, 0x4E, 0x00,
	0x46, 0x00, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBD, 0x04, 0xEF, 0xFE, 0x00, 0x00, 0x01, 0x00,
	0x2A, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE6, 0x02, 0x00, 0x00,
	0x01, 0x00, 0x53, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x46, 0x00,
	0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00,
	0xC2, 0x02, 0x00, 0x00, 0x01, 0x00, 0x30, 0x00, 0x34, 0x00, 0x30, 0x00, 0x39, 0x00, 0x30, 0x00,
	0x34, 0x00, 0x42, 0x00, 0x30, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x1D, 0x00, 0x01, 0x00, 0x43, 0x00,
	0x6F, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x4E, 0x00, 0x61, 0x00,
	0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x68, 0x00, 0x65, 0x00, 0x20, 0x00,
	0x47, 0x00, 0x4C, 0x00, 0x69, 0x00, 0x62, 0x00, 0x20, 0x00, 0x64, 0x00, 0x65, 0x00, 0x76, 0x00,
	0x65, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x63, 0x00,
	0x6F, 0x00, 0x6D, 0x00, 0x6D, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x69, 0x00, 0x74, 0x00, 0x79, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x08, 0x00, 0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00,
	0x65, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x63, 0x00, 0x72, 0x00, 0x69, 0x00, 0x70, 0x00,
	0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x54, 0x00,
	0x68, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x64, 0x00, 0x00, 0x00, 0x32, 0x00, 0x09, 0x00,
	0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x2E, 0x00,
	0x34, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x42, 0x00, 0x11, 0x00, 0x01, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00,
	0x6C, 0x00, 0x69, 0x00, 0x62, 0x00, 0x67, 0x00, 0x74, 0x00, 0x68, 0x00, 0x72, 0x00, 0x65, 0x00,
	0x61, 0x00, 0x64, 0x00, 0x2D, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2D, 0x00, 0x30, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xEC, 0x00, 0x64, 0x00, 0x01, 0x00, 0x4C, 0x00, 0x65, 0x00, 0x67, 0x00,
	0x61, 0x00, 0x6C, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00,
	0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x00, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x79, 0x00,
	0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x20, 0x00, 0xA9, 0x00, 0x20, 0x00,
	0x31, 0x00, 0x39, 0x00, 0x39, 0x00, 0x35, 0x00, 0x2D, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00,
	0x31, 0x00, 0x20, 0x00, 0x50, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00,
	0x4D, 0x00, 0x61, 0x00, 0x74, 0x00, 0x74, 0x00, 0x69, 0x00, 0x73, 0x00, 0x2C, 0x00, 0x20, 0x00,
	0x53, 0x00, 0x70, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00,
	0x4B, 0x00, 0x69, 0x00, 0x6D, 0x00, 0x62, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x2C, 0x00,
	0x20, 0x00, 0x4A, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x68, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x61, 0x00,
	0x63, 0x00, 0x44, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x2C, 0x00,
	0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x62, 0x00, 0x61, 0x00, 0x73, 0x00, 0x74, 0x00, 0x69, 0x00,
	0x61, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x68, 0x00, 0x65, 0x00,
	0x6C, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x20, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x20, 0x00,
	0x6F, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x2E, 0x00, 0x00, 0x00,
	0x52, 0x00, 0x15, 0x00, 0x01, 0x00, 0x4F, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00,
	0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x6E, 0x00,
	0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x62, 0x00, 0x67, 0x00,
	0x74, 0x00, 0x68, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x64, 0x00, 0x2D, 0x00, 0x32, 0x00,
	0x2E, 0x00, 0x30, 0x00, 0x2D, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x05, 0x00, 0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00,
	0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x4C, 0x00, 0x69, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x00, 0x07, 0x00, 0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00,
	0x63, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00,
	0x6E, 0x00, 0x00, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x56, 0x00, 0x61, 0x00, 0x72, 0x00,
	0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00,
	0x6E, 0x00, 0x73, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x09, 0x04, 0xB0, 0x04, 0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x27, 0x31, 0x2E, 0x30, 0x27, 0x20, 0x65, 0x6E, 0x63, 0x6F,
	0x64, 0x69, 0x6E, 0x67, 0x3D, 0x27, 0x55, 0x54, 0x46, 0x2D, 0x38, 0x27, 0x20, 0x73, 0x74, 0x61,
	0x6E, 0x64, 0x61, 0x6C, 0x6F, 0x6E, 0x65, 0x3D, 0x27, 0x79, 0x65, 0x73, 0x27, 0x3F, 0x3E, 0x0D,
	0x0A, 0x3C, 0x61, 0x73, 0x73, 0x65, 0x6D, 0x62, 0x6C, 0x79, 0x20, 0x78, 0x6D, 0x6C, 0x6E, 0x73,
	0x3D, 0x27, 0x75, 0x72, 0x6E, 0x3A, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2D, 0x6D, 0x69,
	0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2D, 0x63, 0x6F, 0x6D, 0x3A, 0x61, 0x73, 0x6D, 0x2E,
	0x76, 0x31, 0x27, 0x20, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6F, 0x6E, 0x3D, 0x27, 0x31, 0x2E, 0x30, 0x27, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x3C, 0x74,
	0x72, 0x75, 0x73, 0x74, 0x49, 0x6E, 0x66, 0x6F, 0x20, 0x78, 0x6D, 0x6C, 0x6E, 0x73, 0x3D, 0x22,
	0x75, 0x72, 0x6E, 0x3A, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2D, 0x6D, 0x69, 0x63, 0x72,
	0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2D, 0x63, 0x6F, 0x6D, 0x3A, 0x61, 0x73, 0x6D, 0x2E, 0x76, 0x33,
	0x22, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74,
	0x79, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x72, 0x65, 0x71, 0x75, 0x65,
    0x73, 0x74, 0x65, 0x64, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6C, 0x65, 0x67, 0x65, 0x73, 0x3E, 0x0D,
	0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x65, 0x64, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x69, 0x6F, 0x6E, 0x4C, 0x65, 0x76, 0x65,
	0x6C, 0x20, 0x6C, 0x65, 0x76, 0x65, 0x6C, 0x3D, 0x27, 0x61, 0x73, 0x49, 0x6E, 0x76, 0x6F, 0x6B,
	0x65, 0x72, 0x27, 0x20, 0x75, 0x69, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3D, 0x27, 0x66, 0x61,
	0x6C, 0x73, 0x65, 0x27, 0x20, 0x2F, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C,
	0x2F, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6C,
	0x65, 0x67, 0x65, 0x73, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x2F, 0x73, 0x65, 0x63,
	0x75, 0x72, 0x69, 0x74, 0x79, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x3C, 0x2F, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x49, 0x6E, 0x66, 0x6F, 0x3E, 0x0D, 0x0A, 0x3C, 0x2F, 0x61, 0x73, 0x73, 0x65, 0x6D, 0x62,
	0x6C, 0x79, 0x3E, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const RAW_SECTIONS: [u8; 240] = [
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x54, 0xAC, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
	0x00, 0xAE, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
	0xEC, 0x64, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0xB2, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
	0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0xB8, 0x39, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC0, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
	0xB8, 0x08, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x2E, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40,
	0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0xA8, 0x05, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00,
	0x00, 0x06, 0x00, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00,
	0x24, 0x05, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3E, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42
];

const RAW_SECTION_OFFSET: u64 = 0x200;
