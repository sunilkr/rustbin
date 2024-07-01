
use serde::Serialize;

use crate::pe::dos::DosHeader;

use super::{hf_to_hfx, ByteEndian, HeaderFieldEx};

#[derive(Debug, Serialize)]
pub struct DosHeaderEx {
    pub e_magic: HeaderFieldEx<u16>,
    pub(crate) e_cblp: HeaderFieldEx<u16>,
    pub(crate) e_cp: HeaderFieldEx<u16>,
    pub(crate) e_crlc: HeaderFieldEx<u16>,
    pub(crate) e_cparhdr: HeaderFieldEx<u16>,
    pub(crate) e_minalloc: HeaderFieldEx<u16>,
    pub(crate) e_maxalloc: HeaderFieldEx<u16>,
    pub(crate) e_ss: HeaderFieldEx<u16>,
    pub(crate) e_sp: HeaderFieldEx<u16>,
    pub(crate) e_csum: HeaderFieldEx<u16>,
    pub(crate) e_ip: HeaderFieldEx<u16>,
    pub(crate) e_cs: HeaderFieldEx<u16>,
    pub(crate) e_lfarlc: HeaderFieldEx<u16>,
    pub(crate) e_ovno: HeaderFieldEx<u16>,
    pub(crate) e_res: HeaderFieldEx<[u16; 4]>,
    pub(crate) e_oemid:  HeaderFieldEx<u16>,
    pub(crate) e_oeminfo: HeaderFieldEx<u16>,
    pub(crate) e_res2: HeaderFieldEx<[u16; 10]>,
    pub e_lfanew: HeaderFieldEx<u32>
}

impl From<&DosHeader> for DosHeaderEx {
    fn from(value: &DosHeader) -> Self {
        let res_val = &value.e_res.value
            .map(|v| v.to_le_bytes())
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>();

        let res2 = &value.e_res2.value
            .map(|v| v.to_le_bytes())
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>();
            

        Self { 
            e_magic: hf_to_hfx(&value.e_magic, ByteEndian::LE),
            e_cblp: hf_to_hfx(&value.e_cblp, ByteEndian::LE),
            e_cp: hf_to_hfx(&value.e_cp, ByteEndian::LE),
            e_crlc: hf_to_hfx(&value.e_crlc, ByteEndian::LE),
            e_cparhdr: hf_to_hfx(&value.e_cparhdr, ByteEndian::LE),
            e_minalloc: hf_to_hfx(&value.e_minalloc, ByteEndian::LE), 
            e_maxalloc: hf_to_hfx(&value.e_maxalloc, ByteEndian::LE),
            e_ss: hf_to_hfx(&value.e_ss, ByteEndian::LE),
            e_sp: hf_to_hfx(&value.e_sp, ByteEndian::LE), 
            e_csum: hf_to_hfx(&value.e_csum, ByteEndian::LE),
            e_ip: hf_to_hfx(&value.e_ip, ByteEndian::LE),
            e_cs: hf_to_hfx(&value.e_cs, ByteEndian::LE),
            e_lfarlc: hf_to_hfx(&value.e_lfarlc, ByteEndian::LE),
            e_ovno: hf_to_hfx(&value.e_ovno, ByteEndian::LE), 
            e_res: HeaderFieldEx { raw: res_val.to_vec(), value: value.e_res.clone() },
            e_oemid: hf_to_hfx(&value.e_oemid, ByteEndian::LE),
            e_oeminfo: hf_to_hfx(&value.e_oeminfo, ByteEndian::LE), 
            e_res2: HeaderFieldEx { raw: res2.to_vec(), value: value.e_res2.clone() }, 
            e_lfanew: hf_to_hfx(&value.e_lfanew, ByteEndian::LE) 
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::{pe::dos::DosHeader, types::Header};

    use super::DosHeaderEx;


    const RAW_DOS_BYTES: [u8; 64] = [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 
        0x00, 0x00, 0xB8, 0x00, 00, 00, 00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00, 
        00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
        00, 00, 00, 00, 00, 00, 00, 0xF8, 00, 00, 00
    ];

    #[test]
    fn test_from_dos() {
        let dos = DosHeader::parse_bytes(RAW_DOS_BYTES.to_vec(), 0).unwrap();
        let dos_ex = DosHeaderEx::from(&dos);

        assert_eq!(dos_ex.e_magic.raw, vec![0x4d, 0x5a]);
        assert_eq!(dos_ex.e_magic.value, dos.e_magic);

        assert_eq!(dos_ex.e_res.raw, vec![0; 8]);
        assert_eq!(dos_ex.e_res.value, dos.e_res);

        assert_eq!(dos_ex.e_res2.raw, vec![0; 20]);
        assert_eq!(dos_ex.e_res2.value, dos.e_res2);

        assert_eq!(dos_ex.e_lfanew.raw, vec![0xf8, 0, 0, 0]);
        assert_eq!(dos_ex.e_lfanew.value, dos.e_lfanew);
    }

    #[cfg(feature="json")]
    #[test]
    fn to_json() {
        let dos = DosHeader::parse_bytes(RAW_DOS_BYTES.to_vec(), 0).unwrap();
        let dos_ex = DosHeaderEx::from(&dos);

        let json = serde_json::to_string_pretty(&dos_ex).unwrap();
        eprintln!("{json}");
    }
}
