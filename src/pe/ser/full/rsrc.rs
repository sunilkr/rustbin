use crate::pe::{rsrc::{ResourceData, ResourceDirectory, ResourceEntry, ResourceNode}, ser::full::ByteEndian};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{pe::rsrc::{ResourceString, ResourceType}, types::HeaderField};

use super::{hf_to_hfx, HeaderFieldEx};


#[derive(Debug, Serialize)]
#[serde(rename="resource_string")]
pub struct RsrcStringEx {
    pub length: HeaderFieldEx<u16>,
    pub value: HeaderField<String>,
}

impl From<&ResourceString> for RsrcStringEx {
    fn from(value: &ResourceString) -> Self {
        Self { 
            length: hf_to_hfx(&value.length, ByteEndian::LE), 
            value: value.value.clone()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename="resource_data")]
pub struct RsrcDataEx {
    pub rva: HeaderFieldEx<u32>,
    pub size: HeaderFieldEx<u32>,
    pub code_page: HeaderFieldEx<u32>,
    pub value: HeaderField<Vec<u8>>,
}

impl From<&ResourceData> for RsrcDataEx {
    fn from(value: &ResourceData) -> Self {
        Self { 
            rva: hf_to_hfx(&value.rva, ByteEndian::LE), 
            size: hf_to_hfx(&value.size, ByteEndian::LE), 
            code_page: hf_to_hfx(&value.code_page, ByteEndian::LE), 
            value: HeaderField {
                value: vec![], 
                offset: value.value.offset,
                rva: value.value.rva,
                size: value.value.size,
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub enum RsrcNodeEx {
    #[serde(rename="string")]
    Str(RsrcStringEx),
    #[serde(rename="data")]
    Data(RsrcDataEx),
    #[serde(rename="directory")]
    Dir(RsrcDirEx)
}

impl From<&ResourceNode> for RsrcNodeEx {
    fn from(value: &ResourceNode) -> Self {
        match value {
            ResourceNode::Str(str) => Self::Str(RsrcStringEx::from(str)),
            ResourceNode::Data(data) => Self::Data(RsrcDataEx::from(data)),
            ResourceNode::Dir(dir) => Self::Dir(RsrcDirEx::from(dir)),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename="resource_entry")]
pub struct RsrcEntryEx {
    pub is_string: bool,
    pub is_data: bool,
    pub id: ResourceType,
    pub name_offset: HeaderFieldEx<u32>,
    pub data_offset: HeaderFieldEx<u32>,
    #[serde(flatten)]
    pub data: RsrcNodeEx,
}

impl From<&ResourceEntry> for RsrcEntryEx {
    fn from(value: &ResourceEntry) -> Self {
        Self {
            is_string: value.is_string,
            is_data: value.is_data,
            id: value.id,
            name_offset: hf_to_hfx(&value.name_offset, ByteEndian::LE),
            data_offset: hf_to_hfx(&value.data_offset, ByteEndian::LE),
            data: RsrcNodeEx::from(&value.data)
        }
    }
}


#[derive(Debug, Serialize)]
#[serde(rename="resource_directory")]
pub struct RsrcDirEx {
    pub charactristics: HeaderFieldEx<u32>,
    pub timestamp: HeaderFieldEx<DateTime<Utc>>,
    pub major_version: HeaderFieldEx<u16>,
    pub minor_version: HeaderFieldEx<u16>,
    #[serde(rename="number_of_named_entries")]
    pub named_entry_count: HeaderFieldEx<u16>,
    #[serde(rename="number_of_id_entries")]
    pub id_entry_count: HeaderFieldEx<u16>,
    pub entries: Vec<RsrcEntryEx>,
}

impl From<&ResourceDirectory> for RsrcDirEx {
    fn from(value: &ResourceDirectory) -> Self {
        Self { 
            charactristics: hf_to_hfx(&value.charactristics, ByteEndian::LE), 
            timestamp: HeaderFieldEx {
                raw: ((value.timestamp.value.timestamp_millis() / 1000) as u32)
                .to_le_bytes()
                .to_vec(),
                value: value.timestamp.clone(),
            },
            major_version: hf_to_hfx(&value.major_version, ByteEndian::LE),
            minor_version: hf_to_hfx(&value.minor_version, ByteEndian::LE),
            named_entry_count: hf_to_hfx(&value.named_entry_count, ByteEndian::LE),
            id_entry_count: hf_to_hfx(&value.id_entry_count, ByteEndian::LE),
            entries: value.entries
                .iter()
                .map(|e| RsrcEntryEx::from(e))
                .collect()
        }
    }
}


#[cfg(test)]
mod tests;