use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{pe::import::{ImpLookup, ImportDescriptor, ImportLookup, ImportName}, types::HeaderField};

use super::{hf_to_hfx, ByteEndian, HeaderFieldEx};

#[derive(Debug, Serialize)]
pub struct ImportDescriptorEx {
    #[serde(rename="import_lookup_table")]
    pub ilt: HeaderFieldEx<u32>,
    pub timestamp: HeaderFieldEx<DateTime<Utc>>,
    pub forwarder_chain: HeaderFieldEx<u32>,
    pub name_rva: HeaderFieldEx<u32>,
    pub first_thunk: HeaderFieldEx<u32>,
    pub name: Option<String>,
    pub imports: Vec<ImportLookupEx>,
}

impl From<&ImportDescriptor> for ImportDescriptorEx{
    fn from(value: &ImportDescriptor) -> Self {
        Self { 
            ilt: hf_to_hfx(&value.ilt, ByteEndian::LE), 
            timestamp: HeaderFieldEx { 
                raw: ((value.timestamp.value.timestamp_millis() / 1000) as u32)
                    .to_le_bytes()
                    .to_vec(),
                value: value.timestamp.clone(),
            }, 
            forwarder_chain: hf_to_hfx(&value.forwarder_chain, ByteEndian::LE), 
            name_rva: hf_to_hfx(&value.name_rva, ByteEndian::LE), 
            first_thunk: hf_to_hfx(&value.first_thunk, ByteEndian::LE), 
            name: value.name.clone(), 
            imports: value.imports
                .iter()
                .map(|il| ImportLookupEx::from(il))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum ImportLookupEx {
    #[serde(untagged)]
    X86(ImpLookupEx<u32>),
    #[serde(untagged)]
    X64(ImpLookupEx<u64>),
}

impl From<&ImportLookup> for ImportLookupEx {
    fn from(value: &ImportLookup) -> Self {
        match value {
            ImportLookup::X86(il) => ImportLookupEx::X86(ImpLookupEx::from(il)),
            ImportLookup::X64(il) => ImportLookupEx::X64(ImpLookupEx::from(il)),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ImpLookupEx<T> {
    pub value: HeaderFieldEx<T>,
    pub is_ordinal: bool,
    #[serde(skip_serializing_if="Option::is_none")]
    pub ordinal: Option<u16>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub iname: Option<HeaderField<ImportNameEx>>,
}

impl From<&ImpLookup<u32>> for ImpLookupEx<u32> {
    fn from(value: &ImpLookup<u32>) -> Self {
        Self { 
            value: hf_to_hfx(&value.value, ByteEndian::LE), 
            is_ordinal: value.is_ordinal, 
            ordinal: value.ordinal, 
            iname: if let Some(il) = &value.iname {
                Some(
                    HeaderField { 
                        value: ImportNameEx::from(&il.value),
                        offset: il.offset,
                        rva: il.rva,
                        size: il.size,
                    }
                )
            }
            else { None }
        }
    }
}


impl From<&ImpLookup<u64>> for ImpLookupEx<u64> {
    fn from(value: &ImpLookup<u64>) -> Self {
        Self { 
            value: hf_to_hfx(&value.value, ByteEndian::LE), 
            is_ordinal: value.is_ordinal, 
            ordinal: value.ordinal, 
            iname: if let Some(il) = &value.iname {
                Some(
                    HeaderField { 
                        value: ImportNameEx::from(&il.value),
                        offset: il.offset,
                        rva: il.rva,
                        size: il.size,
                    }
                )
            }
            else { None }
        }
    }
}


#[derive(Debug, Serialize)]
pub struct ImportNameEx {
    pub hint: HeaderFieldEx<u16>,
    pub name: HeaderFieldEx<String>,
}

impl From<&ImportName> for ImportNameEx {
    fn from(value: &ImportName) -> Self {
        Self { 
            hint: hf_to_hfx(&value.hint, ByteEndian::LE),
            name: HeaderFieldEx { 
                raw: value.name.value.as_bytes().to_vec(),
                value: value.name.clone()
            } 
        }
    }
}
