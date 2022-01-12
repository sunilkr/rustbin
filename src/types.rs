enum Section {
    
}

#[derive(Debug, Default)]
pub struct HeaderField<T>{
    pub value: T,
    pub offset: u64,
    pub rva: u64,
}
