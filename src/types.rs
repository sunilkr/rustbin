use std::fmt::{Debug, Display};

#[derive(Debug, Default)]
pub struct HeaderField<T>{
    pub value: T,
    pub offset: u64,
    pub rva: u64,
}

// impl<T> Debug for HeaderField<T> where T: Debug {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{:?}(0x{:x?}])@{{0x{:x?}, 0x{:?}}}", self.value, self.value, self.offset, self.rva)
//     }
// }

impl<T> Display for HeaderField<T> where T: Display {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}
