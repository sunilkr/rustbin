#[derive(Debug)]
pub struct OptionalHeader32{
    
}

#[derive(Debug)]
pub struct OptionalHeader64{

}

#[derive(Debug)]
pub enum OptionalHeader {
    X86(OptionalHeader32),
    X64(OptionalHeader64),
}