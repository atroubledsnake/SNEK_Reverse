pub mod pe;
pub mod elf;
pub mod macho;

#[allow(dead_code)]
pub trait ExecutableParser {
    fn new(data: &[u8]) -> Result<Self, ParseError> where Self: Sized;
    fn entry_point(&self) -> u64;
    fn extract_strings(&self) -> Vec<String>;
    fn imports(&self) -> Vec<String>;
    fn exports(&self) -> Vec<String>;
    fn identify_packer(&self) -> Option<String>;
    fn sections(&self) -> Vec<ExecutableSection>;
}

#[allow(dead_code)]
pub struct ExecutableSection {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub raw_data: Vec<u8>,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ParseError {
    InvalidMagic,
    UnsupportedArchitecture,
    CorruptedHeader,
    UnknownFormat,
}
