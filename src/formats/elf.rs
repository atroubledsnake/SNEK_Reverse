use super::{ExecutableParser, ExecutableSection, ParseError};

#[allow(dead_code)]
pub struct ElfParser {
    pub is_64_bit: bool,
    pub entry_point: u64,
}

impl ExecutableParser for ElfParser {
    fn new(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 4 || &data[0..4] != b"\x7FELF" {
            return Err(ParseError::InvalidMagic);
        }

        let is_64_bit = data[4] == 2;
        
        Ok(ElfParser {
            is_64_bit,
            entry_point: 0x8048000,
        })
    }

    fn entry_point(&self) -> u64 { self.entry_point }
    fn extract_strings(&self) -> Vec<String> { vec![] }
    fn imports(&self) -> Vec<String> { vec![] }
    fn exports(&self) -> Vec<String> { vec![] }
    fn identify_packer(&self) -> Option<String> { None }
    fn sections(&self) -> Vec<ExecutableSection> { vec![] }
}
