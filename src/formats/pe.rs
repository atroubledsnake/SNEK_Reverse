use super::{ExecutableParser, ExecutableSection, ParseError};

pub struct PeParser {
    pub is_64_bit: bool,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<ExecutableSection>,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

impl ExecutableParser for PeParser {
    fn new(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 0x40 {
            return Err(ParseError::InvalidMagic);
        }

        if data[0] != b'M' || data[1] != b'Z' {
            return Err(ParseError::InvalidMagic);
        }

        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        if data.len() < e_lfanew + 24 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(ParseError::CorruptedHeader);
        }

        let machine = u16::from_le_bytes(data[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
        let num_sections = u16::from_le_bytes(data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap());
        let size_of_optional_header = u16::from_le_bytes(data[e_lfanew + 20..e_lfanew + 22].try_into().unwrap());
        
        let is_64_bit = machine == 0x8664 || machine == 0xAA64;

        let optional_header_offset = e_lfanew + 24;
        if data.len() < optional_header_offset + size_of_optional_header as usize {
            return Err(ParseError::CorruptedHeader);
        }

        let magic = u16::from_le_bytes(data[optional_header_offset..optional_header_offset + 2].try_into().unwrap());
        if (is_64_bit && magic != 0x20B) || (!is_64_bit && magic != 0x10B) {
            return Err(ParseError::InvalidMagic);
        }

        let entry_point = u32::from_le_bytes(data[optional_header_offset + 16..optional_header_offset + 20].try_into().unwrap()) as u64;
        let image_base = if is_64_bit {
            u64::from_le_bytes(data[optional_header_offset + 24..optional_header_offset + 32].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[optional_header_offset + 28..optional_header_offset + 32].try_into().unwrap()) as u64
        };

        fn read_u16(data: &[u8], off: usize) -> Option<u16> {
            if off + 2 > data.len() {
                None
            } else {
                Some(u16::from_le_bytes([data[off], data[off + 1]]))
            }
        }

        fn read_u32(data: &[u8], off: usize) -> Option<u32> {
            if off + 4 > data.len() {
                None
            } else {
                Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
            }
        }

        fn read_u64(data: &[u8], off: usize) -> Option<u64> {
            if off + 8 > data.len() {
                None
            } else {
                Some(u64::from_le_bytes([
                    data[off],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                ]))
            }
        }

        fn read_cstr(data: &[u8], off: usize) -> Option<String> {
            if off >= data.len() {
                return None;
            }
            let mut end = off;
            while end < data.len() && data[end] != 0 {
                end += 1;
                if end - off > 4096 {
                    break;
                }
            }
            if end == off {
                return Some(String::new());
            }
            Some(String::from_utf8_lossy(&data[off..end]).into_owned())
        }

        let mut sections = Vec::new();
        let section_table_offset = optional_header_offset + size_of_optional_header as usize;
        
        for i in 0..num_sections {
            let offset = section_table_offset + (i as usize * 40);
            if data.len() < offset + 40 {
                break;
            }

            let mut name_bytes = data[offset..offset+8].to_vec();
            name_bytes.retain(|&c| c != 0);
            let name = String::from_utf8_lossy(&name_bytes).into_owned();

            let virtual_size = u32::from_le_bytes(data[offset+8..offset+12].try_into().unwrap()) as u64;
            let virtual_address = u32::from_le_bytes(data[offset+12..offset+16].try_into().unwrap()) as u64;
            let size_of_raw_data = u32::from_le_bytes(data[offset+16..offset+20].try_into().unwrap()) as u64;
            let pointer_to_raw_data = u32::from_le_bytes(data[offset+20..offset+24].try_into().unwrap()) as usize;
            let characteristics = u32::from_le_bytes(data[offset+36..offset+40].try_into().unwrap());

            let raw_data = if data.len() >= pointer_to_raw_data + size_of_raw_data as usize {
                data[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data as usize].to_vec()
            } else {
                Vec::new()
            };

            sections.push(ExecutableSection {
                name,
                virtual_address,
                size: virtual_size,
                raw_offset: pointer_to_raw_data as u64,
                raw_size: size_of_raw_data,
                raw_data,
                executable: (characteristics & 0x20000000) != 0,
                readable: (characteristics & 0x40000000) != 0,
                writable: (characteristics & 0x80000000) != 0,
            });
        }

        let rva_to_file_off = |rva: u64| -> Option<usize> {
            for sec in &sections {
                let start = sec.virtual_address;
                let len = sec.size.max(sec.raw_size);
                if rva >= start && rva < start.saturating_add(len) {
                    let delta = rva - start;
                    let file_off = sec.raw_offset.saturating_add(delta) as usize;
                    if file_off < data.len() {
                        return Some(file_off);
                    }
                }
            }
            None
        };

        let (dd_off, dd_count_off) = if is_64_bit {
            (optional_header_offset + 112, optional_header_offset + 108)
        } else {
            (optional_header_offset + 96, optional_header_offset + 92)
        };

        let number_rva_and_sizes = read_u32(data, dd_count_off).unwrap_or(0) as usize;
        let mut export_rva: u64 = 0;
        let mut import_rva: u64 = 0;
        if number_rva_and_sizes >= 2 {
            if let Some(v) = read_u32(data, dd_off + 0) {
                export_rva = v as u64;
            }
            if let Some(v) = read_u32(data, dd_off + 8) {
                import_rva = v as u64;
            }
        }

        let mut imports: Vec<String> = Vec::new();
        if import_rva != 0 {
            if let Some(mut off) = rva_to_file_off(import_rva) {
                for _ in 0..8192 {
                    let orig_first_thunk = read_u32(data, off).unwrap_or(0);
                    let _time_date_stamp = read_u32(data, off + 4).unwrap_or(0);
                    let _forwarder_chain = read_u32(data, off + 8).unwrap_or(0);
                    let name_rva = read_u32(data, off + 12).unwrap_or(0);
                    let first_thunk = read_u32(data, off + 16).unwrap_or(0);
                    if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                        break;
                    }

                    let dll_name = name_rva as u64;
                    let dll = rva_to_file_off(dll_name).and_then(|o| read_cstr(data, o)).unwrap_or_default();
                    let thunk_rva = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk } as u64;
                    if thunk_rva == 0 {
                        off += 20;
                        continue;
                    }

                    if let Some(mut toff) = rva_to_file_off(thunk_rva) {
                        for _ in 0..65535 {
                            let entry = if is_64_bit {
                                read_u64(data, toff).unwrap_or(0)
                            } else {
                                read_u32(data, toff).unwrap_or(0) as u64
                            };
                            if entry == 0 {
                                break;
                            }
                            let is_ordinal = if is_64_bit { (entry & (1u64 << 63)) != 0 } else { (entry & (1u64 << 31)) != 0 };
                            if is_ordinal {
                                let ord = (entry & 0xFFFF) as u64;
                                imports.push(format!("{}!#{}", dll, ord));
                            } else {
                                let ibn_rva = (entry & 0x7FFF_FFFF_FFFF_FFFF) as u64;
                                if let Some(n_off) = rva_to_file_off(ibn_rva) {
                                    let name_off = n_off + 2;
                                    if let Some(func) = read_cstr(data, name_off) {
                                        if !func.is_empty() {
                                            imports.push(format!("{}!{}", dll, func));
                                        }
                                    }
                                }
                            }
                            toff += if is_64_bit { 8 } else { 4 };
                        }
                    }

                    off += 20;
                }
            }
        }
        imports.sort();
        imports.dedup();

        let mut exports: Vec<String> = Vec::new();
        if export_rva != 0 {
            if let Some(eoff) = rva_to_file_off(export_rva) {
                let name_rva = read_u32(data, eoff + 12).unwrap_or(0) as u64;
                let base = read_u32(data, eoff + 16).unwrap_or(0) as u64;
                let number_of_functions = read_u32(data, eoff + 20).unwrap_or(0) as u64;
                let number_of_names = read_u32(data, eoff + 24).unwrap_or(0) as u64;
                let addr_of_names = read_u32(data, eoff + 32).unwrap_or(0) as u64;
                let addr_of_name_ordinals = read_u32(data, eoff + 36).unwrap_or(0) as u64;

                let dll = rva_to_file_off(name_rva).and_then(|o| read_cstr(data, o)).unwrap_or_default();
                let mut named: std::collections::HashSet<u64> = std::collections::HashSet::new();

                if let (Some(n_off), Some(o_off)) = (rva_to_file_off(addr_of_names), rva_to_file_off(addr_of_name_ordinals)) {
                    for i in 0..number_of_names.min(65535) {
                        let nrva = read_u32(data, n_off + (i as usize * 4)).unwrap_or(0) as u64;
                        let ord_idx = read_u16(data, o_off + (i as usize * 2)).unwrap_or(0) as u64;
                        let ord = base + ord_idx;
                        let name = rva_to_file_off(nrva).and_then(|o| read_cstr(data, o)).unwrap_or_default();
                        if !name.is_empty() {
                            if dll.is_empty() {
                                exports.push(name);
                            } else {
                                exports.push(format!("{}!{}", dll, name));
                            }
                            named.insert(ord);
                        }
                    }
                }

                if number_of_functions > 0 && number_of_functions <= 65535 {
                    for i in 0..number_of_functions {
                        let ord = base + i;
                        if named.contains(&ord) {
                            continue;
                        }
                        if dll.is_empty() {
                            exports.push(format!("#{}", ord));
                        } else {
                            exports.push(format!("{}!#{}", dll, ord));
                        }
                    }
                }
            }
        }
        exports.sort();
        exports.dedup();

        let strings = Vec::new();

        Ok(PeParser {
            is_64_bit,
            entry_point,
            image_base,
            sections,
            strings,
            imports,
            exports,
        })
    }

    fn entry_point(&self) -> u64 {
        self.entry_point + self.image_base
    }

    fn extract_strings(&self) -> Vec<String> {
        self.strings.clone()
    }

    fn imports(&self) -> Vec<String> {
        self.imports.clone()
    }

    fn exports(&self) -> Vec<String> {
        self.exports.clone()
    }

    fn identify_packer(&self) -> Option<String> {
        for sec in &self.sections {
            if sec.name.contains("UPX") || sec.name.contains(".aspack") {
                return Some(sec.name.clone());
            }
        }
        None
    }

    fn sections(&self) -> Vec<ExecutableSection> {
        let mut cloned = Vec::new();
        for sec in &self.sections {
            cloned.push(ExecutableSection {
                name: sec.name.clone(),
                virtual_address: sec.virtual_address,
                size: sec.size,
                raw_offset: sec.raw_offset,
                raw_size: sec.raw_size,
                raw_data: sec.raw_data.clone(),
                executable: sec.executable,
                readable: sec.readable,
                writable: sec.writable,
            });
        }
        cloned
    }
}
