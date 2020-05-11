use std::collections::BTreeMap;

trait Parse {
    fn parse<T: Copy>(&self, off: u32) -> T;
}

impl Parse for [u8] {
    fn parse<T: Copy>(&self, off: u32) -> T {
        assert!(
            off as usize + std::mem::size_of::<T>() <= self.len(),
            "Tried to read out of bounds memory."
        );

        unsafe {
            let ptr = self.as_ptr().offset(off as isize);
            (ptr as *const T).read()
        }
    }
}

pub struct Section {
    pub start:      u64,
    pub size:       u64,
    pub writeable:  bool,
    pub executable: bool,
}

pub struct MappedElf {
    pub mapped:     Vec<u8>,
    pub entrypoint: u64,
    pub base:       u64,
    pub sections:   Vec<Section>,
}

pub fn map_elf64(buffer: &[u8]) -> MappedElf {
    let entrypoint:          u64 = buffer.parse(0x18);

    let segment_table:       u64 = buffer.parse(0x20);
    let segment_count:       u16 = buffer.parse(0x38);
    let segment_header_size: u16 = buffer.parse(0x36);

    let section_table:       u64 = buffer.parse(0x28);
    let section_count:       u16 = buffer.parse(0x3C);
    let section_header_size: u16 = buffer.parse(0x3A);

    assert_eq!(segment_header_size, 0x38, "Unexpected program header size.");
    assert_eq!(section_header_size, 0x40, "Unexpected section header size.");

    let mut mapped = Vec::with_capacity(buffer.len());
    let mut base   = None;

    for i in 0..(segment_count as u64) {
        let segment = (segment_table + i * segment_header_size as u64) as u32;

        let segment_type: u32 = buffer.parse(segment);
        if  segment_type != 1 {
            continue;
        }

        let file_off:  u64 = buffer.parse(segment + 0x08);
        let vaddr:     u64 = buffer.parse(segment + 0x10);
        let file_size: u64 = buffer.parse(segment + 0x20);
        let virt_size: u64 = buffer.parse(segment + 0x28);

        if base == None {
            base = Some(vaddr);
        }

        let virt_offset = vaddr - base.unwrap();

        let pad = virt_offset as usize - mapped.len();
        mapped.extend(vec![0u8; pad]);

        let raw = file_off as usize;
        let len = std::cmp::min(file_size, virt_size);
        mapped.extend_from_slice(&buffer[raw..raw + len as usize]);

        let pad = virt_size - file_size;
        mapped.extend(vec![0u8; pad as usize]);
    }

    let base = base.expect("ELF has no loadable sections.");

    let mut sections = BTreeMap::new();

    for i in 0..(section_count as u64) {
        let section = (section_table + i * section_header_size as u64) as u32;
        
        let section_type: u32 = buffer.parse(section + 0x4);
        if  section_type == 0 {
            continue;
        }

        let flags: u64 = buffer.parse(section + 0x8);
        if flags & 2 == 0 {
            continue;
        }

        let writeable  = flags & 1 != 0;
        let executable = flags & 4 != 0;

        let start: u64 = buffer.parse(section + 0x10);
        let size:  u64 = buffer.parse(section + 0x20);

        if size == 0 || start < base {
            continue;
        }

        let start = start & !0xFFF;
        let size  = (size + 0xFFF) & !0xFFF;
        
        let previous = sections.insert(start, Section {
            writeable,
            executable,
            start,
            size,
        });

        if let Some(previous) = previous {
            assert!(writeable == previous.writeable && executable == previous.executable,
                "Sections on the same page have different memory permissions.");
        }
    }

    let pad = ((mapped.len() + 0xFFF) & !0xFFF) - mapped.len();
    mapped.extend(vec![0u8; pad as usize]);

    let sections = sections.into_iter().map(|(_k, v)| v).collect();

    MappedElf {
        mapped,
        entrypoint,
        base,
        sections,
    }
}
