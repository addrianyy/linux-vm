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

pub struct Segment {
    pub start:      u64,
    pub size:       u64,
    pub writeable:  bool,
    pub executable: bool,
}

pub struct MappedElf {
    pub mapped:     Vec<u8>,
    pub entrypoint: u64,
    pub base:       u64,
    pub segments:   Vec<Segment>,
}

pub fn map_elf64(buffer: &[u8]) -> MappedElf {
    let entrypoint:          u64 = buffer.parse(0x18);

    let segment_table:       u64 = buffer.parse(0x20);
    let segment_count:       u16 = buffer.parse(0x38);
    let segment_header_size: u16 = buffer.parse(0x36);

    assert_eq!(segment_header_size, 0x38, "Unexpected program header size.");

    let mut segments = Vec::with_capacity(segment_count as usize);
    let mut mapped   = Vec::with_capacity(buffer.len());
    let mut base     = None;

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

        let flags: u64 = buffer.parse(segment + 0x4);

        let executable = flags & 1 != 0;
        let writeable  = flags & 2 != 0;

        segments.push(Segment {
            start: vaddr,
            size:  virt_size,
            writeable,
            executable,
        });

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

    let pad = ((mapped.len() + 0xFFF) & !0xFFF) - mapped.len();
    mapped.extend(vec![0u8; pad as usize]);

    MappedElf {
        mapped,
        entrypoint,
        base,
        segments,
    }
}
