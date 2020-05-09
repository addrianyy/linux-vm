use super::whvp_bindings as whv;
use super::rawmem;
use std::collections::BTreeMap;

/*
struct Region {
    pub base:    u64,
    pub size:    u64,
    pub backing: *mut u8,
}

pub struct Memory {
    partition: whv::WHV_PARTITION_HANDLE,
    regions:   BTreeMap<u64, Region>,
}

impl Memory {
    pub(super) fn new(partition: whv::WHV_PARTITION_HANDLE) -> Self {
        Self {
            partition,
            regions: BTreeMap::new(),
        }
    }

    fn get_region_mut(&mut self, addr: u64) -> Option<&mut Region> {
        if let Some((_base, region)) = self.regions.range_mut(..=addr).next_back() {
            if addr < region.base + region.size {
                return Some(region);
            }
        }

        None
    }

    pub fn memory(&self, addr: u64) -> Option<&[u8]> {
        if let Some((_base, region)) = self.regions.range(..=addr).next_back() {
            if addr < region.base + region.size {
                let diff = addr - region.base;
                let left = region.size - diff;

                return unsafe {
                    Some(std::slice::from_raw_parts(region.backing.add(diff as usize),
                        left as usize))
                };

            }
        }

        None
    }

    pub fn memory_mut(&mut self, addr: u64) -> Option<&mut [u8]> {
        if let Some((_base, region)) = self.regions.range_mut(..=addr).next_back() {
            if addr < region.base + region.size {
                let diff = addr - region.base;
                let left = region.size - diff;

                return unsafe {
                    Some(std::slice::from_raw_parts_mut(region.backing.add(diff as usize),
                        left as usize))
                };

            }
        }

        None
    }

    pub fn read_phys_u64(&self, addr: u64) -> Result<u64, u64> {
        let mut buffer = [0u8; 8];
        self.read_phys(addr, &mut buffer).map(|_| u64::from_le_bytes(buffer))
    }


    pub fn write_phys_u64(&mut self, addr: u64, value: u64) -> Result<(), u64> {
        self.write_phys(addr, &value.to_le_bytes())
    }

    pub fn write_phys(&mut self, addr: u64, data: &[u8]) -> Result<(), u64> {
        if let Some(memory) = self.memory_mut(addr) {
            memory[..data.len()].copy_from_slice(data);
            Ok(())
        } else {
            Err(0)
        }
    }

    pub fn read_phys(&self, addr: u64, data: &mut [u8]) -> Result<(), u64> {
        if let Some(memory) = self.memory(addr) {
            data.copy_from_slice(&memory[..data.len()]);
            Ok(())
        } else {
            Err(0)
        }
    }

    pub fn map_phys_region(&mut self, addr: u64, size: u64, contents: Option<&[u8]>) {
        assert!(addr & 0xfff == 0, "Address {:X} is not page aligned.", addr);

        let aligned_size = (size + 0xfff) & !0xfff;

        if let Some(contents) = contents {
            assert!(contents.len() <= size as usize,
                "Contents buffer is bigger than requested mapping.");
        }

        let backing = unsafe { rawmem::raw_alloc(aligned_size as usize) };
        if let Some(contents) = contents {
            unsafe {
                std::ptr::copy_nonoverlapping(contents.as_ptr(), backing, contents.len());
            }
        }

        unsafe {
            let success = whv::WHvMapGpaRange(self.partition, 
                backing as _, addr, aligned_size, 1 | 2 | 4);

            assert!(success >= 0);
        }

        let region = Region {
            base: addr,
            size: aligned_size,
            backing,
        };

        self.regions.insert(addr, region);
    }

    pub fn unmap_phys_region(&mut self, _addr: u64, _size: u64) {
    }
}
*/

const RWX_PERMS: i32 = 1 | 2 | 4;

#[derive(Copy, Clone)]
struct Region {
    pub size:    u64,
    pub backing: *mut u8,
}

impl Region {
    fn offseted_slice(&self, offset: u64) -> &[u8] {
        let size_left = self.size.checked_sub(offset)
            .expect("Offset is out of bounds.");

        unsafe {
            std::slice::from_raw_parts(self.backing.add(offset as usize), size_left as usize)
        }
    }

    fn offseted_slice_mut(&mut self, offset: u64) -> &mut [u8] {
        let size_left = self.size.checked_sub(offset)
            .expect("Offset is out of bounds.");

        unsafe {
            std::slice::from_raw_parts_mut(self.backing.add(offset as usize), size_left as usize)
        }
    }
}

pub struct Memory {
    partition: whv::WHV_PARTITION_HANDLE,
    regions:   BTreeMap<u64, Region>,
}

impl Memory {
    pub(super) fn new(partition: whv::WHV_PARTITION_HANDLE) -> Self {
        Self {
            partition,
            regions: BTreeMap::new(),
        }
    }

    fn assert_addr_size(addr: u64, size: u64) {
        assert!(addr & 0xFFF == 0, "Physical address {:X} is not page aligned.", addr);
        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);
    }

    fn assert_unique(&self, addr: u64, size: u64) {
        assert!(self.regions.get(&addr).is_none(), "Hasref");
        // TODO
    }

    fn region(&self, addr: u64) -> Option<(Region, u64)> {
        if let Some((base, region)) = self.regions.range(..=addr).next_back() {
            let start = *base;
            let end   = *base + region.size;

            if addr >= start && addr < end {
                let offset = addr - start;

                return Some((*region, offset));
            }
        }

        None
    }

    pub fn map_phys_region(&mut self, addr: u64, size: u64, contents: Option<&[u8]>) {
        Self::assert_addr_size(addr, size);

        self.assert_unique(addr, size);

        if let Some(contents) = contents {
            assert!(contents.len() <= size as usize,
                "Contents buffer is bigger than region to map.");
        }

        let backing = unsafe {
            let backing = rawmem::raw_alloc(size as usize);

            if let Some(contents) = contents {
                std::ptr::copy_nonoverlapping(contents.as_ptr(), backing, contents.len());
            }

            backing
        };

        let result = unsafe {
            whv::WHvMapGpaRange(self.partition, backing as _, addr, size, RWX_PERMS)
        };

        if result < 0 {
            unsafe {
                rawmem::raw_free(backing);
            }

            panic!("Mapping GPA range failed with result {:X}.", result);
        }

        let region = Region {
            size,
            backing,
        };

        assert!(self.regions.insert(addr, region).is_none(), "Region was already mapped (??).");
    }

    pub fn unmap_phys_region(&mut self, addr: u64, size: u64) {
        Self::assert_addr_size(addr, size);

        let region = self.regions.remove(&addr).expect("Region to unmap was not mapped.");

        let result = unsafe {
            let result = whv::WHvUnmapGpaRange(self.partition, addr, region.size);

            rawmem::raw_free(region.backing);

            result
        };

        assert!(result >= 0, "Unmapping GPA range failed with result {:X}.", result);
        assert!(size == region.size, "Region to unmap has invalid size. Got: {:X}, actual {:X}.",
            size, region.size);
    }

    pub fn read_phys(&self, mut addr: u64, mut buffer: &mut [u8]) -> Result<(), u64> {
        let mut already_read = 0;
        let mut left_to_read = buffer.len();

        while left_to_read > 0 {
            if let Some((region, offset)) = self.region(addr) {
                let backing  = region.offseted_slice(offset);
                let read_len = std::cmp::min(left_to_read, backing.len());

                let buffer = &mut buffer[already_read..];
                let buffer = &mut buffer[..read_len];

                buffer.copy_from_slice(&backing[..read_len]);

                addr         += read_len as u64;
                left_to_read -= read_len;
                already_read += read_len;
            } else {
                return Err(already_read as u64);
            }
        }
        
        Ok(())
    }

    pub fn write_phys(&mut self, mut addr: u64, buffer: &[u8]) -> Result<(), u64> {
        let mut already_written = 0;
        let mut left_to_write   = buffer.len();

        while left_to_write > 0 {
            if let Some((mut region, offset)) = self.region(addr) {
                let backing   = region.offseted_slice_mut(offset);
                let write_len = std::cmp::min(left_to_write, backing.len());

                let buffer = &buffer[already_written..];
                let buffer = &buffer[..write_len];

                backing[..write_len].copy_from_slice(buffer);

                addr            += write_len as u64;
                left_to_write   -= write_len;
                already_written += write_len;
            } else {
                return Err(already_written as u64);
            }
        }
        
        Ok(())
    }

    pub fn read_phys_u64(&self, addr: u64) -> Result<u64, u64> {
        let mut buffer = [0u8; 8];
        self.read_phys(addr, &mut buffer).map(|_| u64::from_le_bytes(buffer))
    }

    pub fn write_phys_u64(&mut self, addr: u64, value: u64) -> Result<(), u64> {
        self.write_phys(addr, &value.to_le_bytes())
    }
}
