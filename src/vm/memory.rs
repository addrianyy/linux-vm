use super::whvp_bindings as whv;
use super::rawmem;
use std::collections::BTreeMap;

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
        if let Some((base, region)) = self.regions.range_mut(..=addr).next_back() {
            if addr < region.base + region.size {
                return Some(region);
            }
        }

        None
    }

    pub fn memory(&self, addr: u64) -> Option<&[u8]> {
        if let Some((base, region)) = self.regions.range(..=addr).next_back() {
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
        if let Some((base, region)) = self.regions.range_mut(..=addr).next_back() {
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
        self.read_phys(addr, &mut buffer).map(|x| u64::from_le_bytes(buffer))
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

    pub fn map_memory(&mut self, addr: u64, size: u64, contents: Option<&[u8]>) {
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
}
