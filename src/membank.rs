use std::collections::BTreeMap;

const PRECISE_TRACKING: bool = true;

pub struct MemBank {
    start_address: u64,
    end_address:   u64,
    next_free:     u64,
    freed:         Vec<(u64, u64)>,
    allocations:   BTreeMap<u64, u64>,
}

impl MemBank {
    fn reuse_address(&mut self, requested_size: u64) -> Option<u64> {
        for (i, &(addr, region_size)) in self.freed.iter().enumerate() {
            if region_size < requested_size {
                continue;
            }
            
            let size_left = region_size - requested_size;

            if size_left == 0 {
                self.freed.remove(i);
            } else {
                self.freed[i] = (addr + requested_size, size_left);
            }

            return Some(addr);
        }

        None
    }

    pub fn new(start_address: u64, end_address: Option<u64>) -> Self {
        Self {
            start_address,
            end_address: end_address.unwrap_or(!0),
            next_free:   start_address,
            freed:       Vec::new(),
            allocations: BTreeMap::new(),
        }
    }

    pub fn reserve_region(&mut self, size: u64) -> u64 {
        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        let addr = self.reuse_address(size).unwrap_or_else(|| {
            assert!(self.next_free.checked_add(size).unwrap() <= self.end_address,
                "Memory bank is out of space.");

            let addr = self.next_free;

            self.next_free += size;

            addr
        });

        if PRECISE_TRACKING {
            assert!(self.allocations.insert(addr, size).is_none(),
                "Region was already reserved.");
        }

        addr
    }

    pub fn return_region(&mut self, addr: u64, size: u64) {
        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        let start = addr;
        let end   = addr.checked_add(size).unwrap();

        assert!(start >= self.start_address && end <= self.end_address,
            "Tried to return region to foreign memory bank.");
        
        if PRECISE_TRACKING {
            let original_size = self.allocations.remove(&addr)
                .expect("Requested to free unknown allocation.");

            assert!(original_size == size, "Freed allocation had originally different size.");
        }

        self.freed.push((addr, size));
    }
}
