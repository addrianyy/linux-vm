use crate::vm::*;
use crate::membank::MemBank;

pub trait PhysAllocator {
    fn alloc_phys(&mut self, vm: &mut Vm, size: u64, contents: Option<&[u8]>) -> u64;
    fn free_phys(&mut self, vm: &mut Vm, addr: u64, size: u64);
}

pub struct ContinousPhysAllocator {
    bank: MemBank,
}

impl ContinousPhysAllocator {
    pub fn new(start_address: u64, end_address: Option<u64>) -> Self {
        Self {
            bank: MemBank::new(start_address, end_address),
        }
    }
}

impl PhysAllocator for ContinousPhysAllocator {
    fn alloc_phys(&mut self, vm: &mut Vm, size: u64, contents: Option<&[u8]>) -> u64 {
        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        let addr = self.bank.reserve_region(size);

        vm.mem_mut().map_phys_region(addr, size, contents);

        addr
    }

    fn free_phys(&mut self, vm: &mut Vm, addr: u64, size: u64) {
        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        self.bank.return_region(addr, size);

        vm.mem_mut().unmap_phys_region(addr, size);
    }
}
