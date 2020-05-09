use crate::vm::*;
use crate::phys_allocator::PhysAllocator;

const PAGE_MASK:       u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_PRESENT:    u64 = 1;
const PAGE_WRITE:      u64 = 1 << 1;
const PAGE_USER:       u64 = 1 << 2;
const PAGE_SIZE:       u64 = 1 << 7;
const PAGE_XD:         u64 = 1 << 63;
const HIERARCHY_DEPTH: u64 = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemAccess {
    Kernelmode,
    Usermode,
}

#[derive(Copy, Clone, Debug)]
pub struct MemProt {
    pub execute: bool,
    pub user:    bool,
    pub write:   bool,
}

impl MemProt {
    pub fn r(acc: MemAccess) -> Self {
        Self {
            execute: false,
            write:   false,
            user:    acc == MemAccess::Usermode,
        }
    }

    pub fn rw(acc: MemAccess) -> Self {
        Self {
            execute: false,
            write:   true,
            user:    acc == MemAccess::Usermode,
        }
    }

    pub fn rx(acc: MemAccess) -> Self {
        Self {
            execute: true,
            write:   false,
            user:    acc == MemAccess::Usermode,
        }
    }

    pub fn rwx(acc: MemAccess) -> Self {
        Self {
            execute: true,
            write:   true,
            user:    acc == MemAccess::Usermode,
        }
    }
}

pub struct PagingManager<A: PhysAllocator> {
    allocator: A,
    pml4:      u64,
}

impl<A: PhysAllocator> PagingManager<A> {
    pub fn new(vm: &mut Vm, mut allocator: A) -> Self {
        let pml4 = allocator.alloc_phys(vm, 0x1000, None);

        Self {
            allocator,
            pml4,
        }
    }

    fn assert_phys_addr(phys_addr: u64) {
        assert!(phys_addr & 0xFFF == 0, "Physical address {:X} is not page aligned.", phys_addr);
    }

    fn assert_virt_addr(virt_addr: u64) {
        assert!(virt_addr & 0xFFF == 0, "Virtual address {:X} is not page aligned.", virt_addr);

        let mut addr = virt_addr as i64;
        addr <<= 16;
        addr >>= 16;

        assert!(addr as u64 == virt_addr, "Virtual address {:X} is not canonical.", virt_addr);
    }

    fn entry_index(virt_addr: u64, depth: u64) -> u64 {
        assert!(depth < HIERARCHY_DEPTH);

        (virt_addr >> (12 + 9 * (3 - depth))) & 0x1FF
    }

    fn map_virt_page(
        &mut self,
        vm:        &mut Vm,
        virt_addr: u64,
        phys_addr: u64,
        prot:      MemProt,
    ) {
        Self::assert_virt_addr(virt_addr);
        Self::assert_phys_addr(phys_addr);
        
        let page_flags = {
            let mut flags = PAGE_PRESENT;

            if  prot.user    { flags |= PAGE_USER; }
            if  prot.write   { flags |= PAGE_WRITE; }
            if !prot.execute { flags |= PAGE_XD; }

            flags
        };

        let mut current = self.pml4;

        for depth in 0..HIERARCHY_DEPTH {
            let last = depth == HIERARCHY_DEPTH - 1;

            let entry_index = Self::entry_index(virt_addr, depth);
            let entry_addr  = current + entry_index * 8;

            let mut entry_value = vm.mem().read_phys_u64(entry_addr)
                .expect("Failed to read page table entry.");

            if entry_value & PAGE_PRESENT != 0 {
                assert!(!last && entry_value & PAGE_SIZE == 0,
                    "Requested page was already mapped.");
            } else {
                entry_value = match last {
                    true  => phys_addr,
                    false => self.allocator.alloc_phys(vm, 0x1000, None),
                };

                let flags = match last {
                    true  => page_flags,
                    false => PAGE_PRESENT | PAGE_WRITE | PAGE_USER,
                };

                entry_value |= flags;

                vm.mem_mut().write_phys_u64(entry_addr, entry_value)
                    .expect("Failed to write page table entry.");
            }

            current = entry_value & PAGE_MASK;
        }
    }

    fn unmap_virt_page(
        &mut self,
        vm:        &mut Vm,
        virt_addr: u64,
    ) -> u64 {
        Self::assert_virt_addr(virt_addr);

        let mut backing_phys = 0;

        let mut walked_entries = [0; 3];
        let mut current        = self.pml4;
        
        for depth in 0..HIERARCHY_DEPTH {
            let last = depth == HIERARCHY_DEPTH - 1;

            let entry_index = Self::entry_index(virt_addr, depth);
            let entry_addr  = current + entry_index * 8;

            if !last {
                walked_entries[depth as usize] = entry_addr;
            }

            let entry_value = vm.mem().read_phys_u64(entry_addr)
                .expect("Failed to read page table entry.");

            assert!(entry_value & PAGE_PRESENT != 0, "Page to free was not mapped.");
            assert!(entry_value & PAGE_SIZE == 0, "Large pages are not supported.");

            if last {
                vm.mem_mut().write_phys_u64(entry_addr, 0)
                    .expect("Failed to zero page table entry.");

                backing_phys = entry_value & PAGE_MASK;
            }

            current = entry_value & PAGE_MASK;
        }
        
        for &entry_addr in walked_entries.iter().rev() {
            let children = vm.mem().read_phys_u64(entry_addr)
                .expect("Failed to read page table entry.");
            let children = children & PAGE_MASK;

            let mut used = false;

            for i in 0..512 {
                let child_addr  = children + i * 8;
                let child_value = vm.mem().read_phys_u64(child_addr)
                    .expect("Failed to read page table entry.");

                if child_value & PAGE_PRESENT != 0 {
                    used = true;
                    break;
                }
            }

            if used {
                break;
            }

            vm.mem_mut().write_phys_u64(entry_addr, 0)
                .expect("Failed to zero page table entry.");

            self.allocator.free_phys(vm, children, 0x1000);
        }

        backing_phys
    }

    pub fn map_virt_region(
        &mut self,
        vm:        &mut Vm,
        virt_addr: u64,
        phys_addr: u64,
        size:      u64,
        prot:      MemProt,
    ) {
        Self::assert_virt_addr(virt_addr);
        Self::assert_phys_addr(phys_addr);

        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        for offset in (0..size).step_by(0x1000) {
            let virt_addr = virt_addr + offset;
            let phys_addr = phys_addr + offset;

            self.map_virt_page(vm, virt_addr, phys_addr, prot);
        }
    }

    pub fn unmap_virt_region(
        &mut self,
        vm:        &mut Vm,
        virt_addr: u64,
        size:      u64,
    ) -> Vec<u64> {
        Self::assert_virt_addr(virt_addr);

        assert!(size & 0xFFF == 0, "Size {:X} is not page aligned.", size);

        let mut backings = Vec::with_capacity(size as usize / 0x1000);

        for offset in (0..size).step_by(0x1000) {
            let virt_addr = virt_addr + offset;
            let backing   = self.unmap_virt_page(vm, virt_addr);

            backings.push(backing);
        }

        backings
    }

    pub fn query_virt_addr(&self, vm: &Vm, virt_addr: u64) -> Option<(u64, MemProt)> {
        let offset    = virt_addr &  0xFFF;
        let virt_addr = virt_addr & !0xFFF;

        Self::assert_virt_addr(virt_addr);
        
        let mut current = self.pml4;

        for depth in 0..HIERARCHY_DEPTH {
            let last = depth == HIERARCHY_DEPTH - 1;

            let entry_index = Self::entry_index(virt_addr, depth);
            let entry_addr  = current + entry_index * 8;

            let entry_value = vm.mem().read_phys_u64(entry_addr)
                .expect("Failed to read page table entry.");

            if entry_value & PAGE_PRESENT == 0 || entry_value & PAGE_SIZE != 0 {
                break;
            }

            if last {
                let user    = entry_value & PAGE_USER  != 0;
                let write   = entry_value & PAGE_WRITE != 0;
                let execute = entry_value & PAGE_XD    == 0;

                let phys = (entry_value & PAGE_MASK) + offset;
                let prot = MemProt {
                    user,
                    write,
                    execute,
                };

                return Some((phys, prot));
            }

            current = entry_value & PAGE_MASK;
        }

        None
    }

    pub fn read_virt(&self, vm: &Vm, mut virt_addr: u64, buffer: &mut [u8]) -> Result<(), u64> {
        let mut already_read = 0;
        let mut left_to_read = buffer.len() as u64;

        while left_to_read > 0 {
            if let Some((backing, _)) = self.query_virt_addr(vm, virt_addr) {
                let offset_in_page = virt_addr & 0xFFF;

                let to_page_end = 0x1000 - offset_in_page;
                let read_len    = std::cmp::min(left_to_read, to_page_end);

                let buffer = &mut buffer[already_read as usize..];
                let buffer = &mut buffer[..read_len as usize];

                vm.mem().read_phys(backing, buffer)?;

                virt_addr    += read_len;
                left_to_read -= read_len;
                already_read += read_len;
            } else {
                return Err(already_read);
            }
        }

        Ok(())
    }

    pub fn write_virt(&self, vm: &mut Vm, mut virt_addr: u64, buffer: &[u8]) -> Result<(), u64> {
        let mut already_written = 0;
        let mut left_to_write   = buffer.len() as u64;

        while left_to_write > 0 {
            if let Some((backing, _)) = self.query_virt_addr(vm, virt_addr) {
                let offset_in_page = virt_addr & 0xFFF;

                let to_page_end    = 0x1000 - offset_in_page;
                let write_len      = std::cmp::min(left_to_write, to_page_end);

                let buffer = &buffer[already_written as usize..];
                let buffer = &buffer[..write_len as usize];

                vm.mem_mut().write_phys(backing, buffer)?;

                virt_addr       += write_len;
                left_to_write   -= write_len;
                already_written += write_len;
            } else {
                return Err(already_written);
            }
        }

        Ok(())
    }

    pub fn read_virt_u64(&self, vm: &Vm, virt_addr: u64) -> Result<u64, u64> {
        let mut buffer = [0u8; 8];
        self.read_virt(vm, virt_addr, &mut buffer).map(|_| u64::from_le_bytes(buffer))
    }

    pub fn write_virt_u64(&self, vm: &mut Vm, virt_addr: u64, value: u64) -> Result<(), u64> {
        self.write_virt(vm, virt_addr, &value.to_le_bytes())
    }

    pub fn cr3(&self) -> u64 {
        self.pml4
    }
}
