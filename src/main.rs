mod vm;
use vm::*;
use std::time::Duration;


fn make_segment(base: u64, limit: u64, attribs: SegAttribs) -> u64 {
    let mut segment = 0;

    segment |= ((base >>  0) & 0xFFFF) << 16;
    segment |= ((base >> 16) &   0xFF) << 32;
    segment |= ((base >> 24) &   0xFF) << 56;


    segment |= ((limit >>  0) & 0xFFFF) << 0;
    segment |= ((limit >> 16) &    0xF) << 48;

    segment |= (attribs.build() as u64) << 40;

    segment
}

pub struct ContinousAllocator {
    next_free:   u64,
    end_address: u64,
}

impl ContinousAllocator {
    pub fn new(start_address: u64, end_address: Option<u64>) -> Self {
        Self {
            next_free:   start_address,
            end_address: end_address.unwrap_or(!0),
        }
    }

    pub fn alloc_phys(&mut self, vm: &mut Vm, size: u64, contents: Option<&[u8]>) -> u64 {
        let size = (size + 0xfff) & !0xfff;

        assert!(self.next_free.checked_add(size).unwrap() <= self.end_address,
            "Continous allocator is out of space.");

        let address = self.next_free;

        self.next_free += size;

        vm.mem_mut().map_memory(address, size, contents);

        address
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum MemoryType {
    Kernelmode,
    Usermode,
}

#[derive(Copy, Clone, Debug)]
pub struct MemoryProtection {
    pub execute: bool,
    pub user:    bool,
    pub write:   bool,
}

impl MemoryProtection {
    pub fn r(t: MemoryType) -> Self {
        Self {
            execute: false,
            write:   false,
            user:    t == MemoryType::Usermode,
        }
    }

    pub fn rw(t: MemoryType) -> Self {
        Self {
            execute: false,
            write:   true,
            user:    t == MemoryType::Usermode,
        }
    }

    pub fn rx(t: MemoryType) -> Self {
        Self {
            execute: true,
            write:   false,
            user:    t == MemoryType::Usermode,
        }
    }

    pub fn rwx(t: MemoryType) -> Self {
        Self {
            execute: true,
            write:   true,
            user:    t == MemoryType::Usermode,
        }
    }
}

pub struct PagingManager {
    allocator: ContinousAllocator,
    pml4:      u64,
}

impl PagingManager {
    pub fn new(vm: &mut Vm, mut allocator: ContinousAllocator) -> Self {
        let pml4 = allocator.alloc_phys(vm, 0x1000, None);

        Self {
            allocator,
            pml4,
        }
    }

    fn map_virtual_page(
        &mut self,
        vm:         &mut Vm,
        virt_addr:  u64,
        phys_addr:  u64,
        prot:       MemoryProtection,
    ) {
        const PAGE_MASK:    u64 = 0x000F_FFFF_FFFF_F000; 
        const PAGE_PRESENT: u64 = 1;
        const PAGE_WRITE:   u64 = 1 << 1;
        const PAGE_USER:    u64 = 1 << 2;
        const PAGE_SIZE:    u64 = 1 << 7;
        const PAGE_XD:      u64 = 1 << 63;

        assert!(virt_addr & 0xfff == 0, "Virtual address {:X} is not page aligned.", virt_addr);
        assert!(phys_addr & 0xfff == 0, "Physical address {:X} is not page aligned.", phys_addr);
        
        let page_flags = {
            let mut flags = 0;

            if  prot.user    { flags |= PAGE_USER; }
            if  prot.write   { flags |= PAGE_WRITE; }
            if !prot.execute { flags |= PAGE_XD; }

            flags
        };

        let mut current = self.pml4;

        for depth in 0..4 {
            let last = depth == 3;

            let entry_index = virt_addr >> (12 + 9 * (3 - depth));
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
                    false => PAGE_WRITE | PAGE_USER,
                };

                entry_value |= flags | PAGE_PRESENT;

                vm.mem_mut().write_phys_u64(entry_addr, entry_value)
                    .expect("Failed to write page table entry.");
            }

            current = entry_value & PAGE_MASK;
        }
    }

    fn unmap_virtual_page(&mut self, vm: &mut Vm, virt_addr: u64) {
        const PAGE_MASK:    u64 = 0x000F_FFFF_FFFF_F000; 
        const PAGE_PRESENT: u64 = 1;
        const PAGE_SIZE:    u64 = 1 << 7;

        assert!(virt_addr & 0xfff == 0, "Virtual address {:X} is not page aligned.", virt_addr);

        let mut walked_entries = [0; 4];
        let mut current = self.pml4;
        
        for depth in 0..4 {
            let last = depth == 3;

            let entry_index = virt_addr >> (12 + 9 * (3 - depth));
            let entry_addr  = current + entry_index * 8;

            walked_entries[depth] = entry_addr;

            let mut entry_value = vm.mem().read_phys_u64(entry_addr)
                .expect("Failed to read page table entry.");

            assert!(entry_value & PAGE_PRESENT != 0, "Page was not mapped.");
            assert!(entry_value & PAGE_SIZE == 0, "Large pages are unsupported.");

            if last {
                vm.mem_mut().write_phys_u64(entry_addr, 0)
                    .expect("Failed to zero page table entry.");

                // TODO: deallocate
            }

            current = entry_value & PAGE_MASK;
        }

        for &entry in walked_entries.iter().rev().skip(1) {
            let children = vm.mem_mut().read_phys_u64(entry)
                .expect("Failed to read page table entry.");
            let children = children & PAGE_MASK;

            let mut used = false;

            for i in 0..512 {
                let entry_addr  = current + i * 8;
                let entry_value = vm.mem().read_phys_u64(entry_addr)
                    .expect("Failed to read page table entry.");

                if entry_value & PAGE_PRESENT != 0 {
                    used = true;
                    break;
                }
            }

            if !used {
                vm.mem_mut().write_phys_u64(entry, 0)
                    .expect("Failed to zero page table entry.");

                // TODO: deallocate
            } else {
                break;
            }
        }
    }

    pub fn map_region(
        &mut self,
        vm:         &mut Vm,
        virt_addr:  u64,
        phys_addr:  u64,
        size:       u64,
        prot:       MemoryProtection,
    ) {
        assert!(virt_addr & 0xfff == 0, "Virtual address {:X} is not page aligned.", virt_addr);
        assert!(phys_addr & 0xfff == 0, "Physical address {:X} is not page aligned.", phys_addr);

        let aligned_size = (size + 0xfff) & !0xfff;

        for offset in (0..aligned_size).step_by(0x1000) {
            let virt_addr = virt_addr + offset;
            let phys_addr = phys_addr + offset;

            self.map_virtual_page(vm, virt_addr, phys_addr, prot);
        }
    }

    pub fn cr3(&self) -> u64 {
        self.pml4
    }
}

pub enum PageSize {
    Page4KB,
    Page2MB,
}

struct Paging {
    pml4: u64,
    free: u64,
}

impl Paging {
    fn alloc4k(&mut self, vm: &mut Vm) -> u64 {
        let addr = self.free;

        self.free += 0x1000;

        vm.mem_mut().map_memory(addr, 0x1000, None);

        addr
    }

    pub fn cr3(&self) -> u64 {
        self.pml4
    }

    pub fn new(vm: &mut Vm) -> Self {
        let mut paging = Self {
            pml4: 0,
            free: 1u64 << 36,
        };

        paging.pml4 = paging.alloc4k(vm);

        paging
    }

    pub fn map_page(&mut self, vm: &mut Vm, vaddr: u64, paddr: u64) {
        const PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000; 

        assert!(vaddr & 0xFFF == 0);
        assert!(paddr & 0xFFF == 0);

        use std::convert::TryInto;

        let indices: [(u64, bool); 4] = [
            (((vaddr >> 39) & 0x1FF), false),
            (((vaddr >> 30) & 0x1FF), false),
            (((vaddr >> 21) & 0x1FF), false),
            (((vaddr >> 12) & 0x1FF), true),
        ];

        let mut cur = self.pml4;

        for &(index, alloc) in &indices {
            let ptr = cur + index * 8;

            let mut buf = [0u8; 8];
            vm.mem().read_phys(ptr, &mut buf);

            let mut val = u64::from_le_bytes(buf.try_into().unwrap());

            if val & 1 != 0 {
                assert!(!alloc, "Requested page is already allocated. {:X}", vaddr);
                assert!(val & (1 << 7) == 0, "Large page in 0xFFFF... region.");
            } else {
                let page = if alloc {
                    paddr
                } else {
                    self.alloc4k(vm)
                };

                val = (page as u64) | 1 | (1 << 1) | (1 << 2);

                vm.mem_mut().write_phys(ptr, &val.to_le_bytes());
            }

            if !alloc {
                cur = val & PAGE_MASK;
            }
        }

    }
}

fn main() {
    let exit_exceptions = [
        ExceptionVector::DivideErrorFault,
        ExceptionVector::DebugTrapOrFault,
        ExceptionVector::BreakpointTrap,
        ExceptionVector::OverflowTrap,
        ExceptionVector::BoundRangeFault,
        ExceptionVector::InvalidOpcodeFault,
        ExceptionVector::DeviceNotAvailableFault,
        ExceptionVector::DoubleFaultAbort,
        ExceptionVector::InvalidTaskStateSegmentFault,
        ExceptionVector::SegmentNotPresentFault,
        ExceptionVector::StackFault,
        ExceptionVector::GeneralProtectionFault,
        ExceptionVector::PageFault,
        ExceptionVector::FloatingPointErrorFault,
        ExceptionVector::AlignmentCheckFault,
        ExceptionVector::MachineCheckAbort,
        ExceptionVector::SimdFloatingPointFault,
    ];

    let mut page_table_allocator = ContinousAllocator::new(1 << 30, None);

    let mut vm = Vm::new(&exit_exceptions);
    let mut paging = PagingManager::new(&mut vm, page_table_allocator);

    //let mut paging = Paging::new(&mut vm);

    let wanted_cpl = 3;

    let code_attribs = SegAttribs {
        seg_type:    0b1011,
        non_system:  true,
        dpl:         wanted_cpl,
        present:     true,
        default:     false,
        granularity: false,
        long:        true,
    };

    let data_attribs = SegAttribs {
        seg_type:    0b0011,
        non_system:  true,
        dpl:         wanted_cpl,
        present:     true,
        default:     false,
        granularity: false,
        long:        false,
    };

    {
        let gdt_addr = 0x1000;

        let mut gdt_contents = Vec::new();
        gdt_contents.extend_from_slice(&0u64.to_le_bytes());
        gdt_contents.extend_from_slice(&make_segment(0, 0, code_attribs).to_le_bytes());
        gdt_contents.extend_from_slice(&make_segment(0, 0, data_attribs).to_le_bytes());

        assert!(gdt_contents.len() == 8 * 3);

        vm.mem_mut().map_memory(gdt_addr, 0x1000, Some(&gdt_contents));

        vm.regs_mut().gdtr = TableReg {
            base:  gdt_addr,
            limit: gdt_contents.len() as u16 - 1
        };
    }

    {
        let code_seg = SegReg {
            sel:     0x04 | wanted_cpl as u16,
            base:    0,
            limit:   0,
            attribs: code_attribs.build()
        };

        let data_seg = SegReg {
            sel:     0x08 | wanted_cpl as u16,
            base:    0,
            limit:   0,
            attribs: data_attribs.build()
        };

        let regs = vm.regs_mut();

        regs.cs = code_seg;
        regs.es = data_seg;
        regs.ss = data_seg;
        regs.ds = data_seg;
    }

    {
        paging.map_region(&mut vm, 0, 0, 1024 * 1024, MemoryProtection::rwx(MemoryType::Usermode));

        /*
        let memory_to_map = 1024 * 1024;

        for addr in (0..memory_to_map).step_by(4096) {
            paging.map_page(&mut vm, addr, addr);
        }
        */

        vm.regs_mut().cr3 = paging.cr3();
    }

    {
        let regs = vm.regs_mut();

        regs.cr0  |= cr0::PE | cr0::PG;
        regs.cr4  |= cr4::PAE;
        regs.efer |= efer::LMA | efer::LME;
    }

    let entry = 0x2000;

    vm.regs_mut().rip = entry;
    
    vm.mem_mut().map_memory(entry, 0x1000, Some(&[0xcc,0x0f, 0x22, 0xc0, 0x48, 0xc7, 0xc0, 0x37, 
        0x13, 0x00, 0x00, 0xcc]));

    vm.set_preemption_time(Some(Duration::from_millis(1000)));

    loop {
        let vmexit = vm.run();

        println!("VM exit: {:#X?}", vmexit);

        match vmexit {
            VmExit::Preemption       => (),
            _                        => break,
        };
    }

    //println!("{:#X?}", vm.regs());
}
