#![allow(dead_code)]

mod vm;
mod phys_allocator;
mod paging;
mod membank;

use vm::*;
use phys_allocator::ContinousPhysAllocator;
use paging::{PagingManager, MemProt, MemAccess};
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

    let page_table_allocator = ContinousPhysAllocator::new(1 << 30, None);

    let mut vm = Vm::new(&exit_exceptions);
    let mut paging = PagingManager::new(&mut vm, page_table_allocator);


    vm.mem_mut().map_phys_region(0x11111000, 0x1000, None);
    paging.map_virt_region(&mut vm, 0xFFFF_8100_0000_0000, 0x11111000, 0x1000,
        MemProt::rwx(MemAccess::Usermode));

    println!("{:X?}", paging.query_virt_addr(&vm, 0xFFFF_8100_0000_0044));


    paging.write_virt_u64(&mut vm, 0xFFFF_8100_0000_0000, 0x133788).unwrap();
    println!("{:X}", vm.mem_mut().read_phys_u64(0x11111000).unwrap());

    let backings = paging.unmap_virt_region(&mut vm, 0xFFFF_8100_0000_0000, 0x1000);
    println!("{:X?}", backings);

    //let mut paging = Paging::new(&mut vm);

    let wanted_cpl = 0;

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

        vm.mem_mut().map_phys_region(gdt_addr, 0x1000, Some(&gdt_contents));

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
        paging.map_virt_region(&mut vm, 0, 0, 1024 * 1024,
            MemProt::rwx(MemAccess::Usermode));

        vm.regs_mut().cr3 = paging.cr3();
    }

    {
        let regs = vm.regs_mut();

        regs.cr0  = cr0::PE | cr0::WP | cr0::PG;
        regs.cr4  = cr4::PAE;
        regs.efer = efer::LMA | efer::LME | efer::NXE;
    }

    let entry = 0x2000;

    vm.regs_mut().rip = entry;
    
    /*
    vm.mem_mut().map_memory(entry, 0x1000, Some(&[0xcc,0x0f, 0x22, 0xc0, 0x48, 0xc7, 0xc0, 0x37, 
        0x13, 0x00, 0x00, 0xcc]));
    */


    let code = [0x48, 0x89, 0x04, 0x25, 0x00, 0x15, 0x00, 0x00, 0xCC];
    vm.mem_mut().map_phys_region(entry, 0x1000, Some(&code));

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
