use crate::vm::*;
use crate::phys_allocator::{PhysAllocator, ContinousPhysAllocator};
use crate::paging::{PagingManager, MemProt, MemAccess};
use crate::bytevec::ByteVec;
use crate::elf_loader;
use crate::errcodes as ec;
use std::fs::File;
use std::io::Write;

const STDIN_FD:  u32 = 0;
const STDOUT_FD: u32 = 1;
const STDERR_FD: u32 = 2;

const EXCEPTIONS_TO_INTERCEPT: &[ExceptionVector] = &[
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

const TARGET_CPL: u8  = 3;
const GDT_VIRT:   u64 = 0xFFFF_8000_0000_0000;

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

type VmPaging = PagingManager<ContinousPhysAllocator>;

pub struct LinuxVm {
    vm:             Vm,
    paging:         VmPaging,
    elf_base:       u64,
    elf_size:       u64,
    phys_allocator: ContinousPhysAllocator,
    cov_file:       File,
    exited:         bool,
    trap_hits:      usize,
}

impl LinuxVm {
    fn initialize_longmode(
        vm:             &mut Vm,
        paging:         &mut VmPaging,
        phys_allocator: &mut ContinousPhysAllocator,
    ) {
        let code_attribs = SegAttribs {
            seg_type:    0b1011,
            non_system:  true,
            dpl:         TARGET_CPL,
            present:     true,
            default:     false,
            granularity: false,
            long:        true,
        }.build();

        let data_attribs = SegAttribs {
            seg_type:    0b0011,
            non_system:  true,
            dpl:         TARGET_CPL,
            present:     true,
            default:     false,
            granularity: false,
            long:        false,
        }.build();

        let mut gdt = ByteVec::new();

        let _null_sel = gdt.push_u64(0);
        let code_sel  = gdt.push_u64((code_attribs as u64) << 40);
        let data_sel  = gdt.push_u64((data_attribs as u64) << 40);

        assert!(gdt.len() == 8 * 3, "GDT does not have 3 entries.");

        let gdt_aligned_size = (gdt.len() as u64 + 0xFFF) & !0xFFF;
        let gdt_phys = phys_allocator.alloc_phys(vm, gdt_aligned_size, Some(&gdt));

        paging.map_virt_region(vm, GDT_VIRT, gdt_phys,
            gdt_aligned_size, MemProt::r(MemAccess::Kernelmode));

        println!("GDT: virt 0x{:X} phys 0x{:X}.", GDT_VIRT, gdt_phys);

        vm.regs_mut().gdtr = TableReg {
            base:  GDT_VIRT,
            limit: gdt.len() as u16 - 1
        };

        let code_seg = SegReg {
            sel:     code_sel as u16 | TARGET_CPL as u16,
            base:    0,
            limit:   0,
            attribs: code_attribs,
        };

        let data_seg = SegReg {
            sel:     data_sel as u16 | TARGET_CPL as u16,
            base:    0,
            limit:   0,
            attribs: data_attribs,
        };

        let regs = vm.regs_mut();

        regs.cs = code_seg;
        regs.es = data_seg;
        regs.ss = data_seg;
        regs.ds = data_seg;
        regs.fs = data_seg;
        regs.gs = data_seg;

        regs.cr0  = cr0::PE | cr0::WP | cr0::PG;
        regs.cr4  = cr4::PAE | cr4::OSFXSR | cr4::OSXMMEXCPT | cr4::OSXSAVE;
        regs.efer = efer::LMA | efer::LME | efer::NXE;
        regs.xcr0 = xcr0::X87 | xcr0::SSE;
    }

    pub fn new(executable_path: &str) -> Self {
        let mut vm = Vm::new(EXCEPTIONS_TO_INTERCEPT);

        let mut phys_allocator = ContinousPhysAllocator::new(0, Some(1 << 30));
        let pt_allocator = ContinousPhysAllocator::new(1 << 30, None);
        let mut paging = PagingManager::new(&mut vm, pt_allocator);

        vm.regs_mut().cr3 = paging.cr3();
        
        let cpl = 3;

        Self::initialize_longmode(&mut vm, &mut paging, &mut phys_allocator);


        /*
        {
            let gdt_virt = 0xFFFF_8000_0000_0000;
            
            let mut gdt = ByteVec::new();

            let _null_sel = gdt.push_u64(0);
            let code_sel  = gdt.push_u64(make_segment(0, 0, code_attribs));
            let data_sel  = gdt.push_u64(make_segment(0, 0, data_attribs));

            assert!(gdt_contents.len() == 8 * 3);

            let gdt_aligned_size = (gdt_contents.len() as u64 + 0xFFF) & !0xFFF;
            let gdt_phys = phys_allocator.alloc_phys(&mut vm, gdt_aligned_size,
                Some(&gdt_contents));

            paging.map_virt_region(&mut vm, gdt_virt, gdt_phys, 
                gdt_aligned_size, MemProt::r(MemAccess::Kernelmode));

            println!("GDT: virt 0x{:X} phys 0x{:X}.", gdt_virt, gdt_phys);

            vm.regs_mut().gdtr = TableReg {
                base:  gdt_virt,
                limit: gdt_contents.len() as u16 - 1
            };

            let code_seg = SegReg {
                sel:     0x04 | cpl as u16,
                base:    0,
                limit:   0,
                attribs: code_attribs.build()
            };

            let data_seg = SegReg {
                sel:     0x08 | cpl as u16,
                base:    0,
                limit:   0,
                attribs: data_attribs.build()
            };

            let regs = vm.regs_mut();

            regs.cs = code_seg;
            regs.es = data_seg;
            regs.ss = data_seg;
            regs.ds = data_seg;

            regs.cr0  = cr0::PE | cr0::WP | cr0::PG;
            regs.cr4  = cr4::PAE | cr4::OSFXSR | cr4::OSXMMEXCPT | cr4::OSXSAVE;
            regs.efer = efer::LMA | efer::LME | efer::NXE;
            regs.xcr0 = xcr0::X87 | xcr0::SSE;
        }
        */

        let (elf_base, elf_size) = {
            let bytes = std::fs::read(executable_path).expect("Failed to read executable ELF.");
            let elf   = elf_loader::map_elf64(&bytes);

            assert!(elf.base & 0xFFF == 0 && elf.mapped.len() & 0xFFF == 0,
                "ELF is not page aligned.");

            let elf_virt = elf.base;
            let elf_size = elf.mapped.len() as u64;
            let elf_phys = phys_allocator.alloc_phys(&mut vm, elf_size, Some(&elf.mapped));

            for offset in (0..elf_size).step_by(0x1000) {
                let virt = elf_virt + offset;
                let phys = elf_phys + offset;

                let mut protection = MemProt::r(MemAccess::Usermode);

                for section in &elf.sections {
                    if virt >= section.start && virt < section.start + section.size {
                        protection = MemProt {
                            write:   section.writeable,
                            execute: section.executable,
                            user:    true,
                        };

                        break;
                    }
                }

                paging.map_virt_region(&mut vm, virt, phys, 0x1000, protection);
            }

            vm.regs_mut().rip = elf.entrypoint;

            (elf_virt, elf_size)
        };

        {
            let stack_size = 1024 * 1024 * 16;
            let stack_phys = phys_allocator.alloc_phys(&mut vm, stack_size, None);
            let stack_virt = 0x7FFF_FFFF_F000 - stack_size;

            paging.map_virt_region(&mut vm, stack_virt, stack_phys, 
                stack_size, MemProt::rw(MemAccess::Usermode));

            let rsp = stack_virt + stack_size - 0x1000;
            
            let mut data = Vec::new();

            let arg1_off = data.len();
            data.extend_from_slice(b"/bin/memulator\0");

            let arg2_off = data.len();
            data.extend_from_slice(b"test\0");

            let env1_off = data.len();
            data.extend_from_slice(b"_=/bin/memulator\0");

            let env2_off = data.len();
            data.extend_from_slice(b"TEST=24\0");
        
            let data_virt = stack_virt - 0x1000;
            let data_phys = phys_allocator.alloc_phys(&mut vm, 0x1000, Some(&data));

            paging.map_virt_region(&mut vm, data_virt, data_phys, 
                0x1000, MemProt::rw(MemAccess::Usermode));

            let mut stack = Vec::new();
            stack.extend_from_slice(&2u64.to_le_bytes());
            stack.extend_from_slice(&(data_virt + arg1_off as u64).to_le_bytes());
            stack.extend_from_slice(&(data_virt + arg2_off as u64).to_le_bytes());
            stack.extend_from_slice(&0u64.to_le_bytes());
            stack.extend_from_slice(&(data_virt + env1_off as u64).to_le_bytes());
            stack.extend_from_slice(&(data_virt + env2_off as u64).to_le_bytes());
            stack.extend_from_slice(&0u64.to_le_bytes());

            paging.write_virt(&mut vm, rsp, &stack);


            // argc - 8 
            // ptr to first arg
            // ptr to second arg
            // null
            // ptr to first env
            // ptr to second env
            // null

            println!("Stack: virt 0x{:X} phys 0x{:X}.", stack_virt, stack_phys);

            vm.regs_mut().rsp = rsp;
        }

        println!("RIP is 0x{:X}.", vm.regs().rip);
        println!("RSP is 0x{:X}.", vm.regs().rsp);

        println!("Enabled coverage. Trap flag set.");

        Self {
            vm,
            paging,
            elf_base,
            elf_size,
            phys_allocator,
            cov_file: File::create("coverage.txt").unwrap(),
            exited: false,
            trap_hits: 0,
        }
    }

    fn get_iovecs(&mut self, iov: u64, vlen: u32) -> Option<Vec<(u64, u64)>> {
        let mut iovecs = Vec::with_capacity(vlen as usize);

        for i in 0..vlen {
            let iovec = iov + i as u64 * 16;

            let res = (self.paging.read_virt_u64(&mut self.vm, iovec),
                       self.paging.read_virt_u64(&mut self.vm, iovec + 8));

            if let (Ok(base), Ok(size)) = res {
                iovecs.push((base, size));
            } else {
                return None;
            }
        }

        Some(iovecs)
    }

    fn sys_arch_prctl(&mut self, params: &[u64]) -> i64 {
        let code = params[0];
        let addr = params[2];

        match code {
            0x1001 => self.vm.regs_mut().gs.base = addr,
            0x1002 => self.vm.regs_mut().fs.base = addr,
            _      => panic!(),
        };

        0
    }

    fn sys_set_tid_address(&mut self, params: &[u64]) -> i64 {
        println!("WARNING: sys_set_tid_address unhandled.");

        80
    }

    fn sys_ioctl(&mut self, params: &[u64]) -> i64 {
        let fd  = params[0] as u32;
        let cmd = params[1] as u32;
        let arg = params[2];

        match fd {
            STDOUT_FD => {
                match cmd {
                    0x00005413 => { // TIOCGWINSZ
                        let result = self.paging.write_virt_u64(&mut self.vm, 
                            arg, 0x0020_0030_0080_0080);

                        if result.is_err() {
                            return -ec::EFAULT;
                        }
                    },
                    _ => {
                        panic!("Unsupported cmd {:X} to stdout.", cmd);
                    },
                }
            },
            _ => panic!("IOCTL to unsupported fd {:X}.", fd),
        }

        0
    }

    fn sys_write(&mut self, params: &[u64]) -> i64 {
        let fd    = params[0] as u32;
        let buf   = params[1];
        let count = params[2];

        match fd {
            STDOUT_FD | STDERR_FD => {
                let mut buffer = vec![0; count as usize];

                if self.paging.read_virt(&mut self.vm, buf, &mut buffer).is_ok() {
                    print!("{}", String::from_utf8_lossy(&buffer));
                    return count as i64;
                } else {
                    return -ec::EFAULT;
                }
            },
            STDIN_FD => panic!("stdin writes not supported."),
            _        => panic!("Unknown fd {:X}.", fd),
        }
    }

    fn sys_writev(&mut self, params: &[u64]) -> i64 {
        let fd     = params[0] as u32;
        let iovec  = params[1];
        let iovcnt = params[2] as u32;

        let mut total = 0;

        if let Some(iovecs) = self.get_iovecs(iovec, iovcnt) {
            for iovec in iovecs {
                let result = self.sys_write(&[fd as u64, iovec.0, iovec.1]);

                if result < 0 {
                    return result;
                }

                total += result;
            }
        } else {
            return -ec::EFAULT;
        }

        total
    }

    fn sys_exit_group(&mut self, params: &[u64]) -> i64 {
        let status = params[0];

        println!("Executable exited with status {:X}.", status);

        self.exited = true;

        0
    }

    fn handle_syscall(&mut self) {
        let (syscall_id, params) = {
            let regs       = self.vm.regs();
            let syscall_id = regs.rax & 0xFFFF_FFFF;
            
            let params = [
                regs.rdi,
                regs.rsi,
                regs.rdx,
                regs.r10,
                regs.r8,
                regs.r9,
            ];

            (syscall_id, params)
        };

        let result = match syscall_id {
            158 => self.sys_arch_prctl(&params),
            218 => self.sys_set_tid_address(&params),
            231 => self.sys_exit_group(&params),
            16  => self.sys_ioctl(&params),
            20  => self.sys_writev(&params),
            _   => panic!("Unknown syscall {} at RIP {:X}.", syscall_id, self.vm.regs().rip),
        };

        self.vm.regs_mut().rax = result as u64;
        self.vm.regs_mut().rip += 2;
    }

    pub fn run(&mut self) {
        self.vm.regs_mut().rflags |= 0x100;

        while !self.exited {
            let vmexit = self.vm.run();
            let mut handled = false;

            if let VmExit::Exception { vector: ExceptionVector::InvalidOpcodeFault, instruction, .. } 
                = &vmexit
            {
                if matches!(instruction, &[0x0F, 0x05, ..]) {
                    self.handle_syscall();
                    handled = true;
                }
            }

            if let VmExit::Exception { vector: ExceptionVector::DebugTrapOrFault, instruction, .. } 
                = &vmexit
            {
                self.cov_file.write_all(format!("{:X}\n", self.vm.regs().rip).as_bytes()).unwrap();
                self.trap_hits += 1;
                handled = true;
            }

            if !handled {
                println!("{:#X?}", self.vm.regs());
                println!("{:#X?}", vmexit);
                panic!();
            }
        }

        println!("#DB trap hit {} times.", self.trap_hits);
        println!("{:#X?}", self.vm.regs());
    }
}
