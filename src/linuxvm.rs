use crate::vm::*;
use crate::phys_allocator::{PhysAllocator, ContinousPhysAllocator};
use crate::paging::{PagingManager, MemProt, MemAccess};
use crate::bytevec::ByteVec;
use crate::elf_loader;
use crate::errcodes as ec;
use std::fs::File;
use std::io::Write;
use std::path::Path;

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

const TARGET_CPL:     u8  = 3;
const GDT_VIRT:       u64 = 0xFFFF_8000_0000_0000;
const STACK_END_VIRT: u64 = 0x7FFF_FFFF_F000;
const STACK_SIZE:     u64 = 1024 * 1024 * 16;

type VmPaging = PagingManager<ContinousPhysAllocator>;

pub struct LinuxVm {
    vm:             Vm,
    paging:         VmPaging,
    phys_allocator: ContinousPhysAllocator,
    elf_base:       u64,
    elf_size:       u64,
    stack_base:     u64,
    stack_size:     u64,
    exited:         bool,
    coverage:       Option<(File, usize)>,
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

        regs.cr3 = paging.cr3();
    }

    fn load_executable<P: AsRef<Path>>(
        executable_path: P,
        vm:              &mut Vm,
        paging:          &mut VmPaging,
        phys_allocator:  &mut ContinousPhysAllocator,
    ) -> (u64, u64) {
        let bytes = std::fs::read(executable_path).expect("Failed to read executable ELF.");
        let elf   = elf_loader::map_elf64(&bytes);

        assert!(elf.base & 0xFFF == 0 && elf.mapped.len() & 0xFFF == 0,
            "ELF is not page aligned.");

        let elf_virt = elf.base;
        let elf_size = elf.mapped.len() as u64;
        let elf_phys = phys_allocator.alloc_phys(vm, elf_size, Some(&elf.mapped));

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

            paging.map_virt_region(vm, virt, phys, 0x1000, protection);
        }

        vm.regs_mut().rip = elf.entrypoint;

        (elf_virt, elf_size)
    }

    fn initialize_stack<S1: AsRef<str>, S2: AsRef<str>>(
        args:            &[S1],
        env:             &[S2],
        vm:              &mut Vm,
        paging:          &mut VmPaging,
        phys_allocator:  &mut ContinousPhysAllocator,
    ) -> (u64, u64) {
        let mut data = ByteVec::new();

        let mut args_offsets = Vec::with_capacity(args.len());
        let mut env_offsets  = Vec::with_capacity(env.len());

        for arg in args.iter() {
            let bytes  = arg.as_ref().as_bytes();
            let offset = data.push_bytes(bytes);

            data.push_bytes(&[0]);

            args_offsets.push(offset);
        }

        for var in env.iter() {
            let bytes  = var.as_ref().as_bytes();
            let offset = data.push_bytes(bytes);

            data.push_bytes(&[0]);

            env_offsets.push(offset);
        }

        let add_size         = (3 + env.len() + args.len()) as u64 * 8;
        let add_aligned_size = (add_size + 0xFFF) & !0xFFF;

        let usable_stack_size = STACK_SIZE;
        let real_stack_size   = usable_stack_size + add_aligned_size;

        let stack_phys = phys_allocator.alloc_phys(vm, real_stack_size, None);
        let stack_virt = STACK_END_VIRT - real_stack_size;

        paging.map_virt_region(vm, stack_virt, stack_phys,
            real_stack_size, MemProt::rw(MemAccess::Usermode));

        let data_aligned_size = (data.len() as u64 + 0xFFF) & !0xFFF;
        let data_phys         = phys_allocator.alloc_phys(vm, data_aligned_size, Some(&data));
        let data_virt         = stack_virt - data_aligned_size - 0x1000;

        paging.map_virt_region(vm, data_virt, data_phys, 
            data_aligned_size, MemProt::r(MemAccess::Usermode));

        let mut ptr_data = ByteVec::with_capacity(add_size as usize);
        
        ptr_data.push_u64(args.len() as u64);
    
        for offset in args_offsets.iter() {
            ptr_data.push_u64(offset + data_virt);
        }

        ptr_data.push_u64(0);

        for offset in env_offsets.iter() {
            ptr_data.push_u64(offset + data_virt);
        }

        ptr_data.push_u64(0);

        assert!(ptr_data.len() == add_size as usize, "Predicted size was wrong.");

        let rsp = stack_virt + usable_stack_size - 0x100;

        paging.write_virt(vm, rsp, &ptr_data).unwrap();

        vm.regs_mut().rsp = rsp;

        (stack_virt, real_stack_size)
    }

    pub fn new<S1: AsRef<str>, S2: AsRef<str>, P1: AsRef<Path>, P2: AsRef<Path>>(
        executable_path: P1,
        args:            &[S1],
        env:             &[S2],
        coverage_path:   Option<P2>,
    ) -> Self {
        assert!(args.len() > 0, "Need to provide at least one cmd line argument.");
        assert!(env.len()  > 0, "Need to provide at least one env variable.");

        let mut vm = Vm::new(EXCEPTIONS_TO_INTERCEPT);

        let phys_pt_start = 1 << 30;

        let mut phys_allocator = ContinousPhysAllocator::new(0, Some(phys_pt_start));
        let mut paging = PagingManager::new(&mut vm, 
            ContinousPhysAllocator::new(phys_pt_start, None));

        Self::initialize_longmode(&mut vm, &mut paging, &mut phys_allocator);

        let (elf_base, elf_size) = Self::load_executable(executable_path, &mut vm, 
            &mut paging, &mut phys_allocator);

        let (stack_base, stack_size) = Self::initialize_stack(args, env, &mut vm,
            &mut paging, &mut phys_allocator);

        let coverage = coverage_path.map(|path| {
            let coverage_file = File::create(path).expect("Failed to open coverage file.");

            (coverage_file, 0)
        });

        if coverage.is_some() {
            const TRAP_FLAG: u64 = 0x100;

            vm.regs_mut().rflags |= TRAP_FLAG;

            println!("Enabled coverage. Trap flag set.\n");
        }

        Self {
            vm,
            paging,
            phys_allocator,
            elf_base,
            elf_size,
            stack_base,
            stack_size,
            exited: false,
            coverage,
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

    fn sys_set_tid_address(&mut self, _params: &[u64]) -> i64 {
        // TODO
        4
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

        println!("\nExecutable exited with status {:X}.", status);

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
        while !self.exited {
            let vmexit = self.vm.run();

            let mut handled = false;

            match vmexit {
                VmExit::Exception { vector, instruction, .. } => {
                    if vector == ExceptionVector::InvalidOpcodeFault && 
                        matches!(&instruction, &[0x0F, 0x05, ..]) 
                    {
                        self.handle_syscall();

                        handled = true;
                    }

                    if vector == ExceptionVector::DebugTrapOrFault {
                        if let Some(coverage) = self.coverage.as_mut() {
                            let rip = self.vm.regs().rip;

                            coverage.1 += 1;
                            coverage.0.write_all(format!("{:X}\n", rip).as_bytes())
                                .expect("Failed to write coverage info.");

                            handled = true;
                        }
                    }
                },
                VmExit::Preemption => handled = true,
                _                  => (),
            }

            if !handled {
                println!("{:#X?}", self.vm.regs());
                println!("{:#X?}", vmexit);
                panic!("Unhandled VM exit.");
            }
        }

        if let Some(coverage) = self.coverage.as_ref() {
            println!("Finished gathering coverage.");
            println!("#DB trap hit {} times.", coverage.1);
        }
    }
}
