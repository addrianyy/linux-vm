mod elf_loader;
mod errcodes;
mod errconv;
mod lxstate;
mod lxfile;
mod lxsyscall;
mod lxrealfile;
mod lxstd;
mod usermem;
mod coverage;
mod syscall_stats;

use crate::vm::*;
use crate::mm::phys_allocator::{PhysAllocator, ContinousPhysAllocator};
use crate::mm::paging::{PagingManager, MemProt, MemAccess};
use crate::bytevec::ByteVec;
use lxstate::LinuxState;
use lxsyscall::LinuxSyscall;
use coverage::Coverage;
use syscall_stats::SyscallStats;

const EXCEPTIONS_TO_INTERCEPT: &[Exception] = &[
    Exception::DivideErrorFault,
    Exception::DebugTrapOrFault,
    Exception::BreakpointTrap,
    Exception::OverflowTrap,
    Exception::BoundRangeFault,
    Exception::InvalidOpcodeFault,
    Exception::DeviceNotAvailableFault,
    Exception::DoubleFaultAbort,
    Exception::InvalidTaskStateSegmentFault,
    Exception::SegmentNotPresentFault,
    Exception::StackFault,
    Exception::GeneralProtectionFault,
    Exception::PageFault,
    Exception::FloatingPointErrorFault,
    Exception::AlignmentCheckFault,
    Exception::MachineCheckAbort,
    Exception::SimdFloatingPointFault,
];

const PROCESS_ID: u32 = 4;
const THREAD_ID:  u32 = 4;

const TARGET_CPL:     u8  = 3;
const GDT_VIRT:       u64 = 0xFFFF_8000_0000_0000;
const STACK_END_VIRT: u64 = 0x7FFF_FFFF_F000;
const STACK_SIZE:     u64 = 1024 * 1024 * 16;

type VmPaging = PagingManager<ContinousPhysAllocator>;

pub struct LinuxVm {
    vm:             Vm,
    paging:         VmPaging,
    phys_allocator: ContinousPhysAllocator,
    coverage:       Option<Coverage>,
    syscall_stats:  Option<SyscallStats>,
    state:          LinuxState,
}

impl LinuxVm {
    /// Prepare guest to run 64 bit code in usermode.
    fn initialize_longmode(
        vm:             &mut Vm,
        paging:         &mut VmPaging,
        phys_allocator: &mut ContinousPhysAllocator,
    ) {
        // Create code and data segment attributes. DPL will be equal to `TARGET_CPL`.
        // Accessed bit must be set because we are manually setting descriptor caches.
        // Granularity bit is not set because limit is ignored anyway.

        // Read, execute, accessed. Long mode is enabled so default needs to be disabled.
        let code_attribs = SegAttribs {
            seg_type:    0b1011,
            non_system:  true,
            dpl:         TARGET_CPL,
            present:     true,
            default:     false,
            granularity: false,
            long:        true,
        }.build();

        // Read, write, accessed.
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

        // Create 64 bit GDT with 3 entries containing usermode code and data segment.
        // Null segment is required by x86. Only attributes are set because base and limit
        // are ignored in long mode.
        let _null_sel = gdt.push_u64(0);
        let code_sel  = gdt.push_u64((code_attribs as u64) << 40);
        let data_sel  = gdt.push_u64((data_attribs as u64) << 40);

        assert!(gdt.len() == 8 * 3, "GDT does not have 3 entries.");

        // Allocate GDT and map it to `GDT_VIRT` virtual address as read-only.
        let gdt_aligned_size = (gdt.len() as u64 + 0xFFF) & !0xFFF;
        let gdt_phys = phys_allocator.alloc_phys(vm, gdt_aligned_size, Some(&gdt));

        paging.map_virt_region(vm, GDT_VIRT, gdt_phys,
            gdt_aligned_size, MemProt::r(MemAccess::Kernelmode));

        // Load newly created GDT.
        vm.regs_mut().gdtr = TableReg {
            base:  GDT_VIRT,
            limit: gdt.len() as u16 - 1,
        };

        // Load empty IDT. All exceptions will be catched and handled by the hypervisor.
        vm.regs_mut().idtr = TableReg {
            base:  0,
            limit: 0,
        };

        // Create code and data segments with appropriate attributes. Base and limit
        // are 0 because they are ignored in long mode and we are using paging anyway.
        // RPL == DPL == TARGET_CPL

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

        // Load all newly created segments.
        regs.cs = code_seg;
        regs.es = data_seg;
        regs.ss = data_seg;
        regs.ds = data_seg;
        regs.fs = data_seg;
        regs.gs = data_seg;

        // Enable protected mode and paging (both required by long mode). Enable write protect
        // to ensure that read-only memory cannot be written.
        regs.cr0  = cr0::PE | cr0::WP | cr0::PG | cr0::MP;

        // Enable Physical Address Extension (required by long mode). Also enable some
        // things to make SSE work properly.
        regs.cr4  = cr4::PAE | cr4::OSFXSR | cr4::OSXMMEXCPT | cr4::OSXSAVE;

        // Enable long mode and activate it. Enable non-execute bit to ensure that
        // data cannot be executed.
        // Syscall enable is off because we need to manually handle syscalls by catching #UD.
        regs.efer = efer::LMA | efer::LME | efer::NXE;

        // Enable SSE and X87 FPU.
        regs.xcr0 = xcr0::X87 | xcr0::SSE;

        // Load physical address of PML4 allocated by paging manager.
        regs.cr3 = paging.cr3();
    }

    /// Load and map ELF executable into guest and prepare it for running.
    fn load_executable(
        executable_path: &str,
        vm:              &mut Vm,
        paging:          &mut VmPaging,
        phys_allocator:  &mut ContinousPhysAllocator,
    ) -> (u64, u64) {
        // Load and parse 64-bit ELF executable.
        let bytes = std::fs::read(executable_path).expect("Failed to read executable ELF.");
        let elf   = elf_loader::map_elf64(&bytes);

        // Ensure that both base address and mapped image size are page aligned.
        assert!(elf.base & 0xFFF == 0 && elf.mapped.len() & 0xFFF == 0,
            "ELF is not page aligned.");

        let elf_virt = elf.base;
        let elf_size = elf.mapped.len() as u64;

        // Allocate physical region containing ELF file.
        let elf_phys = phys_allocator.alloc_phys(vm, elf_size, Some(&elf.mapped));

        // Go through every page in ELF image to map it in virtual memory.
        for offset in (0..elf_size).step_by(0x1000) {
            let virt = elf_virt + offset;
            let phys = elf_phys + offset;

            // If page does not have protection we dafult it to read-only.
            let mut protection = MemProt::r(MemAccess::Usermode);

            // Find segment protection for given page.
            for segment in &elf.segments {
                if virt >= segment.start && virt < segment.start + segment.size {
                    // Code will be executing in usermode so user bit needs to be always set.
                    protection = MemProt {
                        write:   segment.writeable,
                        execute: segment.executable,
                        user:    true,
                    };

                    break;
                }
            }

            // Map page of ELF executable with appropriate protection.
            paging.map_virt_region(vm, virt, phys, 0x1000, protection);
        }

        // Make guest execute code from entrypoint of ELF.
        vm.regs_mut().rip = elf.entrypoint;

        (elf_virt, elf_size)
    }

    /// Create and initialize guest stack containing command line arguments `args` and
    /// enviromental variables `env` used by libc.
    fn initialize_stack<S1: AsRef<str>, S2: AsRef<str>>(
        args:            &[S1],
        env:             &[S2],
        vm:              &mut Vm,
        paging:          &mut VmPaging,
        phys_allocator:  &mut ContinousPhysAllocator,
    ) -> (u64, u64, u64, u64) {
        // Alocate data containing all strings and setup stack layout to contain pointers to them.
        // + 0   argc
        // + 8   ptr to arg 1
        // + 16  ptr to arg 2
        // + 24  null ptr
        // + 32  ptr to env 1
        // + 40  ptr to env 2
        // + 48  null ptr

        // Buffer to hold all strings from `args` and `env`.
        let mut data = ByteVec::new();

        // Offsets from `data` to all entries in `args` and `env`. Required to setup stack
        // containing pointers to all these C strings.
        let mut args_offsets = Vec::with_capacity(args.len());
        let mut env_offsets  = Vec::with_capacity(env.len());

        // Allocate all command line arguments in `data`.
        for arg in args.iter() {
            let bytes  = arg.as_ref().as_bytes();
            let offset = data.push_bytes(bytes);

            // Push null terminator.
            data.push_bytes(&[0]);

            args_offsets.push(offset);
        }

        // Allocate all enviromental variables in `data`.
        for var in env.iter() {
            let bytes  = var.as_ref().as_bytes();
            let offset = data.push_bytes(bytes);

            // Push null terminator.
            data.push_bytes(&[0]);

            env_offsets.push(offset);
        }

        // Calculate additional size on stack required to hold argc, argv and envp.
        // We need to store all enviromental variable pointers, command line pointers
        // and argc, null separator between argv and envp, null separator at the end of envp.
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

        (stack_virt, real_stack_size, data_virt, data_aligned_size)
    }

    pub fn new<S1: AsRef<str>, S2: AsRef<str>>(
        executable_path: &str,
        args:            &[S1],
        env:             &[S2],
        coverage_path:   Option<&str>,
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

        let (stack_base, _stack_size, args_base, _args_size) = Self::initialize_stack(args, env,
            &mut vm, &mut paging, &mut phys_allocator);

        let coverage = coverage_path.map(|path| Coverage::new(path));

        if coverage.is_some() {
            const TRAP_FLAG: u64 = 0x100;

            vm.regs_mut().rflags |= TRAP_FLAG;

            println!("Enabled code coverage.\n");
        }

        let (heap_base, heap_size) = {
            let elf_end = elf_base + elf_size;

            assert!(elf_base > 0, "ELF on null page.");
            assert!(elf_end < stack_base, "ELF on higher address than stack.");
            assert!(elf_end < args_base, "ELF on higher address than args.");

            let gb = 1024 * 1024 * 1024;

            let gap_start = elf_end;
            let gap_end   = std::cmp::min(stack_base, args_base);

            let padding    = 10 * gb;
            let heap_start = gap_start + padding;
            let heap_size  = gap_end - gap_start - padding * 2;

            assert!(heap_size >= 10 * gb, "Heap size is less than 10GB.");

            (heap_start, heap_size)
        };

        let mut lx_state = LinuxState::new(PROCESS_ID, THREAD_ID, heap_base, heap_size);

        const STDIN_FD:  u32 = 0;
        const STDOUT_FD: u32 = 1;
        const STDERR_FD: u32 = 2;

        lx_state.create_file_at_fd(STDIN_FD,  lxstd::LinuxStdin::new());
        lx_state.create_file_at_fd(STDOUT_FD, lxstd::LinuxStdout::new(false));
        lx_state.create_file_at_fd(STDERR_FD, lxstd::LinuxStdout::new(true));

        Self {
            vm,
            paging,
            phys_allocator,
            coverage,
            state:         lx_state,
            syscall_stats: Some(SyscallStats::new()),
        }
    }

    fn report_coverage(&mut self, rip: u64) -> bool {
        if let Some(coverage) = self.coverage.as_mut() {
            coverage.report(rip);

            return true;
        }

        false
    }

    pub fn run(&mut self) {
        // Run till `exit` or `exit_group` syscall.
        while !self.state.exited() {
            let vmexit = self.vm.run();

            let mut handled = false;

            match vmexit {
                VmExit::Exception { vector, instruction, .. } => {
                    // If #UD was caused by `syscall` instruction we need to
                    // emulate it appropriately.
                    if vector == Exception::InvalidOpcodeFault &&
                        matches!(&instruction, &[0x0F, 0x05, ..])
                    {
                        let syscall_id = self.vm.regs().rax as u32;

                        let result = LinuxSyscall::handle(
                            &mut self.vm,
                            &mut self.paging,
                            &mut self.phys_allocator,
                            &mut self.state,
                        );

                        if let Some(syscall_stats) = self.syscall_stats.as_mut() {
                            syscall_stats.report(syscall_id);
                        }

                        let regs = self.vm.regs_mut();

                        regs.rax = result as u64;

                        // Skip faulting instruction.
                        regs.rip += 2;

                        // #DB trap is used to gather code coverage if enabled.
                        // We are emulating `syscall` so trap at the end of this instruction
                        // will not be delivered. To fix this we need to maually report
                        // code coverage on succeeding instruction.

                        let rip = regs.rip;

                        if !self.state.exited() {
                            self.report_coverage(rip);
                        }

                        handled = true;
                    }

                    // #DB trap should be caused by RFLAGS.TF and is used to gather
                    // code coverage.
                    if vector == Exception::DebugTrapOrFault {
                        handled = self.report_coverage(self.vm.regs().rip);
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
            println!("Gathered {} unique coverage entries.", coverage.entries());
        }

        if let Some(syscall_stats) = self.syscall_stats.as_ref() {
            println!();

            syscall_stats.show();
        }
    }
}
