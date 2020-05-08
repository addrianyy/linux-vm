mod misc;
mod regs;
mod regstate;
mod regstate_sync;
mod exception;
mod vmexit;
mod memory;
mod rawmem;
mod whvp_bindings;

use std::mem::MaybeUninit;

pub use misc::{AccessType, PortSize, PendingInterruptType};
pub use regs::{TableReg, SegReg, PendingExceptionReg, IntStateReg};
pub use regstate::RegState;
pub use exception::ExceptionVector;
pub use vmexit::VmExit;
pub use memory::Memory;
use whvp_bindings as whv;

macro_rules! assert_hresult {
    ($hr:expr) => { assert!($hr >= 0); }
}

pub struct Vm {
    partition:       whv::WHV_PARTITION_HANDLE,
    register_values: Vec<whv::WHV_REGISTER_VALUE>,
    pub regs:        RegState,
    pub mem:         Memory,
}

impl Vm {
    fn sync_to_whv(&mut self) {
        let register_names = &regstate_sync::REGSTATE_WHV_NAMES;
        assert!(self.register_values.len() == register_names.len());

        regstate_sync::sync_to_whv(&self.regs, &mut self.register_values);

        let success = unsafe {
            whv::WHvSetVirtualProcessorRegisters(self.partition, 0, register_names.as_ptr(),
                register_names.len() as u32, self.register_values.as_ptr())
        };

        assert_hresult!(success);
    }

    fn sync_from_whv(&mut self) {
        let register_names = &regstate_sync::REGSTATE_WHV_NAMES;
        assert!(self.register_values.len() == register_names.len());

        let success = unsafe {
            whv::WHvGetVirtualProcessorRegisters(self.partition, 0, register_names.as_ptr(),
                register_names.len() as u32, self.register_values.as_mut_ptr())
        };

        assert_hresult!(success);

        regstate_sync::sync_from_whv(&mut self.regs, &self.register_values);
    }

    pub fn new() -> Self {
        let mut partition = std::ptr::null_mut();

        unsafe {
            assert_hresult!(whv::WHvCreatePartition(&mut partition));

            let cpu_count: u32 = 1;
            let cpu_count_code =
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorCount;

            let success = whv::WHvSetPartitionProperty(partition, cpu_count_code,
                &cpu_count as *const u32 as _, std::mem::size_of::<u32>() as u32);

            assert_hresult!(success);

            assert_hresult!(whv::WHvSetupPartition(partition));
            assert_hresult!(whv::WHvCreateVirtualProcessor(partition, 0, 0));
        }

        let register_count = regstate_sync::REGSTATE_WHV_NAMES.len();
        let mut register_values = Vec::with_capacity(register_count);

        for _ in 0..register_count {
            let zeroed_register_value = unsafe {
                MaybeUninit::<whv::WHV_REGISTER_VALUE>::zeroed().assume_init()
            };

            register_values.push(zeroed_register_value);
        }

        let mut vm = Self {
            partition,
            register_values,
            regs: Default::default(),
            mem:  Memory::new(partition),
        };

        vm.sync_from_whv();

        vm
    }

    pub fn run(&mut self) -> VmExit {
        self.sync_to_whv();

        let mut exit_context: MaybeUninit<whv::WHV_RUN_VP_EXIT_CONTEXT> = MaybeUninit::uninit();

        let success = unsafe {
            whv::WHvRunVirtualProcessor(self.partition, 0, exit_context.as_mut_ptr() as _,
                std::mem::size_of::<whv::WHV_RUN_VP_EXIT_CONTEXT>() as u32)
        };

        assert_hresult!(success);

        self.sync_from_whv();
        
        let exit_context = unsafe { exit_context.assume_init() };

        VmExit::from_run_exit_context(&exit_context)
    }
}
