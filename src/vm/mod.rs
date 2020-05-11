mod misc;
mod regs;
mod regstate;
mod regstate_sync;
mod exception;
mod vmexit;
mod memory;
mod rawmem;
mod regbits;
mod whvp_bindings;

use std::mem::MaybeUninit;
use std::thread::{self, JoinHandle};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

pub use misc::{AccessType, PortSize, PendingInterruptType, SegAttribs, UnsupportedFeature};
pub use regs::{TableReg, SegReg, PendingExceptionReg, IntStateReg};
pub use regstate::RegState;
pub use exception::ExceptionVector;
pub use vmexit::VmExit;
pub use memory::Memory;
pub use regbits::{cr0, cr4, efer, xcr0};
use whvp_bindings as whv;

type ExitContext = whv::WHV_RUN_VP_EXIT_CONTEXT;

fn runner_thread(run_receiver: Receiver<usize>, exit_sender: Sender<ExitContext>) {
    while let Ok(partition) = run_receiver.recv() {
        let partition = partition as whv::WHV_PARTITION_HANDLE;

        let mut exit_context: MaybeUninit<whv::WHV_RUN_VP_EXIT_CONTEXT> = MaybeUninit::uninit();

        let result = unsafe {
            whv::WHvRunVirtualProcessor(partition, 0, exit_context.as_mut_ptr() as _,
                std::mem::size_of::<whv::WHV_RUN_VP_EXIT_CONTEXT>() as u32)
        };

        assert!(result >= 0, "Running virtual CPU failed with result {:X}.");

        let exit_context = unsafe { exit_context.assume_init() };

        exit_sender.send(exit_context).unwrap();
    }
}

pub struct Vm {
    partition:         whv::WHV_PARTITION_HANDLE,
    register_values:   Vec<whv::WHV_REGISTER_VALUE>,
    run_sender:        Option<Sender<usize>>,
    exit_receiver:     Option<Receiver<ExitContext>>,
    runner_thread:     Option<JoinHandle<()>>,
    preemption_time:   Option<Duration>,
    timeout_duration:  Duration,
    regs:              RegState,
    mem:               Memory,
    reload_regs:       bool,
    exit_instr_length: u64,
}

impl Vm {
    fn sync_to_whv(&mut self) {
        let register_names = &regstate_sync::REGSTATE_WHV_NAMES;
        assert!(self.register_values.len() == register_names.len());

        regstate_sync::sync_to_whv(&self.regs, &mut self.register_values);

        let result = unsafe {
            whv::WHvSetVirtualProcessorRegisters(self.partition, 0, register_names.as_ptr(),
                register_names.len() as u32, self.register_values.as_ptr())
        };

        assert!(result >= 0, "Syncing regstate to WHV failed with result {:X}.", result);
    }

    fn sync_from_whv(&mut self) {
        let register_names = &regstate_sync::REGSTATE_WHV_NAMES;
        assert!(self.register_values.len() == register_names.len());

        let result = unsafe {
            whv::WHvGetVirtualProcessorRegisters(self.partition, 0, register_names.as_ptr(),
                register_names.len() as u32, self.register_values.as_mut_ptr())
        };

        assert!(result >= 0, "Syncing regstate from WHV failed with result {:X}.", result);

        regstate_sync::sync_from_whv(&mut self.regs, &self.register_values);
    }

    pub fn regs(&self) -> &RegState {
        &self.regs
    }

    pub fn regs_mut(&mut self) -> &mut RegState {
        self.reload_regs = true;

        &mut self.regs
    }

    pub fn mem(&self) -> &Memory {
        &self.mem
    }

    pub fn mem_mut(&mut self) -> &mut Memory {
        &mut self.mem
    }

    pub fn new(exit_exceptions: &[ExceptionVector]) -> Self {
        let mut partition = std::ptr::null_mut();

        unsafe {
            let result = whv::WHvCreatePartition(&mut partition);
            assert!(result >= 0, "Creating WHV partition failed with result {:X}.", result);

            let mut property = MaybeUninit::<whv::WHV_PARTITION_PROPERTY>::zeroed()
                .assume_init();

            let set_property = |p: &whv::WHV_PARTITION_PROPERTY, code: whv::WHV_CAPABILITY_CODE| {
                let size = std::mem::size_of::<whv::WHV_PARTITION_PROPERTY>() as u32;
                let prop = p as *const _ as *const std::ffi::c_void;

                let result = whv::WHvSetPartitionProperty(partition, code, prop, size);
                assert!(result >= 0, "Setting partition property {:X} failed with result {:X}.",
                    code as u32, result);
            };

            property.ProcessorCount = 1;
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorCount);

            property.ExtendedVmExits.__bindgen_anon_1.set_ExceptionExit(1);
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExtendedVmExits);

            {
                let size = std::mem::size_of::<whv::WHV_PARTITION_PROPERTY>() as u32;
                let prop = &mut property as *mut _ as *mut std::ffi::c_void;
                let code = 
                    whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorFeatures;

                let result = whv::WHvGetPartitionProperty(partition, code, prop, size,
                    std::ptr::null_mut());

                assert!(result >= 0, "Getting CPU default features failed with result {:X}.",
                    result);

                let f = &mut property.ProcessorFeatures.__bindgen_anon_1;
                f.set_Sse3Support(1);
                f.set_Sse4_1Support(1);
                f.set_Sse4_2Support(1);
                f.set_Sse4aSupport(1);
                f.set_MisAlignSseSupport(1);
                f.set_Cmpxchg16bSupport(1);

                set_property(&property, code);
            }

            let mut exception_bitmap = 0;
            for exception in exit_exceptions.iter() {
                let id = exception.to_id();
                exception_bitmap |= 1 << id;
            }

            property.ExceptionExitBitmap = exception_bitmap;
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExceptionExitBitmap);
            
            let result = whv::WHvSetupPartition(partition);
            assert!(result >= 0, "Setting up WHV partition failed with result {:X}.", result);

            let result = whv::WHvCreateVirtualProcessor(partition, 0, 0);
            assert!(result >= 0, "Creating virtual CPU failed with result {:X}.", result);
        }

        let (run_sender, run_receiver)       = mpsc::channel();
        let (exit_sender, exit_receiver) = mpsc::channel();

        let runner_thread = thread::spawn(move || runner_thread(run_receiver, exit_sender));

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
            runner_thread:     Some(runner_thread),
            run_sender:        Some(run_sender),
            exit_receiver:     Some(exit_receiver),
            preemption_time:   None,
            timeout_duration:  Duration::from_millis(150),
            regs:              Default::default(),
            mem:               Memory::new(partition),
            reload_regs:       false,
            exit_instr_length: 0,
        };

        vm.sync_from_whv();

        vm
    }

    pub fn inject_exception(&mut self, vector: ExceptionVector, error_code: Option<u32>) {
        self.regs_mut().pending_exception = PendingExceptionReg::Pending {
            error_code,
            vector,
            param: 0,
        };
    }

    pub fn set_preemption_time(&mut self, preemption_time: Option<Duration>) {
        self.preemption_time = preemption_time;
    }

    pub fn exit_instruction_length(&self) -> u64 {
        self.exit_instr_length
    }

    pub fn run(&mut self) -> VmExit {
        if self.reload_regs {
            self.sync_to_whv();

            self.reload_regs = false;
        }
        
        let exit_context = if let Some(preemption_time) = self.preemption_time {
            self.run_sender.as_mut().unwrap().send(self.partition as usize).unwrap();

            let partition     = self.partition;
            let timeout       = self.timeout_duration;
            let exit_receiver = self.exit_receiver.as_mut().unwrap();

            if let Ok(ctx) = exit_receiver.recv_timeout(preemption_time) {
                ctx
            } else {
                unsafe {
                    let result = whv::WHvCancelRunVirtualProcessor(partition, 0, 0);

                    assert!(result >= 0,
                        "Canceling virtual CPU execution failed with result {:X}.", result);
                }

                exit_receiver.recv_timeout(timeout)
                    .expect("Runner thread did not respond in time")
            }
        } else {
            let mut exit_context: MaybeUninit<whv::WHV_RUN_VP_EXIT_CONTEXT> = 
                MaybeUninit::uninit();

            let result = unsafe {
                whv::WHvRunVirtualProcessor(self.partition, 0, exit_context.as_mut_ptr() as _,
                    std::mem::size_of::<whv::WHV_RUN_VP_EXIT_CONTEXT>() as u32)
            };

            assert!(result >= 0, "Running virtual CPU failed with result {:X}.");

            unsafe { exit_context.assume_init() }
        };

        self.sync_from_whv();

        self.exit_instr_length = exit_context.VpContext.InstructionLength() as u64;

        VmExit::from_run_exit_context(&exit_context)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.mem.destroy_all_mappings();

        self.run_sender.take();
        self.exit_receiver.take();
        self.runner_thread.take().unwrap().join().unwrap();

        unsafe {
            let result = whv::WHvDeleteVirtualProcessor(self.partition, 0);
            assert!(result >= 0, "Deleting virtual CPU failed with result {:X}.", result);

            let result = whv::WHvDeletePartition(self.partition);
            assert!(result >= 0, "Deleting WHV partition failed with result {:X}.", result);
        }
    }
}
