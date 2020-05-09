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

pub use misc::{AccessType, PortSize, PendingInterruptType, SegAttribs};
pub use regs::{TableReg, SegReg, PendingExceptionReg, IntStateReg};
pub use regstate::RegState;
pub use exception::ExceptionVector;
pub use vmexit::VmExit;
pub use memory::Memory;
pub use regbits::{cr0, cr4, efer};
use whvp_bindings as whv;

macro_rules! assert_hresult {
    ($hr:expr) => { assert!($hr >= 0); }
}

type ExitContext = whv::WHV_RUN_VP_EXIT_CONTEXT;

fn runner_thread(run_receiver: Receiver<usize>, vmexit_sender: Sender<ExitContext>) {
    while let Ok(partition) = run_receiver.recv() {
        let partition = partition as whv::WHV_PARTITION_HANDLE;

        let mut exit_context: MaybeUninit<whv::WHV_RUN_VP_EXIT_CONTEXT> = MaybeUninit::uninit();

        let success = unsafe {
            whv::WHvRunVirtualProcessor(partition, 0, exit_context.as_mut_ptr() as _,
                std::mem::size_of::<whv::WHV_RUN_VP_EXIT_CONTEXT>() as u32)
        };

        assert_hresult!(success);

        let exit_context = unsafe { exit_context.assume_init() };

        vmexit_sender.send(exit_context).unwrap();
    }
}

pub struct Vm {
    partition:        whv::WHV_PARTITION_HANDLE,
    register_values:  Vec<whv::WHV_REGISTER_VALUE>,
    run_sender:       Option<Sender<usize>>,
    vmexit_receiver:  Option<Receiver<ExitContext>>,
    runner_thread:    Option<JoinHandle<()>>,
    preemption_time:  Option<Duration>,
    timeout_duration: Duration,
    regs:             RegState,
    mem:              Memory,
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

    pub fn regs(&self) -> &RegState {
        &self.regs
    }

    pub fn regs_mut(&mut self) -> &mut RegState {
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
            assert_hresult!(whv::WHvCreatePartition(&mut partition));

            let mut property = MaybeUninit::<whv::WHV_PARTITION_PROPERTY>::zeroed()
                .assume_init();

            let set_property = |p: &whv::WHV_PARTITION_PROPERTY, code: whv::WHV_CAPABILITY_CODE| {
                let size = std::mem::size_of::<whv::WHV_PARTITION_PROPERTY>() as u32;

                assert_hresult!(whv::WHvSetPartitionProperty(partition, code,
                    p as *const _ as _, size));
            };

            property.ProcessorCount = 1;
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorCount);

            property.ExtendedVmExits.__bindgen_anon_1.set_ExceptionExit(1);
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExtendedVmExits);

            let mut exception_bitmap = 0;
            for exception in exit_exceptions.iter() {
                let id = exception.to_id();
                exception_bitmap |= 1 << id;
            }

            property.ExceptionExitBitmap = exception_bitmap;
            set_property(&property,
                whv::WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExceptionExitBitmap);
            
            assert_hresult!(whv::WHvSetupPartition(partition));
            assert_hresult!(whv::WHvCreateVirtualProcessor(partition, 0, 0));
        }

        let (run_sender, run_receiver)       = mpsc::channel();
        let (vmexit_sender, vmexit_receiver) = mpsc::channel();

        let runner_thread = thread::spawn(move || runner_thread(run_receiver, vmexit_sender));

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
            runner_thread:    Some(runner_thread),
            run_sender:       Some(run_sender),
            vmexit_receiver:  Some(vmexit_receiver),
            preemption_time:  None,
            timeout_duration: Duration::from_millis(150),
            regs:             Default::default(),
            mem:              Memory::new(partition),
        };

        vm.sync_from_whv();

        vm
    }

    pub fn inject_exception(&mut self, vector: ExceptionVector, error_code: Option<u32>) {
        self.regs.pending_exception = PendingExceptionReg::Pending {
            error_code,
            vector,
            param: 0,
        };
    }

    pub fn set_preemption_time(&mut self, preemption_time: Option<Duration>) {
        self.preemption_time = preemption_time;
    }

    pub fn run(&mut self) -> VmExit {
        self.sync_to_whv();
        
        self.run_sender.as_mut().unwrap().send(self.partition as usize).unwrap();

        let partition       = self.partition;
        let timeout         = self.timeout_duration;
        let preemption_time = self.preemption_time;
        let vmexit_receiver = self.vmexit_receiver.as_mut().unwrap();

        let vmexit = if let Some(preemption_time) = preemption_time {
            if let Ok(vmexit) = vmexit_receiver.recv_timeout(preemption_time) {
                vmexit
            } else {
                unsafe {
                    assert_hresult!(whv::WHvCancelRunVirtualProcessor(partition, 0, 0));
                }

                vmexit_receiver.recv_timeout(timeout)
                    .expect("Runner thread did not respond in time")
            }
        } else {
            vmexit_receiver.recv().unwrap()
        };

        self.sync_from_whv();

        VmExit::from_run_exit_context(&vmexit)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.run_sender.take();
        self.vmexit_receiver.take();
        self.runner_thread.take().unwrap().join().unwrap();

        unsafe {
            assert_hresult!(whv::WHvDeleteVirtualProcessor(self.partition, 0));
            assert_hresult!(whv::WHvDeletePartition(self.partition));
        }
    }
}
