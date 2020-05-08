use super::{AccessType, SegReg, PortSize, ExceptionVector, PendingInterruptType};
use super::whvp_bindings as whv;

type InstructionBytes = Vec<u8>;

#[derive(Debug, Clone)]
pub enum VmExit {
    MemoryAccess {
        instruction:  InstructionBytes,
        gpa:          u64,
        gva:          u64,
        access:       AccessType,
        gpa_unmapped: bool,
        gva_valid:    bool,
    },
    PortAccess {
        instruction: InstructionBytes,
        port:        u16,
        rax:         u64,
        rcx:         u64,
        rsi:         u64,
        rdi:         u64,
        ds:          SegReg,
        es:          SegReg,
        write:       bool,
        string:      bool,
        rep:         bool,
        size:        PortSize,
    },
    MsrAccess {
        msr:   u32,
        rax:   u64,
        rdx:   u64,
        write: bool,
    },
    Cpuid {
        rax:     u64,
        rcx:     u64,
        rdx:     u64,
        rbx:     u64,
        def_rax: u64,
        def_rcx: u64,
        def_rdx: u64,
        def_rbx: u64,
    },
    Exception {
        instruction:      InstructionBytes,
        exception_vector: ExceptionVector,
        error_code:       Option<u32>,
        software:         bool,
        param:            u64,
    },
    InterruptWindow {
        deliverable_type: PendingInterruptType,
    },
    ApicEoi {
        vector: u32,
    },
    Preemption,
    UnrecoverableException,
    Halt,
}

impl VmExit {
    pub(super) fn from_run_exit_context(exit_context: &whv::WHV_RUN_VP_EXIT_CONTEXT) -> VmExit {
        match exit_context.ExitReason {
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.MemoryAccess };

                let instruction = info.InstructionBytes
                    [0..info.InstructionByteCount as usize].to_owned();

                let access_info = unsafe { info.AccessInfo.AsUINT32 };

                let access = match access_info & 3 {
                    0 => AccessType::Read,
                    1 => AccessType::Write,
                    2 => AccessType::Execute,
                    _ => unreachable!(),
                };

                VmExit::MemoryAccess {
                    instruction,
                    gpa: info.Gpa,
                    gva: info.Gva,
                    access,
                    gpa_unmapped: (access_info >> 2) & 1 != 0,
                    gva_valid:    (access_info >> 3) & 1 != 0,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.IoPortAccess };

                let instruction = info.InstructionBytes
                    [0..info.InstructionByteCount as usize].to_owned();

                let access_info = unsafe { info.AccessInfo.AsUINT32 };

                let port_size_bytes = (access_info >> 1) & 7;
                let port_size = match port_size_bytes {
                    1 => PortSize::Byte,
                    2 => PortSize::Word,
                    4 => PortSize::Dword,
                    _ => panic!("Unexpected port access size {}.", port_size_bytes),
                };

                let get_segreg = |seg: &whv::WHV_X64_SEGMENT_REGISTER| {
                    let attribs = unsafe { seg.__bindgen_anon_1.Attributes };

                    SegReg {
                        base:  seg.Base,
                        limit: seg.Limit,
                        sel:   seg.Selector,
                        attribs,
                    }
                };

                VmExit::PortAccess {
                    instruction,
                    port:   info.PortNumber,
                    rax:    info.Rax,
                    rcx:    info.Rcx,
                    rsi:    info.Rsi,
                    rdi:    info.Rdi,
                    ds:     get_segreg(&info.Ds),
                    es:     get_segreg(&info.Es),
                    write:  access_info & 1 != 0,
                    string: (access_info >> 4) & 1 != 0,
                    rep:    (access_info >> 5) & 1 != 0,
                    size:   port_size,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.MsrAccess };

                let write = unsafe { info.AccessInfo.AsUINT32 } & 1 != 0;

                VmExit::MsrAccess {
                    msr: info.MsrNumber,
                    rax: info.Rax,
                    rdx: info.Rdx,
                    write,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid => {
                let info = unsafe { &exit_context.__bindgen_anon_1.CpuidAccess };

                VmExit::Cpuid {
                    rax:     info.Rax,
                    rdx:     info.Rdx,
                    rcx:     info.Rcx,
                    rbx:     info.Rbx,
                    def_rax: info.DefaultResultRax,
                    def_rdx: info.DefaultResultRdx,
                    def_rcx: info.DefaultResultRcx,
                    def_rbx: info.DefaultResultRbx,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException => {
                let info = unsafe { &exit_context.__bindgen_anon_1.VpException };

                let instruction = info.InstructionBytes
                    [0..info.InstructionByteCount as usize].to_owned();

                let exception_vector = ExceptionVector::from_id(info.ExceptionType)
                    .expect("Unknown exception type.");

                let exception_info = unsafe { info.ExceptionInfo.AsUINT32 };

                let error_code = match exception_info & 1 {
                    0 => None,
                    1 => Some(info.ErrorCode),
                    _ => unreachable!(),
                };

                VmExit::Exception {
                    instruction,
                    exception_vector,
                    error_code,
                    software: (exception_info >> 1) & 1 != 0,
                    param:    info.ExceptionParameter,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64InterruptWindow => {
                let info = unsafe { &exit_context.__bindgen_anon_1.InterruptWindow };

                let deliverable_type = match info.DeliverableType {
                    0 => PendingInterruptType::Interrupt,
                    2 => PendingInterruptType::Nmi,
                    3 => PendingInterruptType::Exception,
                    _ => panic!("Unknown pending interrupt type {}.", info.DeliverableType),
                };

                VmExit::InterruptWindow {
                    deliverable_type,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64ApicEoi => {
                let info = unsafe { &exit_context.__bindgen_anon_1.ApicEoi };

                VmExit::ApicEoi {
                    vector: info.InterruptVector,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled => {
                let info = unsafe { &exit_context.__bindgen_anon_1.CancelReason };
                let reason = info.CancelReason;

                assert!(reason == 0, "Unknown execution cancel reason {}.", reason);

                VmExit::Preemption
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException => {
                VmExit::UnrecoverableException
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Halt => {
                VmExit::Halt
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature => {
                let info = unsafe { &exit_context.__bindgen_anon_1.UnsupportedFeature };

                let feature_code = info.FeatureCode;
                let param = info.FeatureParameter;

                match info.FeatureCode {
                    1 => panic!("Unsupported intercept with parameter {}.", param),
                    2 => panic!("Unsupported task switch with TSS with parameter {}.", param),
                    _ => panic!("Unknown unsupported feature {} with parameter {}.",
                        feature_code, param),
                };
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone => {
                panic!("Processor exited without any reason.");
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue => {
                panic!("Processor has invalid register state.");
            },
            _ => panic!("Unknown exit reason {}.", exit_context.ExitReason)
        }
    }
}
