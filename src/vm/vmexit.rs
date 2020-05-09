use super::{AccessType, SegReg, PortSize, ExceptionVector, 
            PendingInterruptType, UnsupportedFeature};

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
        instruction: InstructionBytes,
        vector:      ExceptionVector,
        error_code:  Option<u32>,
        software:    bool,
        param:       u64,
    },
    InterruptWindow {
        deliverable_type: PendingInterruptType,
    },
    ApicEoi {
        vector: u32,
    },
    UnsupportedFeature {
        feature: UnsupportedFeature,
        param:   u64,
    },
    UnrecoverableException,
    InvalidState,
    Preemption,
    Halt,
}

impl VmExit {
    pub(super) fn from_run_exit_context(exit_context: &whv::WHV_RUN_VP_EXIT_CONTEXT) -> VmExit {
        let instruction_length = exit_context.VpContext.InstructionLength() as usize;

        match exit_context.ExitReason {
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone => {
                panic!("Processor exited without any reason.");
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.MemoryAccess };

                let ilen = std::cmp::min(instruction_length, info.InstructionByteCount as usize);
                let instruction = info.InstructionBytes[0..ilen].to_owned();

                let access_info = unsafe { info.AccessInfo.__bindgen_anon_1 };

                let access = match access_info.AccessType() {
                    0 => AccessType::Read,
                    1 => AccessType::Write,
                    2 => AccessType::Execute,
                    _ => panic!("Unknown memory access type {}.", access_info.AccessType()),
                };

                VmExit::MemoryAccess {
                    instruction,
                    gpa: info.Gpa,
                    gva: info.Gva,
                    access,
                    gpa_unmapped: access_info.GpaUnmapped() != 0,
                    gva_valid:    access_info.GvaValid() != 0,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.IoPortAccess };

                let ilen = std::cmp::min(instruction_length, info.InstructionByteCount as usize);
                let instruction = info.InstructionBytes[0..ilen].to_owned();

                let access_info = unsafe { info.AccessInfo.__bindgen_anon_1 };

                let port_size = match access_info.AccessSize() {
                    1 => PortSize::Byte,
                    2 => PortSize::Word,
                    4 => PortSize::Dword,
                    _ => panic!("Unknown port access size {}.", access_info.AccessSize()),
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
                    write:  access_info.IsWrite() != 0,
                    string: access_info.StringOp() != 0,
                    rep:    access_info.RepPrefix() != 0,
                    size:   port_size,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess => {
                let info = unsafe { &exit_context.__bindgen_anon_1.MsrAccess };

                let access_info = unsafe { info.AccessInfo.__bindgen_anon_1 };

                VmExit::MsrAccess {
                    msr:   info.MsrNumber,
                    rax:   info.Rax,
                    rdx:   info.Rdx,
                    write: access_info.IsWrite() != 0,
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

                let ilen = std::cmp::min(instruction_length, info.InstructionByteCount as usize);
                let instruction = info.InstructionBytes[0..ilen].to_owned();

                let vector = ExceptionVector::from_id(info.ExceptionType)
                    .expect("Unknown exception type.");

                let exception_info = unsafe { info.ExceptionInfo.__bindgen_anon_1 };

                let error_code = match exception_info.ErrorCodeValid() {
                    0 => None,
                    _ => Some(info.ErrorCode),
                };

                VmExit::Exception {
                    instruction,
                    vector,
                    error_code,
                    software: exception_info.SoftwareException() != 0,
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
                let info   = unsafe { &exit_context.__bindgen_anon_1.CancelReason };
                let reason = info.CancelReason;

                assert!(reason == 0, "Unknown execution cancel reason {}.", reason);

                VmExit::Preemption
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature => {
                let info = unsafe { &exit_context.__bindgen_anon_1.UnsupportedFeature };

                let feature = match info.FeatureCode {
                    1 => UnsupportedFeature::Intercept,
                    2 => UnsupportedFeature::TaskSwitchTss,
                    _ => panic!("Unknown unsupported feature {}.", info.FeatureParameter),
                };

                VmExit::UnsupportedFeature {
                    feature,
                    param: info.FeatureParameter,
                }
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException => {
                VmExit::UnrecoverableException
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue => {
                VmExit::InvalidState
            },
            whv::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Halt => {
                VmExit::Halt
            },
            _ => panic!("Unknown exit reason {}.", exit_context.ExitReason)
        }
    }
}
