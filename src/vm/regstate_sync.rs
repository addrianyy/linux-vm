use super::whvp_bindings as whv;
use super::ExceptionVector;
use super::regs::{Reg64, SegReg, TableReg, PendingExceptionReg, IntStateReg};
use super::regstate::RegState;

trait RegSyncWhvValue {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self;
    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE);
}

impl RegSyncWhvValue for SegReg {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self {
        let value   = unsafe { &value.Segment };
        let attribs = unsafe { value.__bindgen_anon_1.Attributes };

        Self {
            base:  value.Base,
            limit: value.Limit,
            sel:   value.Selector,
            attribs,
        }
    }

    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE) {
        let value = unsafe { &mut value.Segment };

        value.Base     = self.base;
        value.Limit    = self.limit;
        value.Selector = self.sel;

        value.__bindgen_anon_1.Attributes = self.attribs;
    }
}

impl RegSyncWhvValue for TableReg {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self {
        let value = unsafe { &value.Table };

        Self {
            base:  value.Base,
            limit: value.Limit,
        }
    }

    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE) {
        let value = unsafe { &mut value.Table };

        value.Base  = self.base;
        value.Limit = self.limit;
    }
}

impl RegSyncWhvValue for Reg64 {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self {
        unsafe { value.Reg64 }
    }

    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE) {
        value.Reg64 = *self;
    }
}

impl RegSyncWhvValue for IntStateReg {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self {
        let value = unsafe { &value.InterruptState.__bindgen_anon_1 };

        Self {
            int_shadow: value.InterruptShadow() != 0,
            nmi_masked: value.NmiMasked() != 0,
        }
    }

    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE) {
        let value = unsafe { &mut value.InterruptState.__bindgen_anon_1 };

        value.set_InterruptShadow(self.int_shadow as u64);
        value.set_NmiMasked(self.nmi_masked as u64);
    }
}

impl RegSyncWhvValue for PendingExceptionReg {
    fn create_from_whv(value: &whv::WHV_REGISTER_VALUE) -> Self {
        let value = unsafe { &value.ExceptionEvent.__bindgen_anon_1 };

        if value.EventPending() == 0 {
            PendingExceptionReg::NotPending
        } else {
            assert!(value.EventType() == 
                whv::WHV_X64_PENDING_EVENT_TYPE_WHvX64PendingEventException as u32);

            let error_code = match value.DeliverErrorCode() {
                0 => None,
                _ => Some(value.ErrorCode),
            };

            let vector = ExceptionVector::from_id(value.Vector() as u8)
                .expect("Invalid exception vector.");

            PendingExceptionReg::Pending {
                error_code,
                vector,
                param: value.ExceptionParameter,
            }
        }
    }

    fn save_to_whv(&self, value: &mut whv::WHV_REGISTER_VALUE) {
        let value = unsafe { &mut value.ExceptionEvent.__bindgen_anon_1 };

        match self {
            PendingExceptionReg::NotPending => {
                value.set_EventPending(0);
            },
            PendingExceptionReg::Pending { vector, error_code, param } => {
                value.set_EventPending(1);
                value.set_EventType(
                    whv::WHV_X64_PENDING_EVENT_TYPE_WHvX64PendingEventException as u32);

                match error_code {
                    Some(code) => {
                        value.ErrorCode = *code;
                        value.set_DeliverErrorCode(1);
                    },
                    None => {
                        value.set_DeliverErrorCode(0);
                    }
                };

                value.set_Vector(vector.to_id() as u32);
                value.ExceptionParameter = *param;
            },
        }
    }
}

macro_rules! sync_regstate {
    () => {
        sync_reg!(rax);
        sync_reg!(rcx);
        sync_reg!(rdx);
        sync_reg!(rbx);
        sync_reg!(rsp);
        sync_reg!(rbp);
        sync_reg!(rsi);
        sync_reg!(rdi);
        sync_reg!(r8);
        sync_reg!(r9);
        sync_reg!(r10);
        sync_reg!(r11);
        sync_reg!(r12);
        sync_reg!(r13);
        sync_reg!(r14);
        sync_reg!(r15);
        sync_reg!(rip);
        sync_reg!(rflags);

        sync_reg!(es);
        sync_reg!(cs);
        sync_reg!(ss);
        sync_reg!(ds);
        sync_reg!(fs);
        sync_reg!(gs);
        sync_reg!(ldtr);
        sync_reg!(tr);

        sync_reg!(idtr);
        sync_reg!(gdtr);

        sync_reg!(cr0);
        sync_reg!(cr2);
        sync_reg!(cr3);
        sync_reg!(cr4);
        sync_reg!(cr8);

        sync_reg!(dr0);
        sync_reg!(dr1);
        sync_reg!(dr2);
        sync_reg!(dr3);
        sync_reg!(dr6);
        sync_reg!(dr7);

        sync_reg!(tsc);
        sync_reg!(efer);
        sync_reg!(kernel_gsbase);
        sync_reg!(apic_base);
        sync_reg!(pat);
        sync_reg!(sysenter_es);
        sync_reg!(sysenter_eip);
        sync_reg!(sysenter_esp);
        sync_reg!(star);
        sync_reg!(lstar);
        sync_reg!(cstar);
        sync_reg!(sfmask);

        sync_reg!(int_state);
        sync_reg!(pending_exception);
    }
}

pub const REGSTATE_WHV_NAMES: &[whv::WHV_REGISTER_NAME] = &[
    whv::WHV_REGISTER_NAME_WHvX64RegisterRax,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRcx,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRdx,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRbx,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRsp,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRbp,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRsi,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRdi,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR8,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR9,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR10,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR11,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR12,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR13,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR14,
    whv::WHV_REGISTER_NAME_WHvX64RegisterR15,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRip,
    whv::WHV_REGISTER_NAME_WHvX64RegisterRflags,

    whv::WHV_REGISTER_NAME_WHvX64RegisterEs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterSs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterFs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterGs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterLdtr,
    whv::WHV_REGISTER_NAME_WHvX64RegisterTr,

    whv::WHV_REGISTER_NAME_WHvX64RegisterIdtr,
    whv::WHV_REGISTER_NAME_WHvX64RegisterGdtr,

    whv::WHV_REGISTER_NAME_WHvX64RegisterCr0,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCr2,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCr3,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCr4,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCr8,

    whv::WHV_REGISTER_NAME_WHvX64RegisterDr0,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDr1,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDr2,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDr3,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDr6,
    whv::WHV_REGISTER_NAME_WHvX64RegisterDr7,

    whv::WHV_REGISTER_NAME_WHvX64RegisterTsc,
    whv::WHV_REGISTER_NAME_WHvX64RegisterEfer,
    whv::WHV_REGISTER_NAME_WHvX64RegisterKernelGsBase,
    whv::WHV_REGISTER_NAME_WHvX64RegisterApicBase,
    whv::WHV_REGISTER_NAME_WHvX64RegisterPat,
    whv::WHV_REGISTER_NAME_WHvX64RegisterSysenterCs,
    whv::WHV_REGISTER_NAME_WHvX64RegisterSysenterEip,
    whv::WHV_REGISTER_NAME_WHvX64RegisterSysenterEsp,
    whv::WHV_REGISTER_NAME_WHvX64RegisterStar,
    whv::WHV_REGISTER_NAME_WHvX64RegisterLstar,
    whv::WHV_REGISTER_NAME_WHvX64RegisterCstar,
    whv::WHV_REGISTER_NAME_WHvX64RegisterSfmask,

    whv::WHV_REGISTER_NAME_WHvRegisterInterruptState,
    whv::WHV_REGISTER_NAME_WHvRegisterPendingEvent,
];

pub fn sync_from_whv(state: &mut RegState, mut register_values: &[whv::WHV_REGISTER_VALUE]) {
    macro_rules! sync_reg {
        ($reg:tt) => {
            state.$reg = RegSyncWhvValue::create_from_whv(&register_values[0]);
            register_values = &register_values[1..];
        }
    };

    sync_regstate!();

    assert!(register_values.is_empty(), "Didn't sync every value.");
}

pub fn sync_to_whv(state: &RegState, mut register_values: &mut [whv::WHV_REGISTER_VALUE]) {
    macro_rules! sync_reg {
        ($reg:tt) => {
            &state.$reg.save_to_whv(&mut register_values[0]);
            register_values = &mut register_values[1..];
        }
    };

    sync_regstate!();

    assert!(register_values.is_empty(), "Didn't sync every value.");
}
