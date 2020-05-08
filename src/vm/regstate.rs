use super::regs::{Reg64, SegReg, TableReg, PendingExceptionReg, IntStateReg};

#[derive(Default, Debug, Clone)]
pub struct RegState {
    pub rax:    Reg64,
    pub rcx:    Reg64,
    pub rdx:    Reg64,
    pub rbx:    Reg64,
    pub rsp:    Reg64,
    pub rbp:    Reg64,
    pub rsi:    Reg64,
    pub rdi:    Reg64,
    pub r8:     Reg64,
    pub r9:     Reg64,
    pub r10:    Reg64,
    pub r11:    Reg64,
    pub r12:    Reg64,
    pub r13:    Reg64,
    pub r14:    Reg64,
    pub r15:    Reg64,
    pub rip:    Reg64,
    pub rflags: Reg64,

    pub es:   SegReg,
    pub cs:   SegReg,
    pub ss:   SegReg,
    pub ds:   SegReg,
    pub fs:   SegReg,
    pub gs:   SegReg,
    pub ldtr: SegReg,
    pub tr:   SegReg,

    pub idtr: TableReg,
    pub gdtr: TableReg,

    pub cr0: Reg64,
    pub cr2: Reg64,
    pub cr3: Reg64,
    pub cr4: Reg64,
    pub cr8: Reg64,

    pub dr0: Reg64,
    pub dr1: Reg64,
    pub dr2: Reg64,
    pub dr3: Reg64,
    pub dr6: Reg64,
    pub dr7: Reg64,

    pub tsc:           Reg64,
    pub efer:          Reg64,
    pub kernel_gsbase: Reg64,
    pub apic_base:     Reg64,
    pub pat:           Reg64,
    pub sysenter_es:   Reg64,
    pub sysenter_eip:  Reg64,
    pub sysenter_esp:  Reg64,
    pub star:          Reg64,
    pub lstar:         Reg64,
    pub cstar:         Reg64,
    pub sfmask:        Reg64,

    pub int_state:         IntStateReg,
    pub pending_exception: PendingExceptionReg,
}
