use super::ExceptionVector;

pub type Reg64 = u64;

#[derive(Default, Debug, Copy, Clone)]
pub struct SegReg {
    pub base:    u64,
    pub limit:   u32,
    pub sel:     u16,
    pub attribs: u16,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct TableReg {
    pub base:  u64,
    pub limit: u16,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct IntStateReg {
    pub int_shadow: bool,
    pub nmi_masked: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum PendingExceptionReg {
    NotPending,
    Pending {
        error_code: Option<u32>,
        vector:     ExceptionVector,
        param:      u64,
    },
}

impl Default for PendingExceptionReg {
    fn default() -> Self {
        PendingExceptionReg::NotPending
    }
}
