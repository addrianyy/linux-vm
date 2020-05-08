#[derive(Debug, Copy, Clone)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Copy, Clone)]
pub enum PortSize {
    Byte,
    Word,
    Dword,
}

#[derive(Debug, Copy, Clone)]
pub enum PendingInterruptType {
    Interrupt,
    Nmi,
    Exception,
}
