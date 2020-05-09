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

#[derive(Debug, Copy, Clone)]
pub enum UnsupportedFeature {
    Intercept,
    TaskSwitchTss,
}

#[derive(Debug, Copy, Clone)]
pub struct SegAttribs {
    pub seg_type:    u8,
    pub non_system:  bool,
    pub dpl:         u8,
    pub present:     bool,
    pub default:     bool,
    pub granularity: bool,
    pub long:        bool,
}

impl SegAttribs {
    pub fn build(&self) -> u16 {
        assert!(self.seg_type <= 0b1111, "Invalid segment type.");
        assert!(self.dpl      <= 0b11, "Invalid DPL.");

        (self.seg_type         as u16)        |
            ((self.non_system  as u16) << 4)  |
            ((self.dpl         as u16) << 5)  | 
            ((self.present     as u16) << 7)  | 
            ((self.long        as u16) << 13) | 
            ((self.default     as u16) << 14) | 
            ((self.granularity as u16) << 15) 
    }
}
