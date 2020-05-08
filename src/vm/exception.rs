#[derive(Debug, Copy, Clone)]
pub enum ExceptionVector {
    DivideErrorFault,
    DebugTrapOrFault,
    BreakpointTrap,
    OverflowTrap,
    BoundRangeFault,
    InvalidOpcodeFault,
    DeviceNotAvailableFault,
    DoubleFaultAbort,
    InvalidTaskStateSegmentFault,
    SegmentNotPresentFault,
    StackFault,
    GeneralProtectionFault,
    PageFault,
    FloatingPointErrorFault,
    AlignmentCheckFault,
    MachineCheckAbort,
    SimdFloatingPointFault,
}

impl ExceptionVector {
    pub(super) fn from_id(exception: u8) -> Option<Self> {
        match exception {
            0x00 => Some(ExceptionVector::DivideErrorFault),
            0x01 => Some(ExceptionVector::DebugTrapOrFault),
            0x03 => Some(ExceptionVector::BreakpointTrap),
            0x04 => Some(ExceptionVector::OverflowTrap),
            0x05 => Some(ExceptionVector::BoundRangeFault),
            0x06 => Some(ExceptionVector::InvalidOpcodeFault),
            0x07 => Some(ExceptionVector::DeviceNotAvailableFault),
            0x08 => Some(ExceptionVector::DoubleFaultAbort),
            0x0A => Some(ExceptionVector::InvalidTaskStateSegmentFault),
            0x0B => Some(ExceptionVector::SegmentNotPresentFault),
            0x0C => Some(ExceptionVector::StackFault),
            0x0D => Some(ExceptionVector::GeneralProtectionFault),
            0x0E => Some(ExceptionVector::PageFault),
            0x10 => Some(ExceptionVector::FloatingPointErrorFault),
            0x11 => Some(ExceptionVector::AlignmentCheckFault),
            0x12 => Some(ExceptionVector::MachineCheckAbort),
            0x13 => Some(ExceptionVector::SimdFloatingPointFault),
            _    => None,
        }
    }

    pub(super) fn to_id(&self) -> u8 {
        match self {
            ExceptionVector::DivideErrorFault => 0x00,
            ExceptionVector::DebugTrapOrFault => 0x01,
            ExceptionVector::BreakpointTrap => 0x03,
            ExceptionVector::OverflowTrap => 0x04,
            ExceptionVector::BoundRangeFault => 0x05,
            ExceptionVector::InvalidOpcodeFault => 0x06,
            ExceptionVector::DeviceNotAvailableFault => 0x07,
            ExceptionVector::DoubleFaultAbort => 0x08,
            ExceptionVector::InvalidTaskStateSegmentFault => 0x0A,
            ExceptionVector::SegmentNotPresentFault => 0x0B,
            ExceptionVector::StackFault => 0x0C,
            ExceptionVector::GeneralProtectionFault => 0x0D,
            ExceptionVector::PageFault => 0x0E,
            ExceptionVector::FloatingPointErrorFault => 0x10,
            ExceptionVector::AlignmentCheckFault => 0x11,
            ExceptionVector::MachineCheckAbort => 0x12,
            ExceptionVector::SimdFloatingPointFault => 0x13,
        }
    }
}
