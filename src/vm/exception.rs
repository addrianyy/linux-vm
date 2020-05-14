#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Exception {
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

impl Exception {
    pub(super) fn from_id(exception: u8) -> Option<Self> {
        match exception {
            0x00 => Some(Exception::DivideErrorFault),
            0x01 => Some(Exception::DebugTrapOrFault),
            0x03 => Some(Exception::BreakpointTrap),
            0x04 => Some(Exception::OverflowTrap),
            0x05 => Some(Exception::BoundRangeFault),
            0x06 => Some(Exception::InvalidOpcodeFault),
            0x07 => Some(Exception::DeviceNotAvailableFault),
            0x08 => Some(Exception::DoubleFaultAbort),
            0x0A => Some(Exception::InvalidTaskStateSegmentFault),
            0x0B => Some(Exception::SegmentNotPresentFault),
            0x0C => Some(Exception::StackFault),
            0x0D => Some(Exception::GeneralProtectionFault),
            0x0E => Some(Exception::PageFault),
            0x10 => Some(Exception::FloatingPointErrorFault),
            0x11 => Some(Exception::AlignmentCheckFault),
            0x12 => Some(Exception::MachineCheckAbort),
            0x13 => Some(Exception::SimdFloatingPointFault),
            _    => None,
        }
    }

    pub(super) fn to_id(&self) -> u8 {
        match self {
            Exception::DivideErrorFault => 0x00,
            Exception::DebugTrapOrFault => 0x01,
            Exception::BreakpointTrap => 0x03,
            Exception::OverflowTrap => 0x04,
            Exception::BoundRangeFault => 0x05,
            Exception::InvalidOpcodeFault => 0x06,
            Exception::DeviceNotAvailableFault => 0x07,
            Exception::DoubleFaultAbort => 0x08,
            Exception::InvalidTaskStateSegmentFault => 0x0A,
            Exception::SegmentNotPresentFault => 0x0B,
            Exception::StackFault => 0x0C,
            Exception::GeneralProtectionFault => 0x0D,
            Exception::PageFault => 0x0E,
            Exception::FloatingPointErrorFault => 0x10,
            Exception::AlignmentCheckFault => 0x11,
            Exception::MachineCheckAbort => 0x12,
            Exception::SimdFloatingPointFault => 0x13,
        }
    }
}
