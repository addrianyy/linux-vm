pub mod cr0 {
    pub const PE: u64 = 1;
    pub const MP: u64 = 1 << 1;
    pub const WP: u64 = 1 << 16;
    pub const PG: u64 = 1 << 31;
}

pub mod cr4 {
    pub const PAE:        u64 = 1 << 5;
    pub const OSFXSR:     u64 = 1 << 9;
    pub const OSXMMEXCPT: u64 = 1 << 10;
    pub const OSXSAVE:    u64 = 1 << 18;
}

pub mod xcr0 {
    pub const X87: u64 = 1;
    pub const SSE: u64 = 1 << 1;
}

pub mod efer {
    pub const LME: u64 = 1 << 8;
    pub const LMA: u64 = 1 << 10;
    pub const NXE: u64 = 1 << 11;
}
