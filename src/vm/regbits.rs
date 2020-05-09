pub mod cr0 {
    pub const PE: u64 = 1;
    pub const PG: u64 = 1 << 31;
}

pub mod cr4 {
    pub const PAE: u64 = 1 << 5;
}

pub mod efer {
    pub const LME: u64 = 1 << 8;
    pub const LMA: u64 = 1 << 10;
}
