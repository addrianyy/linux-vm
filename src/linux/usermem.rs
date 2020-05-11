use crate::mm::paging::MemProt;

pub const USER_R:  MemProt = MemProt { execute: false, write: false, user: true };
pub const USER_RW: MemProt = MemProt { execute: false, write: true,  user: true };
pub const USER_RX: MemProt = MemProt { execute: true,  write: false, user: true };
