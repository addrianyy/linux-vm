#![allow(dead_code)]

mod vm;
mod phys_allocator;
mod paging;
mod membank;
mod linuxvm;
mod elf_loader;
mod errcodes;
mod bytevec;

use linuxvm::LinuxVm;

fn main() {
    let mut linux_vm = LinuxVm::new("F:\\result");
    linux_vm.run();
}
