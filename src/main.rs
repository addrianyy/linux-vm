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
    let cmdline_args = [
        "mememulator",
        "hello",
        "world",
        "params",
    ];

    let env = [
        "env var 1",
        "env var 2",
        "something",
    ];

    let mut linux_vm = LinuxVm::new("F:\\result", &cmdline_args, &env, Some("cov.txt"));
    linux_vm.run();
}
