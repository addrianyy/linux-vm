#![allow(dead_code)]

mod vm;
mod mm;
mod linux;
mod bytevec;

use linux::LinuxVm;

fn main() {
    let cmdline_args = [
        "test_emulator",
        "123",
        "test00000",
    ];

    let env = [
        "env var 1",
        "env var 2",
        "something",
    ];

    let mut linux_vm = LinuxVm::new("compiled-app", &cmdline_args, &env, None);

    linux_vm.run();
}
