#![allow(dead_code)]

mod vm;
mod mm;
mod linux;
mod bytevec;

use linux::LinuxVm;

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

    let mut linux_vm = LinuxVm::new("F:\\result", &cmdline_args, &env, Some("coverage.txt"));
    linux_vm.run();
}
