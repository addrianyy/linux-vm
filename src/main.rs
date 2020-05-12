#![allow(dead_code)]

mod vm;
mod mm;
mod linux;
mod bytevec;

use linux::LinuxVm;

fn main() {
    let cmdline_args = [
        "mememulator",
        "3840",
        "2160",
        "params",
    ];

    let env = [
        "env var 1",
        "env var 2",
        "something",
    ];

    let mut linux_vm = LinuxVm::new("F:\\linuxapp\\compiled", &cmdline_args, &env,
        None);

    linux_vm.run();
}
