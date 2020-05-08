mod vm;
use vm::*;

fn main() {
    let mut vm = Vm::new();

    vm.regs.rip     = 0x1000;
    vm.regs.cs.base = 0x0;
    vm.regs.cs.sel  = 0x0;

    vm.mem.map_memory(0x1000, 0x1000, Some(&[0xEB, 0xFE]));

    let vmexit = vm.run();

    println!("VM exit: {:#X?}", vmexit);
}
