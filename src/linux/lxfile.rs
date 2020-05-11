use crate::vm::*;
use super::VmPaging;

pub type DynLinuxFile = dyn LinuxFile + 'static;

pub trait LinuxFile {
    fn read(&mut self, buffer: &mut [u8]) -> i64;
    fn write(&mut self, buffer: &[u8]) -> i64;
    fn ioctl(&mut self, cmd: u32, arg: u64, vm: &mut Vm, paging: &mut VmPaging) -> i64;
}
