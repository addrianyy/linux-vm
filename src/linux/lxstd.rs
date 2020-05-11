use crate::vm::*;
use super::VmPaging;
use super::errcodes as ec;
use super::lxfile::LinuxFile;

pub struct LinuxStdout {
    is_err: bool,
}

impl LinuxStdout {
    pub fn new(is_err: bool) -> Self {
        Self {
            is_err,
        }
    }
}

impl LinuxFile for LinuxStdout {
    fn read(&mut self, _buffer: &mut [u8]) -> i64 {
        panic!("Reads not implemented for stdout/stderr.");
    }

    fn write(&mut self, buffer: &[u8]) -> i64 {
        print!("{}", String::from_utf8_lossy(&buffer));

        buffer.len() as i64
    }

    fn ioctl(&mut self, cmd: u32, arg: u64, vm: &mut Vm, paging: &mut VmPaging) -> i64 {
        match cmd {
            0x00005413 => { // TIOCGWINSZ
                let result = paging.write_virt_u64(vm, arg, 0x0020_0030_0080_0080);

                if result.is_err() {
                    return -ec::EFAULT;
                }

                0
            },
            _ => {
                panic!("Unsupported cmd {:X} to stdout.", cmd);
            },
        }
    }
}


pub struct LinuxStdin {
    _priv: bool,
}

impl LinuxStdin {
    pub fn new() -> Self {
        Self {
            _priv: true,
        }
    }
}

impl LinuxFile for LinuxStdin {
    fn read(&mut self, _buffer: &mut [u8]) -> i64 {
        panic!("Reads not implemented for stdin.");
    }

    fn write(&mut self, _buffer: &[u8]) -> i64 {
        panic!("Writes not implemented for stdin.");
    }

    fn ioctl(&mut self, _cmd: u32, _arg: u64, _vm: &mut Vm, _paging: &mut VmPaging) -> i64 {
        panic!("IOCTLs not implemented for stdin.");
    }
}
