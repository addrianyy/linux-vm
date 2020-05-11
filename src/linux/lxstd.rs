use crate::vm::*;
use super::VmPaging;
use super::errcodes as ec;
use super::lxfile::LinuxFile;
use super::usermem::USER_RW;
use crate::bytevec::ByteVec;

pub struct LinuxStdout {
    is_stderr: bool,
}

impl LinuxStdout {
    pub fn new(is_stderr: bool) -> Self {
        Self {
            is_stderr,
        }
    }

    fn name(&self) -> &str {
        match self.is_stderr {
            true  => "stderr",
            false => "stdout",
        }
    }
}

impl LinuxFile for LinuxStdout {
    fn read(&mut self, _buffer: &mut [u8]) -> i64 {
        panic!("Reads not implemented for {}.", self.name());
    }

    fn write(&mut self, buffer: &[u8]) -> i64 {
        print!("{}", String::from_utf8_lossy(&buffer));

        buffer.len() as i64
    }

    fn ioctl(&mut self, cmd: u32, arg: u64, vm: &mut Vm, paging: &mut VmPaging) -> i64 {
        match cmd {
            0x00005413 => { // TIOCGWINSZ
                let mut winsize = ByteVec::with_capacity(2 * 4);

                winsize.push_u16(25); // rows
                winsize.push_u16(80); // cols
                winsize.push_u16(0);  // xpixel
                winsize.push_u16(0);  // ypixel

                if paging.write_virt_checked(vm, arg, &winsize, USER_RW).is_err() {
                    return -ec::EFAULT;
                }

                0
            },
            _ => panic!("Unsupported IOCTL {:X} to {}.", cmd, self.name()),
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
