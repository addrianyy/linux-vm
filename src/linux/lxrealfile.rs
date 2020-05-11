use crate::vm::*;
use super::VmPaging;
use super::errcodes as ec;
use super::lxfile::LinuxFile;

use std::fs::File;
use std::io::{Read, Write};

pub struct LinuxRealFile {
    file: File,
}

impl LinuxRealFile {
    pub fn new(file: File) -> Self {
        Self {
            file,
        }
    }
}

impl LinuxFile for LinuxRealFile {
    fn read(&mut self, buffer: &mut [u8]) -> i64 {
        match self.file.read_exact(buffer) {
            Ok(_)      => buffer.len() as i64,
            Err(error) => { 
                panic!("Unsupported read error {:?}.", error)
            },
        }
    }

    fn write(&mut self, buffer: &[u8]) -> i64 {
        match self.file.write_all(buffer) {
            Ok(_)      => buffer.len() as i64,
            Err(error) => { 
                panic!("Unsupported write error {:?}.", error)
            },
        }
    }

    fn ioctl(&mut self, cmd: u32, _arg: u64, _vm: &mut Vm, _paging: &mut VmPaging) -> i64 {

        match cmd {
            0x5413 => -ec::ENOTTY,
            _      => panic!("Unsupported IOCTL {:X} to file.", cmd),
        }
    }
}
