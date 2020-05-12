use crate::vm::*;
use super::VmPaging;
use super::errcodes as ec;
use super::lxfile::LinuxFile;
use super::errconv::ekind_to_linux_error;

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
        match self.file.read(buffer) {
            Ok(bytes)  => bytes as i64,
            Err(error) => ekind_to_linux_error(error.kind()),
        }
    }

    fn write(&mut self, buffer: &[u8]) -> i64 {
        match self.file.write(buffer) {
            Ok(bytes)  => bytes as i64,
            Err(error) => ekind_to_linux_error(error.kind()),
        }
    }

    fn ioctl(&mut self, cmd: u32, _arg: u64, _vm: &mut Vm, _paging: &mut VmPaging) -> i64 {
        match cmd {
            0x5413 => -ec::ENOTTY,
            _      => panic!("Unsupported IOCTL {:X} to file.", cmd),
        }
    }
}
