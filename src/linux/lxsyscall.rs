use crate::vm::*;
use crate::mm::phys_allocator::{PhysAllocator, ContinousPhysAllocator};
use crate::mm::paging::MemProt;
use super::usermem::{USER_R, USER_RW};
use super::lxstate::LinuxState;
use super::lxfile::DynLinuxFile;
use super::lxrealfile::LinuxRealFile;
use crate::bytevec::ByteVec;
use super::VmPaging;
use super::errcodes as ec;
use super::errconv::ekind_to_linux_error;

use std::time::{SystemTime, Duration};
use std::convert::TryInto;
use std::fs::OpenOptions;

const O_WRONLY:    u32 = 00000001;
const O_RDWR:      u32 = 00000002;
const O_CREAT:     u32 = 01000;
const O_TRUNC:     u32 = 02000;
const O_EXCL:      u32 = 04000;
const O_APPEND:    u32 = 00010;
const O_DIRECTORY: u32 = 0100000;

pub struct LinuxSyscall<'a> {
    vm:             &'a mut Vm,
    paging:         &'a mut VmPaging,
    phys_allocator: &'a mut ContinousPhysAllocator,
    state:          &'a mut LinuxState,
}

impl<'a> LinuxSyscall<'a> {
    pub fn handle(
        vm:             &'a mut Vm,
        paging:         &'a mut VmPaging,
        phys_allocator: &'a mut ContinousPhysAllocator,
        state:          &'a mut LinuxState,
    ) -> i64 {
        let mut syscall = Self {
            vm,
            paging,
            phys_allocator,
            state,
        };

        syscall.service_syscall()
    }

    fn service_syscall(&mut self) -> i64 {
        let (syscall_id, params) = {
            let regs       = self.vm.regs();
            let syscall_id = regs.rax as u32;
            
            let params = [
                regs.rdi,
                regs.rsi,
                regs.rdx,
                regs.r10,
                regs.r8,
                regs.r9,
            ];

            (syscall_id, params)
        };

        match syscall_id {
            0   => self.sys_read(params[0] as u32, params[1], params[2]),
            1   => self.sys_write(params[0] as u32, params[1], params[2]),
            2   => self.sys_open(params[0], params[1] as u32, params[2] as u32),
            3   => self.sys_close(params[0] as u32),
            9   => self.sys_mmap(params[0], params[1], params[2] as u32, params[3] as u32,
                                 params[4] as u32, params[5] as u32),
            11  => self.sys_munmap(params[0], params[1]),
            12  => self.sys_brk(params[0]),
            16  => self.sys_ioctl(params[0] as u32, params[1] as u32, params[2]),
            19  => self.sys_readv(params[0] as u32, params[1], params[2] as u32),
            20  => self.sys_writev(params[0] as u32, params[1], params[2] as u32),
            28  => self.sys_madvise(params[0], params[1], params[2] as u32),
            35  => self.sys_nanosleep(params[0], params[1]),
            60  => self.sys_exit(params[0] as u32),
            85  => self.sys_creat(params[0], params[1] as u32),
            158 => self.sys_arch_prctl(params[0] as u32, params[1]),
            218 => self.sys_set_tid_address(params[0]),
            228 => self.sys_clock_gettime(params[0] as u32, params[1]),
            231 => self.sys_exit_group(params[0] as u32),
            _   => panic!("Unknown syscall {} at RIP {:X}.", syscall_id, self.vm.regs().rip),
        }
    }

    fn allocate(&mut self, length: u64, prot: MemProt) -> u64 {
        assert!(length & 0xFFF == 0, "Size {:X} not page aligned.", length);

        let phys_addr = self.phys_allocator.alloc_phys(&mut self.vm, length, None);
        let virt_addr = self.state.heap.reserve_region(length);

        self.paging.map_virt_region(&mut self.vm, virt_addr, phys_addr, length, prot);

        virt_addr
    }

    fn sys_mmap(&mut self, addr: u64, length: u64, prot: u32, flags: u32, _fd: u32, _off: u32) 
        -> i64
    {
        const PROT_READ:  u32 = 1;
        const PROT_WRITE: u32 = 2;
        const PROT_EXEC:  u32 = 4;

        const MAP_FILE:      u32 = 0x00;
        const MAP_SHARED:    u32 = 0x01;
        const MAP_PRIVATE:   u32 = 0x02;
        const MAP_ANONYMOUS: u32 = 0x20;

        // TODO

        assert!(flags & MAP_SHARED    == 0, "Shared mmap is not supported.");
        assert!(flags & MAP_PRIVATE   != 0, "Non-private mmap is not supported.");
        assert!(flags & MAP_ANONYMOUS != 0, "Non-anonymous mmap is not supported.");

        if addr != 0 {
            println!("WARNING: Ignoring mmap base address {:X}.", addr);
        }

        let length = (length + 0xFFF) & !0xFFF;

        self.allocate(length, MemProt {
            user:    true,
            write:   prot & PROT_WRITE != 0,
            execute: prot & PROT_EXEC  != 0,
        }) as i64
    }

    fn sys_munmap(&mut self, addr: u64, _size: u64) -> i64 {
        // TODO
        println!("munmap {:X}", addr);

        0
    }

    fn sys_madvise(&mut self, _addr: u64, _length: u64, _advice: u32) -> i64 {
        0
    }

    fn sys_nanosleep(&mut self, rqtp: u64, _rmtp: u64) -> i64 {
        let mut timespec = [0u8; 16];

        if self.paging.read_virt_checked(&mut self.vm, rqtp, &mut timespec, USER_RW).is_err() {
            return -ec::EFAULT;
        }

        let seconds = u64::from_le_bytes(timespec[0..8].try_into().unwrap());
        let nanos   = u64::from_le_bytes(timespec[8..16].try_into().unwrap());

        let duration = Duration::from_secs(seconds) + Duration::from_nanos(nanos);

        std::thread::sleep(duration);

        0
    }

    fn sys_clock_gettime(&mut self, _clock_id: u32, tp: u64) -> i64 {
        let unix_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let seconds = unix_time.as_secs();
        let nanos   = (unix_time.as_nanos() - Duration::from_secs(seconds).as_nanos()) as u64;

        let mut timespec = ByteVec::with_capacity(16);

        timespec.push_u64(seconds);
        timespec.push_u64(nanos);

        if self.paging.write_virt_checked(&mut self.vm, tp, &timespec, USER_RW).is_err() {
            return -ec::EFAULT;
        }

        0
    }

    fn read_string(&mut self, mut addr: u64) -> Option<String> {
        let mut bytes = Vec::with_capacity(1024);

        while bytes.len() < 1024 {
            let mut buf = [0u8; 16];
            let result  = self.paging.read_virt_checked(&mut self.vm, addr, &mut buf, USER_R);

            let read_bytes = match result {
                Ok(_)     => buf.len(),
                Err(read) => read as usize,
            };

            if read_bytes == 0 {
                return None;
            }

            let null_terminator = buf.iter().position(|x| *x == 0);
            if let Some(pos) = null_terminator {
                if pos != 0 {
                    bytes.extend_from_slice(&buf[0..pos]);
                }

                break;
            } else {
                bytes.extend_from_slice(&buf[0..read_bytes]);
            }

            if read_bytes < buf.len() {
                break;
            }

            addr += read_bytes as u64;
        }

        Some(String::from_utf8_lossy(&bytes).to_string())
    }


    fn sys_creat(&mut self, path: u64, mode: u32) -> i64 {
        self.sys_open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)
    }

    fn sys_open(&mut self, path: u64, mut flags: u32, _mode: u32) -> i64 {
        let path = if let Some(path) = self.read_string(path) {
            if path.contains("../") || path.contains("..\\") {
                return -ec::EACCES;
            }

            let mut final_path = String::new();
            final_path.push_str("linuxfs/");

            if path.starts_with("/") {
                final_path.push_str(&path[1..]);
            } else {
                final_path.push_str(&path);
            }

            final_path
        } else {
            return -ec::EFAULT;
        };

        if flags & O_CREAT != 0 {
            flags &= !O_DIRECTORY;
        }

        if flags & O_DIRECTORY != 0 {
            println!("WARNING: Opening of directories ({}) is not supported.", path);
            return -ec::ENOTDIR;
        }

        if flags & O_RDWR != 0 && flags & O_WRONLY != 0 {
            return -ec::EINVAL;
        }

        let read  = flags & O_RDWR != 0 || flags & O_WRONLY == 0;
        let write = flags & O_RDWR != 0 || flags & O_WRONLY == 1;

        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .append(flags & O_APPEND != 0)
            .truncate(flags & O_TRUNC != 0)
            .create(flags & O_CREAT != 0)
            .create_new(flags & O_EXCL != 0)
            .open(path);

        match file {
            Ok(file)   => self.state.create_file(LinuxRealFile::new(file)) as i64,
            Err(error) => ekind_to_linux_error(error.kind()),
        }
    }

    fn sys_close(&mut self, fd: u32) -> i64 {
        match self.state.close_file(fd) {
            true  => 0,
            false => -ec::EBADF,
        }
    }

    fn sys_brk(&mut self, _brk: u64) -> i64 {
        -ec::ENOMEM
    }

    fn is_um_addr(&self, addr: u64) -> bool {
        if let Some((_, prot)) = self.paging.query_virt_addr(&self.vm, addr) {
            return prot.user;
        }

        return false;
    }

    fn sys_arch_prctl(&mut self, code: u32, addr: u64) -> i64 {
        match code {
            0x1001 => { // ARCH_SET_GS
                if !self.is_um_addr(addr) {
                    return -ec::EPERM;
                }

                self.vm.regs_mut().gs.base = addr;
            },
            0x1002 => { // ARCH_SET_FS
                if !self.is_um_addr(addr) {
                    return -ec::EPERM;
                }

                self.vm.regs_mut().fs.base = addr;
            },
            0x1003 => { // ARCH_GET_FS
                let base = self.vm.regs().fs.base;
                if self.paging.write_virt_u64_checked(&mut self.vm, addr, base, USER_RW).is_err() {
                    return -ec::EFAULT;
                }
            },
            0x1004 => { // ARCH_GET_GS
                let base = self.vm.regs().gs.base;
                if self.paging.write_virt_u64_checked(&mut self.vm, addr, base, USER_RW).is_err() {
                    return -ec::EFAULT;
                }
            },
            0x1011 | 0x1012 => { // ARCH_GET_CPUID or ARCH_SET_CPUID
                return -ec::ENODEV;
            }
            _ => {
                return -ec::EINVAL;
            }
        };

        0
    }

    fn sys_set_tid_address(&mut self, _tidptr: u64) -> i64 {
        self.state.tid() as i64
    }

    fn sys_exit(&mut self, status: u32) -> i64 {
        println!("\nExecutable exited with status {:X}.", status);

        self.state.exit();

        0
    }

    fn sys_exit_group(&mut self, status: u32) -> i64 {
        self.sys_exit(status)
    }

    fn sys_ioctl(&mut self, fd: u32, cmd: u32, arg: u64) -> i64 {
        match self.state.file_from_fd(fd) {
            Some(file) => file.ioctl(cmd, arg, &mut self.vm, &mut self.paging),
            _          => -ec::EBADF,
        }
    }

    fn read(
        vm:     &mut Vm,
        paging: &mut VmPaging,
        file:   &mut DynLinuxFile,
        buf:    u64,
        count:  u64,
    ) -> i64 {
        let mut buffer = vec![0u8; count as usize];

        let result = file.read(&mut buffer);

        if result > 0 {
            let buffer = &buffer[..result as usize];

            if paging.write_virt_checked(vm, buf, buffer, USER_RW).is_err() {
                return -ec::EFAULT
            }
        }

        return result;
    }

    fn write(
        vm:     &mut Vm,
        paging: &mut VmPaging,
        file:   &mut DynLinuxFile,
        buf:    u64,
        count:  u64,
    ) -> i64 {
        let mut buffer = vec![0u8; count as usize];

        if paging.read_virt_checked(vm, buf, &mut buffer, USER_R).is_err() {
            return -ec::EFAULT
        }

        file.write(&buffer)
    }

    fn iovec_rw(
        &mut self,
        fd:     u32,
        iov:    u64,
        iovcnt: u32,
        func:   impl Fn(&mut Vm, &mut VmPaging, &mut DynLinuxFile, u64, u64) -> i64,
    ) -> i64 {
        if let Some(file) = self.state.file_from_fd(fd) {
            let mut total = 0;

            for i in 0..iovcnt {
                let iovec = iov + i as u64 * 16;

                let res = (self.paging.read_virt_u64_checked(&mut self.vm, iovec, USER_R),
                           self.paging.read_virt_u64_checked(&mut self.vm, iovec + 8, USER_R));

                if let (Ok(base), Ok(size)) = res {
                    let result = func(&mut self.vm, &mut self.paging, file, base, size);

                    if result < 0 {
                        return result;
                    }

                    total += result;
                } else {
                    return -ec::EFAULT;
                }
            }

            return total;
        } else {
            -ec::EBADF
        }
    }

    fn sys_read(&mut self, fd: u32, buf: u64, count: u64) -> i64 {
        match self.state.file_from_fd(fd) {
            Some(file) => Self::read(&mut self.vm, &mut self.paging, file, buf, count),
            _          => -ec::EBADF,
        }
    }

    fn sys_write(&mut self, fd: u32, buf: u64, count: u64) -> i64 {
        match self.state.file_from_fd(fd) {
            Some(file) => Self::write(&mut self.vm, &mut self.paging, file, buf, count),
            _          => -ec::EBADF,
        }
    }

    fn sys_readv(&mut self, fd: u32, iov: u64, iovcnt: u32) -> i64 {
        self.iovec_rw(fd, iov, iovcnt, Self::read)
    }

    fn sys_writev(&mut self, fd: u32, iov: u64, iovcnt: u32) -> i64 {
        self.iovec_rw(fd, iov, iovcnt, Self::write)
    }
}
