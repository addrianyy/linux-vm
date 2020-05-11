use crate::vm::*;
use crate::mm::phys_allocator::ContinousPhysAllocator;
use super::usermem::{USER_R, USER_RW};
use super::lxstate::LinuxState;
use super::lxfile::DynLinuxFile;
use super::VmPaging;
use super::errcodes as ec;

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
            16  => self.sys_ioctl(params[0] as u32, params[1] as u32, params[2]),
            19  => self.sys_readv(params[0] as u32, params[1], params[2] as u32),
            20  => self.sys_writev(params[0] as u32, params[1], params[2] as u32),
            60  => self.sys_exit(params[0] as u32),
            158 => self.sys_arch_prctl(params[0] as u32, params[1]),
            218 => self.sys_set_tid_address(params[0]),
            231 => self.sys_exit_group(params[0] as u32),
            _   => panic!("Unknown syscall {} at RIP {:X}.", syscall_id, self.vm.regs().rip),
        }
    }

    fn is_valid_addr(&self, addr: u64) -> bool {
        if let Some((_, prot)) = self.paging.query_virt_addr(&self.vm, addr) {
            return prot.user;
        }

        return false;
    }

    fn sys_arch_prctl(&mut self, code: u32, addr: u64) -> i64 {
        match code {
            0x1001 => { // ARCH_SET_GS
                if !self.is_valid_addr(addr) {
                    return -ec::EPERM;
                }

                self.vm.regs_mut().gs.base = addr;
            },
            0x1002 => { // ARCH_SET_FS
                if !self.is_valid_addr(addr) {
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
        // TODO: Set TID ptr and handle it on thread termination.

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
