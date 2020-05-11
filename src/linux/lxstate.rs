use std::collections::{BTreeMap, BTreeSet};
use crate::mm::membank::MemBank;
use super::lxfile::{LinuxFile, DynLinuxFile};

pub type Fd = u32;

pub struct LinuxState {
    tid:      u32,
    pid:      u32,
    exited:   bool,
    fds:      BTreeMap<Fd, Box<DynLinuxFile>>,
    reserved: BTreeSet<Fd>,
    pub heap: MemBank,
}

impl LinuxState {
    pub fn new(pid: u32, tid: u32, heap_start: u64, heap_end: u64) -> Self {
        Self {
            pid,
            tid,
            exited:   false,
            fds:      BTreeMap::new(),
            reserved: BTreeSet::new(),
            heap:     MemBank::new(heap_start, Some(heap_end)),
        }
    }

    pub fn create_file_at_fd(&mut self, fd: Fd, file: impl LinuxFile + 'static, reserve: bool) {
        assert!(self.fds.insert(fd, Box::new(file)).is_none(), "FD {} was already used.", fd);

        if reserve {
            assert!(self.reserved.insert(fd), "FD {} was already reserved.", fd);
        }
    }

    pub fn exit(&mut self) {
        self.exited = true;
    }

    pub fn exited(&self) -> bool {
        self.exited
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn file_from_fd(&mut self, fd: Fd) -> Option<&mut DynLinuxFile> {
        self.fds.get_mut(&fd).map(|file| &mut **file)
    }
}
