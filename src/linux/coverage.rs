use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;

pub struct Coverage {
    rips: BTreeSet<u64>,
    file: File,
}

impl Coverage {
    pub fn new(path: &str) -> Self {
        let file = File::create(path).expect("Failed to create coverage file.");

        Self {
            rips: BTreeSet::new(),
            file,
        }
    }

    pub fn report(&mut self, rip: u64) {
        self.rips.insert(rip);
    }

    pub fn entries(&self) -> usize {
        self.rips.len()
    }
}

impl Drop for Coverage {
    fn drop(&mut self) {
        for rip in self.rips.iter() {
            self.file.write_all(format!("{:X}\n", rip).as_bytes())
                .expect("Failed to write coverage info.");
        }
    }
}
