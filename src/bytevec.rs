use std::ops::Deref;

pub struct ByteVec {
    vec: Vec<u8>,
}

impl ByteVec {
    pub fn new() -> Self {
        Self {
            vec: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            vec: Vec::with_capacity(capacity),
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> u64 {
        let offset = self.vec.len() as u64;

        self.vec.extend_from_slice(bytes);

        offset
    }

    pub fn push_u64(&mut self, value: u64) -> u64 {
        let offset = self.vec.len() as u64;

        self.vec.extend_from_slice(&value.to_le_bytes());

        offset
    }

    pub fn as_slice(&self) -> &[u8] {
        self.vec.as_slice()
    }
}

impl Deref for ByteVec {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
