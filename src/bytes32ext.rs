use std::ops::Index;

pub trait Bytes32Ext: Index<usize> {
    /// Returns the `index`-th nibble.
    fn get_nibble(&self, index: usize) -> crate::types::nibble::Nibble;
}

impl Bytes32Ext for [u8; 32] {
    fn get_nibble(&self, index: usize) -> crate::types::nibble::Nibble {
        crate::types::nibble::Nibble::from(if index % 2 == 0 {
            self[index / 2] >> 4
        } else {
            self[index / 2] & 0x0F
        })
    }
}
