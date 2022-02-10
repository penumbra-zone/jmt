// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_proof;

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof};
use crate::{KeyHash, ValueHash};

pub struct SparseMerkleInternalNode {
    left_child: [u8; 32],
    right_child: [u8; 32],
}

impl SparseMerkleInternalNode {
    pub fn new(left_child: [u8; 32], right_child: [u8; 32]) -> Self {
        Self {
            left_child,
            right_child,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        // chop a vowel to fit in 16 bytes
        hasher.update(b"JMT::IntrnalNode");
        hasher.update(&self.left_child);
        hasher.update(&self.right_child);
        *hasher.finalize().as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct SparseMerkleLeafNode {
    key_hash: KeyHash,
    value_hash: ValueHash,
}

impl SparseMerkleLeafNode {
    pub fn new(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        SparseMerkleLeafNode {
            key_hash,
            value_hash,
        }
    }

    pub fn key_hash(&self) -> KeyHash {
        self.key_hash
    }

    pub fn value_hash(&self) -> ValueHash {
        self.value_hash
    }

    pub fn hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"JMT::LeafNode");
        hasher.update(&self.key_hash.0);
        hasher.update(&self.value_hash.0);
        *hasher.finalize().as_ref()
    }
}
