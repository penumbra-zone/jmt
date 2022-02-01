// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_proof;

use crate::hash::{
    CryptoHash, CryptoHasher, EventAccumulatorHasher, HashValue, SparseMerkleInternalHasher,
    TestOnlyHasher, TransactionAccumulatorHasher,
};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof};

pub struct MerkleTreeInternalNode<H> {
    left_child: HashValue,
    right_child: HashValue,
    hasher: PhantomData<H>,
}

impl<H: CryptoHasher> MerkleTreeInternalNode<H> {
    pub fn new(left_child: HashValue, right_child: HashValue) -> Self {
        Self {
            left_child,
            right_child,
            hasher: PhantomData,
        }
    }
}

impl<H: CryptoHasher> CryptoHash for MerkleTreeInternalNode<H> {
    type Hasher = H;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(self.left_child.as_ref());
        state.update(self.right_child.as_ref());
        state.finish()
    }
}

pub type SparseMerkleInternalNode = MerkleTreeInternalNode<SparseMerkleInternalHasher>;
pub type TransactionAccumulatorInternalNode = MerkleTreeInternalNode<TransactionAccumulatorHasher>;
pub type EventAccumulatorInternalNode = MerkleTreeInternalNode<EventAccumulatorHasher>;
pub type TestAccumulatorInternalNode = MerkleTreeInternalNode<TestOnlyHasher>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct SparseMerkleLeafNode {
    key: HashValue,
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub fn new(key: HashValue, value_hash: HashValue) -> Self {
        SparseMerkleLeafNode { key, value_hash }
    }

    pub fn key(&self) -> HashValue {
        self.key
    }

    pub fn value_hash(&self) -> HashValue {
        self.value_hash
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    type Hasher = SparseMerkleLeafNodeHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(self.key.as_ref());
        state.update(self.value_hash.as_ref());
        state.finish()
    }
}

// Inlined result of the macro expansion of `derive(CryptoHash)` for `SparseMerkleLeafNode`.

#[derive(Clone)]
pub struct SparseMerkleLeafNodeHasher(crate::hash::DefaultHasher);

static SPARSE_MERKLE_LEAF_NODE_SEED: once_cell::sync::OnceCell<[u8; 32]> =
    once_cell::sync::OnceCell::new();

impl SparseMerkleLeafNodeHasher {
    fn new() -> Self {
        let name = serde_name::trace_name::<SparseMerkleLeafNode>()
            .expect("The `CryptoHasher` macro only applies to structs and enums");
        SparseMerkleLeafNodeHasher(crate::hash::DefaultHasher::new(name.as_bytes()))
    }
}

static SPARSE_MERKLE_LEAF_NODE_HASHER: once_cell::sync::Lazy<SparseMerkleLeafNodeHasher> =
    once_cell::sync::Lazy::new(SparseMerkleLeafNodeHasher::new);

impl std::default::Default for SparseMerkleLeafNodeHasher {
    fn default() -> Self {
        SPARSE_MERKLE_LEAF_NODE_HASHER.clone()
    }
}

impl crate::hash::CryptoHasher for SparseMerkleLeafNodeHasher {
    fn seed() -> &'static [u8; 32] {
        SPARSE_MERKLE_LEAF_NODE_SEED.get_or_init(|| {
            let name = serde_name::trace_name::<SparseMerkleLeafNode>()
                .expect("The `CryptoHasher` macro only applies to structs and enums.")
                .as_bytes();
            crate::hash::DefaultHasher::prefixed_hash(name)
        })
    }

    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(self) -> crate::hash::HashValue {
        self.0.finish()
    }
}

impl std::io::Write for SparseMerkleLeafNodeHasher {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
