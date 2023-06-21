// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Merkle proof types.

pub(crate) mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod proptest_proof;

use serde::{Deserialize, Serialize};

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof};
use crate::{KeyHash, PhantomHasher, SimpleHasher, ValueHash};

pub const LEAF_DOMAIN_SEPARATOR: &[u8] = b"JMT::LeafNode";
pub const INTERNAL_DOMAIN_SEPARATOR: &[u8] = b"JMT::IntrnalNode";

pub(crate) struct SparseMerkleInternalNode<H: SimpleHasher> {
    left_child: [u8; 32],
    right_child: [u8; 32],
    _phantom: PhantomHasher<H>,
}

impl<H: SimpleHasher> SparseMerkleInternalNode<H> {
    pub fn new(left_child: [u8; 32], right_child: [u8; 32]) -> Self {
        Self {
            left_child,
            right_child,
            _phantom: Default::default(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = H::new();
        // chop a vowel to fit in 16 bytes
        hasher.update(INTERNAL_DOMAIN_SEPARATOR);
        hasher.update(&self.left_child);
        hasher.update(&self.right_child);
        hasher.finalize()
    }
}

#[derive(Eq, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleLeafNode<H: SimpleHasher> {
    key_hash: KeyHash,
    value_hash: ValueHash,
    #[serde(bound(serialize = "", deserialize = ""))]
    _phantom: PhantomHasher<H>,
}

// Manually implement Arbitrary to get the correct bounds (proptest_derive) only allows all-or-nothing,
// but we need H: SimpleHasher only.
#[cfg(any(test, feature = "fuzzing"))]
impl<H: SimpleHasher> proptest::arbitrary::Arbitrary for SparseMerkleLeafNode<H> {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, strategy::Strategy};
        (any::<KeyHash>(), any::<ValueHash>())
            .prop_map(|(key_hash, value_hash)| Self {
                key_hash,
                value_hash,
                _phantom: Default::default(),
            })
            .boxed()
    }
}
// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> Clone for SparseMerkleLeafNode<H> {
    fn clone(&self) -> Self {
        Self {
            key_hash: self.key_hash.clone(),
            value_hash: self.value_hash.clone(),
            _phantom: self._phantom.clone(),
        }
    }
}

// Manually implement Debug to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> core::fmt::Debug for SparseMerkleLeafNode<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleLeafNode")
            .field("key_hash", &self.key_hash)
            .field("value_hash", &self.value_hash)
            .field("_phantom", &self._phantom)
            .finish()
    }
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> PartialEq for SparseMerkleLeafNode<H> {
    fn eq(&self, other: &Self) -> bool {
        self.key_hash == other.key_hash && self.value_hash == other.value_hash
    }
}

impl<H: SimpleHasher> SparseMerkleLeafNode<H> {
    pub(crate) fn new(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        SparseMerkleLeafNode {
            key_hash,
            value_hash,
            _phantom: Default::default(),
        }
    }

    pub(crate) fn key_hash(&self) -> KeyHash {
        self.key_hash
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        let mut hasher = H::new();
        hasher.update(LEAF_DOMAIN_SEPARATOR);
        hasher.update(&self.key_hash.0);
        hasher.update(&self.value_hash.0);
        hasher.finalize()
    }
}
