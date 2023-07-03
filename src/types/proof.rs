// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Merkle proof types.

pub(crate) mod definition;
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod proptest_proof;

use crate::proof::SparseMerkleNode::{Internal, Leaf};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

pub use self::definition::{SparseMerkleProof, SparseMerkleRangeProof};
use crate::{KeyHash, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const LEAF_DOMAIN_SEPARATOR: &[u8] = b"JMT::LeafNode";
pub const INTERNAL_DOMAIN_SEPARATOR: &[u8] = b"JMT::IntrnalNode";

#[derive(
    Serialize, Deserialize, Clone, Copy, Eq, PartialEq, BorshSerialize, BorshDeserialize, Debug,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
/// A [`SparseMerkleNode`] is either a null node, an internal sparse node or a leaf node.
/// This is useful in the delete case to know if we need to coalesce the leaves on deletion.
/// The [`SparseMerkleNode`] needs to store either a [`SparseMerkleInternalNode`] or a [`SparseMerkleLeafNode`]
/// to be able to safely assert that the node is either a leaf or an internal node. Indeed,
/// if one stores the node/leaf hash directly into the structure, any malicious prover would
/// be able to forge the node/leaf type, as this assertion wouldn't be checked.
/// Providing a [`SparseMerkleInternalNode`] or a [`SparseMerkleLeafNode`] structure is sufficient to
/// prove the node type as one would need to reverse the hash function to forge them.
pub(crate) enum SparseMerkleNode {
    // The default sparse node
    Null,
    // The internal sparse merkle tree node
    Internal(SparseMerkleInternalNode),
    // The leaf sparse merkle tree node
    Leaf(SparseMerkleLeafNode),
}

impl SparseMerkleNode {
    pub(crate) fn hash(&self) -> [u8; 32] {
        match self {
            SparseMerkleNode::Null => SPARSE_MERKLE_PLACEHOLDER_HASH,
            Internal(node) => node.hash(),
            Leaf(node) => node.hash(),
        }
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Eq, PartialEq, BorshSerialize, BorshDeserialize, Debug,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub(crate) struct SparseMerkleInternalNode {
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
        hasher.update(INTERNAL_DOMAIN_SEPARATOR);
        hasher.update(self.left_child);
        hasher.update(self.right_child);
        *hasher.finalize().as_ref()
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct SparseMerkleLeafNode {
    key_hash: KeyHash,
    value_hash: ValueHash,
}

impl SparseMerkleLeafNode {
    pub(crate) fn new(key_hash: KeyHash, value_hash: ValueHash) -> Self {
        SparseMerkleLeafNode {
            key_hash,
            value_hash,
        }
    }

    pub(crate) fn key_hash(&self) -> KeyHash {
        self.key_hash
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(LEAF_DOMAIN_SEPARATOR);
        hasher.update(self.key_hash.0);
        hasher.update(self.value_hash.0);
        *hasher.finalize().as_ref()
    }
}
