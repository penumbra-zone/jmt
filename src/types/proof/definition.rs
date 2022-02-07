// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module has definition of various proofs.

use std::marker::PhantomData;

use anyhow::{bail, ensure, format_err, Result};
use serde::{Deserialize, Serialize};

use super::{SparseMerkleInternalNode, SparseMerkleLeafNode};
use crate::hash::{CryptoHash, HashValue, SPARSE_MERKLE_PLACEHOLDER_HASH};

/// A proof that can be used to authenticate an element in a Sparse Merkle Tree given trusted root
/// hash. For example, `TransactionInfoToAccountProof` can be constructed on top of this structure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SparseMerkleProof<V> {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof. `leaf_node.key` is the only key
    ///           that exists in the subtree and `leaf_node.value_hash` equals the hash of the
    ///           corresponding account blob.
    ///     - If this is `None`, this is also a non-inclusion proof which indicates the subtree is
    ///       empty.
    leaf: Option<SparseMerkleLeafNode>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level.
    siblings: Vec<HashValue>,

    phantom: PhantomData<V>,
}

impl<V> SparseMerkleProof<V>
where
    V: CryptoHash,
{
    /// Constructs a new `SparseMerkleProof` using leaf and a list of siblings.
    pub fn new(leaf: Option<SparseMerkleLeafNode>, siblings: Vec<HashValue>) -> Self {
        SparseMerkleProof {
            leaf,
            siblings,
            phantom: PhantomData,
        }
    }

    /// Returns the leaf node in this proof.
    pub fn leaf(&self) -> Option<SparseMerkleLeafNode> {
        self.leaf
    }

    /// Returns the list of siblings in this proof.
    pub fn siblings(&self) -> &[HashValue] {
        &self.siblings
    }

    /// If `element_value` is present, verifies an element whose key is `element_key` and value is
    /// `element_value` exists in the Sparse Merkle Tree using the provided proof. Otherwise
    /// verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the
    /// tree.
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_value: Option<&V>,
    ) -> Result<()> {
        ensure!(
            self.siblings.len() <= HashValue::LENGTH_IN_BITS,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            HashValue::LENGTH_IN_BITS,
            self.siblings.len(),
        );

        match (element_value, self.leaf) {
            (Some(value), Some(leaf)) => {
                // This is an inclusion proof, so the key and value hash provided in the proof
                // should match element_key and element_value_hash. `siblings` should prove the
                // route from the leaf node to the root.
                ensure!(
                    element_key == leaf.key,
                    "Keys do not match. Key in proof: {:x}. Expected key: {:x}.",
                    leaf.key,
                    element_key
                );
                let hash = value.hash();
                ensure!(
                    hash == leaf.value_hash,
                    "Value hashes do not match. Value hash in proof: {:x}. \
                     Expected value hash: {:x}",
                    leaf.value_hash,
                    hash,
                );
            }
            (Some(_value), None) => bail!("Expected inclusion proof. Found non-inclusion proof."),
            (None, Some(leaf)) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will break a currently existing leaf
                // node represented by `proof_key` into a branch. `siblings` should prove the
                // route from that leaf node to the root.
                ensure!(
                    element_key != leaf.key,
                    "Expected non-inclusion proof, but key exists in proof.",
                );
                ensure!(
                    element_key.common_prefix_bits_len(leaf.key) >= self.siblings.len(),
                    "Key would not have ended up in the subtree where the provided key in proof \
                     is the only existing key, if it existed. So this is not a valid \
                     non-inclusion proof.",
                );
            }
            (None, None) => {
                // This is a non-inclusion proof. The proof intends to show that if a leaf node
                // representing `element_key` is inserted, it will show up at a currently empty
                // position. `sibling` should prove the route from this empty position to the root.
            }
        }

        let current_hash = self
            .leaf
            .map_or(*SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash());
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                element_key
                    .iter_bits()
                    .rev()
                    .skip(HashValue::LENGTH_IN_BITS - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_hash, bit)| {
                if bit {
                    SparseMerkleInternalNode::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::new(hash, *sibling_hash).hash()
                }
            });
        ensure!(
            actual_root_hash == expected_root_hash,
            "Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
            actual_root_hash,
            expected_root_hash,
        );

        Ok(())
    }
}

/// Note: this is not a range proof in the sense that a range of nodes is verified!
/// Instead, it verifies the entire left part of the tree up to a known rightmost node.
/// See the description below.
///
/// A proof that can be used to authenticate a range of consecutive leaves, from the leftmost leaf to
/// the rightmost known one, in a sparse Merkle tree. For example, given the following sparse Merkle tree:
///
/// ```text
///                   root
///                  /     \
///                 /       \
///                /         \
///               o           o
///              / \         / \
///             a   o       o   h
///                / \     / \
///               o   d   e   X
///              / \         / \
///             b   c       f   g
/// ```
///
/// if the proof wants show that `[a, b, c, d, e]` exists in the tree, it would need the siblings
/// `X` and `h` on the right.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SparseMerkleRangeProof {
    /// The vector of siblings on the right of the path from root to last leaf. The ones near the
    /// bottom are at the beginning of the vector. In the above example, it's `[X, h]`.
    right_siblings: Vec<HashValue>,
}

impl SparseMerkleRangeProof {
    /// Constructs a new `SparseMerkleRangeProof`.
    pub fn new(right_siblings: Vec<HashValue>) -> Self {
        Self { right_siblings }
    }

    /// Returns the right siblings.
    pub fn right_siblings(&self) -> &[HashValue] {
        &self.right_siblings
    }

    /// Verifies that the rightmost known leaf exists in the tree and that the resulting
    /// root hash matches the expected root hash.
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        rightmost_known_leaf: SparseMerkleLeafNode,
        left_siblings: Vec<HashValue>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        let mut left_sibling_iter = left_siblings.iter();
        let mut right_sibling_iter = self.right_siblings().iter();

        let mut current_hash = rightmost_known_leaf.hash();
        for bit in rightmost_known_leaf
            .key()
            .iter_bits()
            .rev()
            .skip(HashValue::LENGTH_IN_BITS - num_siblings)
        {
            let (left_hash, right_hash) = if bit {
                (
                    *left_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing left sibling."))?,
                    current_hash,
                )
            } else {
                (
                    current_hash,
                    *right_sibling_iter
                        .next()
                        .ok_or_else(|| format_err!("Missing right sibling."))?,
                )
            };
            current_hash = SparseMerkleInternalNode::new(left_hash, right_hash).hash();
        }

        ensure!(
            current_hash == expected_root_hash,
            "Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
            current_hash,
            expected_root_hash,
        );

        Ok(())
    }
}
