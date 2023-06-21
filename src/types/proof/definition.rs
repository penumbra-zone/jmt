// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module has definition of various proofs.

use core::marker::PhantomData;

use alloc::vec::Vec;
use anyhow::{bail, ensure, format_err, Result};
use serde::{Deserialize, Serialize};

use super::{SparseMerkleInternalNode, SparseMerkleLeafNode};
use crate::{
    Bytes32Ext, KeyHash, RootHash, SimpleHasher, ValueHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

/// A proof that can be used to authenticate an element in a Sparse Merkle Tree given trusted root
/// hash. For example, `TransactionInfoToAccountProof` can be constructed on top of this structure.
#[derive(Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleProof<H> {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof. `leaf_node.key` is the only key
    ///           that exists in the subtree and `leaf_node.value_hash` equals the hash of the
    ///           corresponding account blob.
    ///     - If this is `None`, this is also a non-inclusion proof which indicates the subtree is
    ///       empty.
    #[serde(bound(serialize = "", deserialize = ""))]
    leaf: Option<SparseMerkleLeafNode<H>>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level.
    siblings: Vec<[u8; 32]>,

    /// A marker type showing which hash function is used in this proof.
    #[serde(bound(serialize = "", deserialize = ""))]
    phantom_hasher: PhantomData<H>,
}

// Deriving Debug fails since H is not Debug though phantom_hasher implements it
// generically. Implement Debug manually as a workaround to enable Proptest
impl<H: SimpleHasher> core::fmt::Debug for SparseMerkleProof<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleProof")
            .field("leaf", &self.leaf)
            .field("siblings", &self.siblings)
            .field("phantom_hasher", &self.phantom_hasher)
            .finish()
    }
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> PartialEq for SparseMerkleProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.leaf == other.leaf && self.siblings == other.siblings
    }
}

// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H: SimpleHasher> Clone for SparseMerkleProof<H> {
    fn clone(&self) -> Self {
        Self {
            leaf: self.leaf.clone(),
            siblings: self.siblings.clone(),
            phantom_hasher: Default::default(),
        }
    }
}

impl<H: SimpleHasher> SparseMerkleProof<H> {
    /// Constructs a new `SparseMerkleProof` using leaf and a list of siblings.
    pub(crate) fn new(leaf: Option<SparseMerkleLeafNode<H>>, siblings: Vec<[u8; 32]>) -> Self {
        SparseMerkleProof {
            leaf,
            siblings,
            phantom_hasher: Default::default(),
        }
    }

    /// Returns the leaf node in this proof.
    pub fn leaf(&self) -> Option<SparseMerkleLeafNode<H>> {
        self.leaf.clone()
    }

    /// Returns the list of siblings in this proof.
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// Verifies an element whose key is `element_key` and value is
    /// `element_value` exists in the Sparse Merkle Tree using the provided proof.
    pub fn verify_existence<V: AsRef<[u8]>>(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
        element_value: V,
    ) -> Result<()> {
        self.verify(expected_root_hash, element_key, Some(element_value))
    }

    /// Verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the
    /// tree.
    pub fn verify_nonexistence(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
    ) -> Result<()> {
        self.verify(expected_root_hash, element_key, None::<&[u8]>)
    }

    /// If `element_value` is present, verifies an element whose key is `element_key` and value is
    /// `element_value` exists in the Sparse Merkle Tree using the provided proof. Otherwise
    /// verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the
    /// tree.
    pub fn verify<V: AsRef<[u8]>>(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
        element_value: Option<V>,
    ) -> Result<()> {
        ensure!(
            self.siblings.len() <= 256,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            256,
            self.siblings.len(),
        );

        match (element_value, self.leaf.clone()) {
            (Some(value), Some(leaf)) => {
                // This is an inclusion proof, so the key and value hash provided in the proof
                // should match element_key and element_value_hash. `siblings` should prove the
                // route from the leaf node to the root.
                ensure!(
                    element_key == leaf.key_hash,
                    "Keys do not match. Key in proof: {:?}. Expected key: {:?}.",
                    leaf.key_hash,
                    element_key
                );
                let hash: ValueHash = ValueHash::with::<H>(value);
                ensure!(
                    hash == leaf.value_hash,
                    "Value hashes do not match. Value hash in proof: {:?}. \
                     Expected value hash: {:?}",
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
                    element_key != leaf.key_hash,
                    "Expected non-inclusion proof, but key exists in proof.",
                );
                ensure!(
                    element_key.0.common_prefix_bits_len(&leaf.key_hash.0) >= self.siblings.len(),
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
            .clone()
            .map_or(SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash());
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                element_key
                    .0
                    .iter_bits()
                    .rev()
                    .skip(256 - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_hash, bit)| {
                if bit {
                    SparseMerkleInternalNode::<H>::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::<H>::new(hash, *sibling_hash).hash()
                }
            });
        ensure!(
            actual_root_hash == expected_root_hash.0,
            "Root hashes do not match. Actual root hash: {:?}. Expected root hash: {:?}.",
            actual_root_hash,
            expected_root_hash,
        );

        Ok(())
    }

    pub fn root_hash(&self) -> RootHash {
        let current_hash = self
            .leaf
            .clone()
            .map_or(SPARSE_MERKLE_PLACEHOLDER_HASH, |leaf| leaf.hash());
        let actual_root_hash = self
            .siblings
            .iter()
            .zip(
                self.leaf()
                    .expect("need leaf hash for root_hash")
                    .key_hash
                    .0
                    .iter_bits()
                    .rev()
                    .skip(256 - self.siblings.len()),
            )
            .fold(current_hash, |hash, (sibling_hash, bit)| {
                if bit {
                    SparseMerkleInternalNode::<H>::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::<H>::new(hash, *sibling_hash).hash()
                }
            });

        RootHash(actual_root_hash)
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
#[derive(Eq, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparseMerkleRangeProof<H> {
    /// The vector of siblings on the right of the path from root to last leaf. The ones near the
    /// bottom are at the beginning of the vector. In the above example, it's `[X, h]`.
    right_siblings: Vec<[u8; 32]>,
    #[serde(bound(serialize = "", deserialize = ""))]
    _phantom: PhantomData<H>,
}

// Manually implement PartialEq to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H> PartialEq for SparseMerkleRangeProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.right_siblings == other.right_siblings
    }
}

// Manually implement Clone to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H> Clone for SparseMerkleRangeProof<H> {
    fn clone(&self) -> Self {
        Self {
            right_siblings: self.right_siblings.clone(),
            _phantom: self._phantom.clone(),
        }
    }
}

// Manually implement Debug to circumvent [incorrect auto-bounds](https://github.com/rust-lang/rust/issues/26925)
// TODO: Switch back to #[derive] once the perfect_derive feature lands
impl<H> core::fmt::Debug for SparseMerkleRangeProof<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseMerkleRangeProof")
            .field("right_siblings", &self.right_siblings)
            .field("_phantom", &self._phantom)
            .finish()
    }
}

impl<H: SimpleHasher> SparseMerkleRangeProof<H> {
    /// Constructs a new `SparseMerkleRangeProof`.
    pub(crate) fn new(right_siblings: Vec<[u8; 32]>) -> Self {
        Self {
            right_siblings,
            _phantom: Default::default(),
        }
    }

    /// Returns the right siblings.
    pub fn right_siblings(&self) -> &[[u8; 32]] {
        &self.right_siblings
    }

    /// Verifies that the rightmost known leaf exists in the tree and that the resulting
    /// root hash matches the expected root hash.
    pub fn verify(
        &self,
        expected_root_hash: RootHash,
        rightmost_known_leaf: SparseMerkleLeafNode<H>,
        left_siblings: Vec<[u8; 32]>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        let mut left_sibling_iter = left_siblings.iter();
        let mut right_sibling_iter = self.right_siblings().iter();

        let mut current_hash = rightmost_known_leaf.hash();
        for bit in rightmost_known_leaf
            .key_hash()
            .0
            .iter_bits()
            .rev()
            .skip(256 - num_siblings)
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
            current_hash = SparseMerkleInternalNode::<H>::new(left_hash, right_hash).hash();
        }

        ensure!(
            current_hash == expected_root_hash.0,
            "Root hashes do not match. Actual root hash: {:?}. Expected root hash: {:?}.",
            current_hash,
            expected_root_hash,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use crate::{proof::SparseMerkleLeafNode, KeyHash, ValueHash};

    use super::{SparseMerkleProof, SparseMerkleRangeProof};

    fn get_test_proof() -> SparseMerkleProof<Sha256> {
        SparseMerkleProof {
            leaf: Some(SparseMerkleLeafNode::new(
                KeyHash([1u8; 32]),
                ValueHash([2u8; 32]),
            )),
            siblings: vec![[3u8; 32], [4u8; 32]],
            phantom_hasher: Default::default(),
        }
    }

    fn get_test_range_proof() -> SparseMerkleRangeProof<Sha256> {
        SparseMerkleRangeProof {
            right_siblings: vec![[3u8; 32], [4u8; 32]],
            _phantom: Default::default(),
        }
    }

    #[test]
    fn test_sparse_merkle_proof_roundtrip_serde() {
        let proof = get_test_proof();
        let serialized_proof = serde_json::to_string(&proof).expect("serialization is infallible");
        let deserialized =
            serde_json::from_str(&serialized_proof).expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_proof_roundtrip_borsh() {
        use borsh::{BorshDeserialize, BorshSerialize};
        let proof = get_test_proof();
        let serialized_proof = proof.try_to_vec().expect("serialization is infallible");
        let deserialized =
            SparseMerkleProof::<Sha256>::deserialize(&mut serialized_proof.as_slice())
                .expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_range_proof_roundtrip_serde() {
        let proof = get_test_range_proof();
        let serialized_proof = serde_json::to_string(&proof).expect("serialization is infallible");
        let deserialized =
            serde_json::from_str(&serialized_proof).expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_sparse_merkle_range_proof_roundtrip_borsh() {
        use borsh::{BorshDeserialize, BorshSerialize};
        let proof = get_test_range_proof();
        let serialized_proof = proof.try_to_vec().expect("serialization is infallible");
        let deserialized =
            SparseMerkleRangeProof::<Sha256>::deserialize(&mut serialized_proof.as_slice())
                .expect("serialized proof is valid");

        assert_eq!(proof, deserialized);
    }
}
