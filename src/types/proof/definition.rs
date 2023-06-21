// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module has definition of various proofs.

use alloc::vec::Vec;
use anyhow::{bail, ensure, format_err, Result};
use serde::{Deserialize, Serialize};

use super::{SparseMerkleInternalNode, SparseMerkleLeafNode};
use crate::{
    storage::{LeafNode, Node},
    types::nibble::nibble_path::{skip_common_prefix, NibblePath},
    Bytes32Ext, KeyHash, PhantomHasher, RootHash, SimpleHasher, ValueHash,
    SPARSE_MERKLE_PLACEHOLDER_HASH,
};

/// A proof that can be used to authenticate an element in a Sparse Merkle Tree given trusted root
/// hash. For example, `TransactionInfoToAccountProof` can be constructed on top of this structure.
#[derive(
    Clone, Eq, PartialEq, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SparseMerkleProof<H: SimpleHasher> {
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
    siblings: Vec<[u8; 32]>,

    /// A marker type showing which hash function is used in this proof.
    phantom_hasher: PhantomHasher<H>,
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

impl<H: SimpleHasher> SparseMerkleProof<H> {
    /// Constructs a new `SparseMerkleProof` using leaf and a list of siblings.
    pub(crate) fn new(leaf: Option<SparseMerkleLeafNode>, siblings: Vec<[u8; 32]>) -> Self {
        SparseMerkleProof {
            leaf,
            siblings,
            phantom_hasher: Default::default(),
        }
    }

    /// Returns the leaf node in this proof.
    pub fn leaf(&self) -> Option<SparseMerkleLeafNode> {
        self.leaf
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

        match (element_value, self.leaf) {
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

        self.unsafe_verify(expected_root_hash, element_key)?;

        Ok(())
    }

    /// A helper function that is used to verify the values of the Merkle tree against the root hash without
    /// any preliminary checks
    fn unsafe_verify(&self, expected_root_hash: RootHash, element_key: KeyHash) -> Result<()> {
        let current_hash = self
            .leaf
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
                    SparseMerkleInternalNode::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::new(hash, *sibling_hash).hash()
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

    /// Verifies an update of the [`JellyfishMerkleTree`], proving the transition from an `old_root_hash` to a `new_root_hash` ([`RootHash`])
    /// Multiple cases to handle:
    ///    - Insert a tuple `new_element_key`, `new_element_value`
    ///    - Update a tuple `new_element_key`, `new_element_value`
    ///    - Delete the `new_element_key`
    /// This function does the following high level operations:
    ///    1. Verify the Merkle path provided against the `old_root_hash`
    ///    2. Use the provided Merkle path and the tuple (`new_element_key`, `new_element_value`) to compute the new Merkle path.
    ///    3. Compare the new Merkle path against the new_root_hash
    /// If these steps are verified then the [`JellyfishMerkleTree`] has been soundly updated
    ///
    /// This function consumes the Merkle proof to avoid uneccessary copying.
    pub fn verify_update<V: AsRef<[u8]>>(
        mut self,
        old_root_hash: RootHash,
        new_root_hash: RootHash,
        new_element_key: KeyHash,
        new_element_value: Option<V>,
    ) -> Result<()> {
        if let Some(new_element_value) = new_element_value {
            // A value have been supplied, we need to prove that we inserted a given value at the new key

            match self.leaf {
                // In the case there is a leaf in the Merkle path, we check that this leaf exists in the tree
                // The inserted key is going to update an existing leaf
                Some(leaf_node) => {
                    if new_element_key == leaf_node.key_hash {
                        // Case 1: The new element key is the same as the leaf key (value update)
                        // Step 1: we verify the key (with the old value) is present in the Merkle tree
                        self.verify_existence(
                            old_root_hash,
                            new_element_key,
                            leaf_node.value_hash.0,
                        )?;

                        // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
                        // In this case the siblings are left unchanged, only the leaf value is updated
                        let new_merkle_path: SparseMerkleProof<H> = SparseMerkleProof::new(
                            Some(SparseMerkleLeafNode::new(
                                new_element_key,
                                ValueHash::with::<H>(new_element_value),
                            )),
                            self.siblings,
                        );

                        new_merkle_path.unsafe_verify(new_root_hash, new_element_key)?;
                    } else {
                        // Case 2: The new element key is different from the leaf key (leaf creation)
                        // Step 1: we verify the old key is going to be split following the insertion of the
                        // new key (nonexistence proof)
                        self.verify_nonexistence(old_root_hash, new_element_key)?;

                        // Add the correct siblings of the new element key by finding the splitting nibble and
                        // adding the default leaves to the path
                        let new_key_path = NibblePath::new(new_element_key.0.to_vec());
                        let old_key_path = NibblePath::new(leaf_node.key_hash.0.to_vec());

                        let mut new_key_iter = new_key_path.nibbles();
                        let mut old_key_iter = old_key_path.nibbles();

                        // Skip the common prefix of the new and old key, then compute the remaining length to
                        // find the number of default nodes to add to the sibling list
                        let num_default_siblings =
                            skip_common_prefix(&mut new_key_iter, &mut old_key_iter);

                        let mut new_siblings: Vec<[u8; 32]> = Vec::with_capacity(
                            num_default_siblings + 1 + self.siblings.len(), /* The default siblings, the current leaf that becomes a sibling and the former siblings */
                        );

                        // Fill the siblings with the former default siblings
                        new_siblings.resize(num_default_siblings, Node::new_null().hash());

                        // Then add the previous leaf node
                        new_siblings.push(leaf_node.hash());

                        // Finally add the other siblings
                        new_siblings.append(&mut self.siblings);

                        // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
                        // In this case the siblings are left unchanged, only the leaf value is updated
                        let new_merkle_path: SparseMerkleProof<H> = SparseMerkleProof::new(
                            Some(SparseMerkleLeafNode::new(
                                new_element_key,
                                ValueHash::with::<H>(new_element_value),
                            )),
                            new_siblings,
                        );

                        new_merkle_path.unsafe_verify(new_root_hash, new_element_key)?;
                    }
                }

                // There is no leaf in the Merkle path, which means the key we are going to insert does not update an existing leaf
                None => {
                    // Step 1: we check that the `new_element_key` is going to populate an empty spot (nonexistence proof)
                    self.verify_nonexistence(old_root_hash, new_element_key)?;

                    // Step 2: we compute the new Merkle path (we build a new [`SparseMerkleProof`] object)
                    // In this case the siblings are left unchanged, only the leaf value is updated
                    let new_merkle_path: SparseMerkleProof<H> = SparseMerkleProof::new(
                        Some(SparseMerkleLeafNode::new(
                            new_element_key,
                            ValueHash::with::<H>(new_element_value),
                        )),
                        self.siblings,
                    );

                    // Step 3: we compare the new Merkle path against the new_root_hash
                    new_merkle_path.unsafe_verify(new_root_hash, new_element_key)?;
                }
            }
        } else {
            // No value supplied, we need to prove that the previous value was deleted
            if let Some(leaf_node) = self.leaf {
                ensure!(
                    new_element_key == leaf_node.key_hash,
                    "Key {:?} to remove doesn't match the leaf key {:?} supplied with the proof",
                    new_element_key,
                    leaf_node.key_hash
                );

                // Step 1: we verify the existence of the old key in the tree
                self.verify_existence(old_root_hash, new_element_key, leaf_node.value_hash.0)?;

                // Step 2: we compute the new Merkle tree path (same siblings but without the original leaf)
                let new_merkle_path: SparseMerkleProof<H> =
                    SparseMerkleProof::new(None, self.siblings);

                // Step 3: we verify that the key is not present in the tree anymore
                new_merkle_path.verify_nonexistence(new_root_hash, new_element_key)?;
            } else {
                bail!("Trying to remove an empty leaf")
            }
        }

        Ok(())
    }

    pub fn root_hash(&self) -> RootHash {
        let current_hash = self
            .leaf
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
                    SparseMerkleInternalNode::new(*sibling_hash, hash).hash()
                } else {
                    SparseMerkleInternalNode::new(hash, *sibling_hash).hash()
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
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct SparseMerkleRangeProof {
    /// The vector of siblings on the right of the path from root to last leaf. The ones near the
    /// bottom are at the beginning of the vector. In the above example, it's `[X, h]`.
    right_siblings: Vec<[u8; 32]>,
}

impl SparseMerkleRangeProof {
    /// Constructs a new `SparseMerkleRangeProof`.
    pub(crate) fn new(right_siblings: Vec<[u8; 32]>) -> Self {
        Self { right_siblings }
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
        rightmost_known_leaf: SparseMerkleLeafNode,
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
            current_hash = SparseMerkleInternalNode::new(left_hash, right_hash).hash();
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
