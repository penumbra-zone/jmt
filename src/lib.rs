// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! This module implements [`JellyfishMerkleTree`] backed by storage module. The tree itself doesn't
//! persist anything, but realizes the logic of R/W only. The write path will produce all the
//! intermediate results in a batch for storage layer to commit and the read path will return
//! results directly. The public APIs are only [`new`], [`put_value_sets`], [`put_value_set`] and
//! [`get_with_proof`]. After each put with a `value_set` based on a known version, the tree will
//! return a new root hash with a [`TreeUpdateBatch`] containing all the new nodes and indices of
//! stale nodes.
//!
//! A Jellyfish Merkle Tree itself logically is a 256-bit sparse Merkle tree with an optimization
//! that any subtree containing 0 or 1 leaf node will be replaced by that leaf node or a placeholder
//! node with default hash value. With this optimization we can save CPU by avoiding hashing on
//! many sparse levels in the tree. Physically, the tree is structurally similar to the modified
//! Patricia Merkle tree of Ethereum but with some modifications. A standard Jellyfish Merkle tree
//! will look like the following figure:
//!
//! ```text
//!                                     .──────────────────────.
//!                             _.─────'                        `──────.
//!                        _.──'                                        `───.
//!                    _.─'                                                  `──.
//!                _.─'                                                          `──.
//!              ,'                                                                  `.
//!           ,─'                                                                      '─.
//!         ,'                                                                            `.
//!       ,'                                                                                `.
//!      ╱                                                                                    ╲
//!     ╱                                                                                      ╲
//!    ╱                                                                                        ╲
//!   ╱                                                                                          ╲
//!  ;                                                                                            :
//!  ;                                                                                            :
//! ;                                                                                              :
//! │                                                                                              │
//! +──────────────────────────────────────────────────────────────────────────────────────────────+
//!  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.
//! /    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \
//! +----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----+
//!  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!   )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//!  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!   )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//!  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!   )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//!  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!   )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//!  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■
//!
//!  ■: the [`Value`] type this tree stores.
//! ```
//!
//! A Jellyfish Merkle Tree consists of [`InternalNode`] and [`LeafNode`]. [`InternalNode`] is like
//! branch node in ethereum patricia merkle with 16 children to represent a 4-level binary tree and
//! [`LeafNode`] is similar to that in patricia merkle too. In the above figure, each `bell` in the
//! jellyfish is an [`InternalNode`] while each tentacle is a [`LeafNode`]. It is noted that
//! Jellyfish merkle doesn't have a counterpart for `extension` node of ethereum patricia merkle.
//!
//! [`JellyfishMerkleTree`]: struct.JellyfishMerkleTree.html
//! [`new`]: struct.JellyfishMerkleTree.html#method.new
//! [`put_value_sets`]: struct.JellyfishMerkleTree.html#method.put_value_sets
//! [`put_value_set`]: struct.JellyfishMerkleTree.html#method.put_value_set
//! [`get_with_proof`]: struct.JellyfishMerkleTree.html#method.get_with_proof
//! [`TreeUpdateBatch`]: struct.TreeUpdateBatch.html
//! [`InternalNode`]: node_type/struct.InternalNode.html
//! [`LeafNode`]: node_type/struct.LeafNode.html

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use sha2::digest::generic_array::GenericArray;
use sha2::digest::OutputSizeUser;
use sha2::Digest;
use thiserror::Error;

mod bytes32ext;
mod iterator;
mod metrics;
mod node_type;
mod reader;
mod tree;
mod tree_cache;
mod types;
mod writer;

pub mod mock;
pub mod restore;

use bytes32ext::Bytes32Ext;
pub use iterator::JellyfishMerkleIterator;
#[cfg(feature = "ics23")]
pub use tree::ics23_impl::ics23_spec;
pub use tree::{JellyfishMerkleTree, Sha256Jmt};
use types::nibble::ROOT_NIBBLE_HEIGHT;
pub use types::proof;
pub use types::Version;

/// Contains types used to bridge a [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// to the backing storage recording the tree's internal data.
pub mod storage {
    pub use node_type::{LeafNode, Node, NodeDecodeError, NodeKey};
    pub use reader::HasPreimage;
    pub use reader::TreeReader;
    pub use writer::{
        NodeBatch, NodeStats, StaleNodeIndex, StaleNodeIndexBatch, TreeUpdateBatch, TreeWriter,
    };

    use super::*;
}

#[cfg(any(test, feature = "fuzzing"))]
mod tests;

/// An error that occurs when the state root for a requested version is missing (e.g., because it was pruned).
#[derive(Error, Debug)]
#[error("Missing state root node at version {version}, probably pruned.")]
pub struct MissingRootError {
    pub version: Version,
}

// TODO: reorg

const SPARSE_MERKLE_PLACEHOLDER_HASH: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

/// An owned value stored in the [`JellyfishMerkleTree`].
pub type OwnedValue = Vec<u8>;

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

/// A root of a [`JellyfishMerkleTree`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct RootHash(pub [u8; 32]);

/// A hashed key used to index a [`JellyfishMerkleTree`].
///
/// The [`JellyfishMerkleTree`] only stores key hashes, not full keys.  Byte
/// keys can be converted to a [`KeyHash`] using the provided `From` impl.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct KeyHash(pub [u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
// This needs to be public for the fuzzing/Arbitrary feature, but we don't
// really want it to be, so #[doc(hidden)] is the next best thing.
#[doc(hidden)]
pub struct ValueHash(pub [u8; 32]);

impl ValueHash {
    pub fn with<H: SimpleHasher>(value: impl AsRef<[u8]>) -> Self {
        Self(H::hash(value))
    }
}

impl KeyHash {
    pub fn with<H: SimpleHasher>(key: impl AsRef<[u8]>) -> Self {
        let key_hash = Self(H::hash(key.as_ref()));
        // Adding a tracing event here allows cross-referencing the key hash
        // with the original key bytes when looking through logs.
        tracing::debug!(key = ?EscapedByteSlice(key.as_ref()), ?key_hash);
        key_hash
    }
}

impl std::fmt::Debug for KeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyHash")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl std::fmt::Debug for ValueHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ValueHash")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl std::fmt::Debug for RootHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RootHash")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

struct EscapedByteSlice<'a>(&'a [u8]);

impl<'a> std::fmt::Debug for EscapedByteSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "b\"")?;
        for &b in self.0 {
            // https://doc.rust-lang.org/reference/tokens.html#byte-escapes
            #[allow(clippy::manual_range_contains)]
            if b == b'\n' {
                write!(f, "\\n")?;
            } else if b == b'\r' {
                write!(f, "\\r")?;
            } else if b == b'\t' {
                write!(f, "\\t")?;
            } else if b == b'\\' || b == b'"' {
                write!(f, "\\{}", b as char)?;
            } else if b == b'\0' {
                write!(f, "\\0")?;
            // ASCII printable
            } else if b >= 0x20 && b < 0x7f {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        write!(f, "\"")?;
        Ok(())
    }
}

/// A minimal trait representing a hash function. We implement our own
/// rather than relying on `Digest` for broader compatibility.
pub trait SimpleHasher: Sized {
    /// Creates a new hasher with default state.
    fn new() -> Self;
    /// Ingests the provided data, updating the hasher's state.
    fn update(&mut self, data: &[u8]);
    /// Consumes the hasher state to produce a digest.
    fn finalize(self) -> [u8; 32];
    /// Returns the digest of the provided data.
    fn hash(data: impl AsRef<[u8]>) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

/// A wrapper around `std::marker::Phatomdata` which implements
/// Debug, PartialEq, Eq, and Clone  This allows higher level
/// structs to derive these traits even if the concrete hasher does not
/// implement them.
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct PhantomHasher<H: SimpleHasher>(std::marker::PhantomData<H>);

impl<H: SimpleHasher> Debug for PhantomHasher<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PhantomHasher")
            .field(&stringify!(H))
            .finish()
    }
}

impl<H: SimpleHasher> PartialEq for PhantomHasher<H> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<H: SimpleHasher> Default for PhantomHasher<H> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<T: Digest> SimpleHasher for T
where
    [u8; 32]: From<GenericArray<u8, <T as OutputSizeUser>::OutputSize>>,
{
    fn new() -> Self {
        <T as Digest>::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data)
    }

    fn finalize(self) -> [u8; 32] {
        self.finalize().into()
    }
}
