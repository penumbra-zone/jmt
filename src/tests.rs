use crate::Value;
use proptest::prelude::Arbitrary;

mod helper;
mod iterator;
mod jellyfish_merkle;
mod mock_tree_store;
mod nibble_path;
mod node_type;
mod restore;
mod tree_cache;

/// `TestValue` defines the types of data that can be stored in a Jellyfish Merkle tree and used in
/// tests.
#[cfg(any(test, feature = "fuzzing"))]
pub trait TestValue: Value + Arbitrary + std::fmt::Debug + Eq + PartialEq + 'static {}
