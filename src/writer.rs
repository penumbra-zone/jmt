use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

use crate::{
    node_type::{Node, NodeKey},
    types::Version,
};

/// Defines the interface used to write a batch of updates from a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// to the underlying storage holding nodes.
pub trait TreeWriter {
    /// Writes a node batch into storage.
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()>;
}

/// Node batch that will be written into db atomically with other batches.
pub type NodeBatch = BTreeMap<NodeKey, Node>;
/// [`StaleNodeIndex`](struct.StaleNodeIndex.html) batch that will be written into db atomically
/// with other batches.
pub type StaleNodeIndexBatch = BTreeSet<StaleNodeIndex>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeStats {
    pub new_nodes: usize,
    pub new_leaves: usize,
    pub stale_nodes: usize,
    pub stale_leaves: usize,
}

/// Indicates a node becomes stale since `stale_since_version`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct StaleNodeIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey,
}

/// This is a wrapper of [`NodeBatch`](type.NodeBatch.html),
/// [`StaleNodeIndexBatch`](type.StaleNodeIndexBatch.html) and some stats of nodes that represents
/// the incremental updates of a tree and pruning indices after applying a write set,
/// which is a vector of `hashed_account_address` and `new_value` pairs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TreeUpdateBatch {
    pub node_batch: NodeBatch,
    pub stale_node_index_batch: StaleNodeIndexBatch,
    pub node_stats: Vec<NodeStats>,
}
