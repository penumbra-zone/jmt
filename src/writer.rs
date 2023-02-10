use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

use crate::{
    node_type::{AugmentedNode, NodeKey},
    types::{value_identifier::ValueIdentifier, Version},
};

/// Defines the interface used to write a batch of updates from a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// to the underlying storage holding nodes.
pub trait TreeWriter {
    /// Writes a node batch into storage. Note: all deleted values must be processed by the
    /// underlying data store, or the JMT may return incorrect results during `get` queries.
    fn write_node_batch(&self, node_batch: &TreeChangeBatch) -> Result<()>;
}

/// A batch of changes to the tree that will be written into db atomically with other batches.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TreeChangeBatch {
    pub insertions: BTreeMap<NodeKey, AugmentedNode>,
    pub deleted_values: Vec<ValueIdentifier>,
}

impl TreeChangeBatch {
    /// Reset a NodeBatch to its empty state
    pub fn clear(&mut self) {
        self.insertions.clear();
        self.deleted_values.clear()
    }

    /// Get a node by key
    pub fn get_node(&self, node_key: &NodeKey) -> Option<&AugmentedNode> {
        self.insertions.get(node_key)
    }

    /// Returns a reference to the current set of nodes
    pub fn nodes(&self) -> &BTreeMap<NodeKey, AugmentedNode> {
        &self.insertions
    }

    /// Insert a node into the batch
    pub fn insert_node(&mut self, node_key: NodeKey, node: AugmentedNode) -> Option<AugmentedNode> {
        self.insertions.insert(node_key, node)
    }

    /// Returns a reference to the current set of nodes
    pub fn deleted_values(&self) -> &Vec<ValueIdentifier> {
        &self.deleted_values
    }

    /// Extend a node batch
    pub fn extend(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeKey, AugmentedNode)>,
        deleted_values: impl IntoIterator<Item = ValueIdentifier>,
    ) {
        self.insertions.extend(nodes);
        self.deleted_values.extend(deleted_values);
    }

    /// Merge two NodeBatches into a single one
    pub fn merge(&mut self, rhs: Self) {
        self.extend(rhs.insertions, rhs.deleted_values)
    }

    pub fn is_empty(&self) -> bool {
        self.insertions.is_empty() && self.deleted_values.is_empty()
    }
}

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
    pub node_batch: TreeChangeBatch,
    pub stale_node_index_batch: StaleNodeIndexBatch,
    pub node_stats: Vec<NodeStats>,
}
