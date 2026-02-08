use anyhow::Result;

use crate::node_type::{LeafNode, Node, NodeKey};
use crate::{KeyHash, OwnedValue, Version};

/// Defines the interface for reading from sharded storage.
/// Each shard corresponds to a nibble path prefix (0-15).
pub trait ShardedTreeReader {
    /// Gets node given a node key. Automatically routes to the correct shard.
    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        let shard_idx = self.get_shard_index(node_key);
        self.get_node_from_shard(shard_idx, node_key)
    }

    /// Gets node given a shard index and node key.
    fn get_node_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Node> {
        self.get_node_option_from_shard(shard_idx, node_key)?
            .ok_or_else(|| anyhow::format_err!("Missing node at {:?} in shard {}.", node_key, shard_idx))
    }

    /// Gets node given a node key. Returns `None` if the node does not exist.
    /// Automatically routes to the correct shard.
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let shard_idx = self.get_shard_index(node_key);
        self.get_node_option_from_shard(shard_idx, node_key)
    }

    /// Gets node given a shard index and node key. Returns `None` if the node does not exist.
    fn get_node_option_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Option<Node>>;

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version. Returns an error if the value does not exist.
    fn get_value(&self, max_version: Version, key_hash: KeyHash) -> Result<OwnedValue> {
        self.get_value_option(max_version, key_hash)?
            .ok_or_else(|| {
                anyhow::format_err!(
                    "Missing value with max_version {max_version:} and key hash {key_hash:?}."
                )
            })
    }

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version.  Returns None if the value does not exist.
    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>>;

    /// Gets the rightmost leaf. Note that this assumes we are in the process of restoring the tree
    /// and all nodes are at the same version.
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>>;

    /// Returns a reference to self as Any for downcasting.
    /// This is used for runtime type checking and dynamic dispatch.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Calculates the shard index for a given node key.
    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        calculate_shard_index(node_key)
    }

    /// Gets multiple nodes in batch, potentially in parallel.
    ///
    /// # Arguments
    /// * `node_keys` - A slice of node keys to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a vector of `(NodeKey, Option<Node>)` pairs.
    fn get_nodes_batch(&self, node_keys: &[NodeKey]) -> Result<Vec<(NodeKey, Option<Node>)>> where Self: Sync {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            node_keys
                .par_iter()
                .map(|node_key| {
                    let result = self.get_node_option(node_key);
                    (node_key.clone(), result)
                })
                .map(|(node_key, result)| {
                    result.map(|node| (node_key, node))
                })
                .collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            node_keys
                .iter()
                .map(|node_key| {
                    let result = self.get_node_option(node_key);
                    result.map(|node| (node_key.clone(), node))
                })
                .collect()
        }
    }

    /// Gets the number of shards.
    fn num_shards(&self) -> usize;
}

/// Defines the interface for writing to sharded storage.
pub trait ShardedTreeWriter {
    /// Writes a node batch into storage. Automatically routes nodes to the correct shards.
    fn write_node_batch(&self, node_batch: &crate::writer::NodeBatch) -> Result<()> where Self: Sync {
        // Group nodes by shard
        let shard_batches = self.group_nodes_by_shard(node_batch);

        // Write each shard batch
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            shard_batches
                .into_par_iter()
                .try_for_each(|(shard_idx, batch)| {
                    self.write_shard_batch(shard_idx, &batch)
                })?
        }
        #[cfg(not(feature = "parallel"))]
        {
            shard_batches
                .into_iter()
                .try_for_each(|(shard_idx, batch)| {
                    self.write_shard_batch(shard_idx, &batch)
                })?
        }

        // Write values
        self.write_values(node_batch)
    }

    /// Writes values from a node batch into storage.
    fn write_values(&self, node_batch: &crate::writer::NodeBatch) -> Result<()> {
        // Default implementation - no-op
        Ok(())
    }

    /// Groups nodes by their corresponding shard index.
    fn group_nodes_by_shard(
        &self,
        node_batch: &crate::writer::NodeBatch,
    ) -> std::collections::HashMap<usize, Vec<(NodeKey, Node)>> {
        let mut shard_batches = std::collections::HashMap::new();

        for (node_key, node) in node_batch.nodes() {
            let shard_idx = self.get_shard_index(node_key);
            shard_batches
                .entry(shard_idx)
                .or_insert_with(Vec::new)
                .push((node_key.clone(), node.clone()));
        }

        shard_batches
    }

    /// Writes a batch of nodes to a specific shard.
    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()>;

    /// Calculates the shard index for a given node key.
    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        calculate_shard_index(node_key)
    }

    /// Gets the number of shards.
    fn num_shards(&self) -> usize;
}

/// Calculates the shard index for a given node key based on its nibble path.
/// The first nibble (0-15) determines the shard index, modulo the number of shards.
#[inline]
pub fn calculate_shard_index(node_key: &NodeKey) -> usize {
    let nibble_path = node_key.nibble_path();
    if nibble_path.is_empty() {
        // Root node goes to shard 0
        return 0;
    }
    
    let first_nibble = nibble_path.get_nibble(0);
    first_nibble.as_usize()
}

/// Calculates the shard index for a given node key with a specific number of shards.
#[inline]
pub fn calculate_shard_index_with_count(node_key: &NodeKey, num_shards: usize) -> usize {
    let nibble_path = node_key.nibble_path();
    if nibble_path.is_empty() {
        // Root node goes to shard 0
        return 0;
    }
    
    let first_nibble = nibble_path.get_nibble(0);
    first_nibble.as_usize() % num_shards
}

/// Defines the interface for a sharded tree store that combines both reading and writing.
pub trait ShardedTreeStore: ShardedTreeReader + ShardedTreeWriter {
    /// Gets the number of shards.
    fn num_shards(&self) -> usize;

    /// Gets a reference to a specific shard.
    fn get_shard(&self, shard_idx: usize) -> Result<&dyn Shard>;
}

/// Defines the interface for a single shard in the sharded storage.
pub trait Shard {
    /// Gets the shard index.
    fn shard_index(&self) -> usize;

    /// Gets a node from this shard.
    fn get_node(&self, node_key: &NodeKey) -> Result<Option<Node>>;

    /// Writes a batch of nodes to this shard.
    fn write_batch(&self, batch: &[(NodeKey, Node)]) -> Result<()>;

    /// Gets a reference to self as Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;
}
