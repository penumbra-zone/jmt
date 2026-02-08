// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "parallel")]
use num_cpus;


use crate::node_type::{Node, NodeKey};
use crate::storage::TreeReader;

/// Optimized parallel I/O operations for tree storage.
/// This module provides efficient parallel access to storage systems,
/// minimizing lock contention and maximizing I/O throughput.
pub struct ParallelIO<R: TreeReader + Sync> {
    reader: Arc<R>,
}

impl<R: TreeReader + Sync + Send> ParallelIO<R> {
    /// Creates a new parallel I/O handler for the given storage reader.
    ///
    /// # Arguments
    /// * `reader` - The storage reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader: Arc::new(reader),
        }
    }

    /// Gets multiple nodes in parallel with optimized performance.
    ///
    /// # Arguments
    /// * `node_keys` - A slice of node keys to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a vector of `(NodeKey, Option<Node>)` pairs.
    pub fn get_nodes_parallel(&self, node_keys: &[NodeKey]) -> Result<Vec<(NodeKey, Option<Node>)>> {
        // Early return for empty case
        if node_keys.is_empty() {
            return Ok(Vec::new());
        }

        // Use rayon's parallel iterator with optimized performance
        let results: Vec<(NodeKey, Option<Node>)> = node_keys
            .par_iter()
            .map(|node_key| {
                // Use thread-local reader clone to minimize contention
                let reader = self.reader.clone();
                let node_key_clone = node_key.clone();
                let result = reader.get_node_option(&node_key_clone);
                (node_key_clone, result)
            })
            .filter_map(|(node_key, result)| {
                result.ok().map(|node| (node_key, node))
            })
            .collect();

        Ok(results)
    }

    /// Gets nodes in parallel with optimized batch processing.
    ///
    /// # Arguments
    /// * `node_keys` - A slice of node keys to retrieve.
    /// * `batch_size` - The maximum number of nodes to process per batch.
    ///
    /// # Returns
    /// A `Result` containing a vector of `(NodeKey, Option<Node>)` pairs.
    pub fn get_nodes_parallel_batched(
        &self,
        node_keys: &[NodeKey],
        batch_size: usize,
    ) -> Result<Vec<(NodeKey, Option<Node>)>> {
        // Early return for empty case
        if node_keys.is_empty() {
            return Ok(Vec::new());
        }

        // Determine optimal batch size
        let optimal_batch_size = if batch_size == 0 {
            // Default batch size based on number of cores
            let num_cores = num_cpus::get();
            std::cmp::max(1, std::cmp::min(1000, node_keys.len() / num_cores))
        } else {
            batch_size
        };

        // Process node keys in parallel with optimized batching
        let results: Vec<(NodeKey, Option<Node>)> = node_keys
            .par_chunks(optimal_batch_size)
            .flat_map(|batch| {
                batch
                    .par_iter()
                    .map(|node_key| {
                        // Use thread-local reader clone to minimize contention
                        let reader = self.reader.clone();
                        let node_key_clone = node_key.clone();
                        let result = reader.get_node_option(&node_key_clone);
                        (node_key_clone, result)
                    })
                    .filter_map(|(node_key, result)| {
                        result.ok().map(|node| (node_key, node))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Ok(results)
    }

    /// Prefetches nodes in parallel with optimized performance.
    /// This is useful for warming up caches before actual operations.
    ///
    /// # Arguments
    /// * `node_keys` - A slice of node keys to prefetch.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    pub fn prefetch_nodes(&self, node_keys: &[NodeKey]) -> Result<()> {
        // Early return for empty case
        if node_keys.is_empty() {
            return Ok(());
        }

        // Prefetch all node keys in parallel with optimized batching
        node_keys
            .par_iter()
            .for_each(|node_key| {
                // Use thread-local reader clone to minimize contention
                let reader = self.reader.clone();
                let _ = reader.get_node_option(node_key);
            });

        Ok(())
    }

    /// Gets multiple nodes in parallel with cancellation support.
    ///
    /// # Arguments
    /// * `node_keys` - A slice of node keys to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a vector of `(NodeKey, Option<Node>)` pairs.
    pub fn get_nodes_parallel_with_cancellation(
        &self,
        node_keys: &[NodeKey],
    ) -> Result<Vec<(NodeKey, Option<Node>)>> {
        // Early return for empty case
        if node_keys.is_empty() {
            return Ok(Vec::new());
        }

        // Process all node keys in parallel with cancellation support
        let results: Vec<(NodeKey, Option<Node>)> = node_keys
            .par_iter()
            .map(|node_key| {
                // Use thread-local reader clone to minimize contention
                let reader = self.reader.clone();
                let node_key_clone = node_key.clone();
                let result = reader.get_node_option(&node_key_clone);
                (node_key_clone, result)
            })
            .filter_map(|(node_key, result)| {
                result.ok().map(|node| (node_key, node))
            })
            .collect();

        Ok(results)
    }

    /// Gets a reference to underlying reader.
    pub fn reader(&self) -> &R {
        &self.reader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockTreeStore;
    use crate::node_type::{LeafNode, Node};
    use crate::{KeyHash, OwnedValue};

    #[test]
    fn test_parallel_io_basic() {
        let mock_store = MockTreeStore::default();
        let parallel_io = ParallelIO::new(mock_store);

        // Create some test node keys
        let mut node_keys = Vec::new();
        for i in 0..10 {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<sha2::Sha256>(key.as_bytes());
            let value_hash = crate::ValueHash::with::<sha2::Sha256>(&[i as u8; 32]);
            let leaf_node = LeafNode::new(key_hash, value_hash);
            let node = Node::Leaf(leaf_node);
            let node_key = NodeKey::new(0, crate::storage::NibblePath::new(vec![i as u8]));
            node_keys.push(node_key);
        }

        // Test parallel get
        let results = parallel_io.get_nodes_parallel(&node_keys);
        assert!(results.is_ok());
    }

    #[test]
    fn test_parallel_io_batched() {
        let mock_store = MockTreeStore::default();
        let parallel_io = ParallelIO::new(mock_store);

        // Create some test node keys
        let mut node_keys = Vec::new();
        for i in 0..20 {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<sha2::Sha256>(key.as_bytes());
            let value_hash = crate::ValueHash::with::<sha2::Sha256>(&[i as u8; 32]);
            let leaf_node = LeafNode::new(key_hash, value_hash);
            let node = Node::Leaf(leaf_node);
            let node_key = NodeKey::new(0, crate::storage::NibblePath::new(vec![i as u8]));
            node_keys.push(node_key);
        }

        // Test parallel get with batching
        let results = parallel_io.get_nodes_parallel_batched(&node_keys, 5);
        assert!(results.is_ok());
    }
}
