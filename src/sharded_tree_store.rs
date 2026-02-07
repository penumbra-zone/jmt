use anyhow::Result;

use crate::node_type::{Node, NodeKey};
use crate::sharded_storage::{Shard, ShardedTreeReader, ShardedTreeStore, ShardedTreeWriter};

/// A mock implementation of a shard for testing purposes.
pub struct MockShard {
    shard_idx: usize,
    nodes: std::sync::Mutex<std::collections::BTreeMap<NodeKey, Node>>,
}

impl MockShard {
    /// Creates a new mock shard.
    pub fn new(shard_idx: usize) -> Self {
        Self {
            shard_idx,
            nodes: std::sync::Mutex::new(Default::default()),
        }
    }

    /// Gets all nodes in this shard.
    pub fn nodes(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<NodeKey, Node>> {
        self.nodes.lock().unwrap()
    }
}

impl Shard for MockShard {
    fn shard_index(&self) -> usize {
        self.shard_idx
    }

    fn get_node(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let nodes = self.nodes.lock().unwrap();
        Ok(nodes.get(node_key).cloned())
    }

    fn write_batch(&self, batch: &[(NodeKey, Node)]) -> Result<()> {
        let mut nodes = self.nodes.lock().unwrap();

        for (node_key, node) in batch {
            nodes.insert(node_key.clone(), node.clone());
        }

        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A mock implementation of sharded tree store for testing purposes.
pub struct MockShardedTreeStore {
    shards: Vec<Box<dyn Shard>>,
    num_shards: usize,
}

impl MockShardedTreeStore {
    /// Creates a new mock sharded tree store with the specified number of shards.
    pub fn new(num_shards: usize) -> Self {
        let mut shards = Vec::with_capacity(num_shards);
        for i in 0..num_shards {
            let shard: Box<dyn Shard> = Box::new(MockShard::new(i));
            shards.push(shard);
        }

        Self {
            shards,
            num_shards,
        }
    }

    /// Gets a reference to the mock shard at the specified index.
    pub fn get_mock_shard(&self, shard_idx: usize) -> Option<&MockShard> {
        self.shards[shard_idx].as_any().downcast_ref::<MockShard>()
    }
}

impl Shard for MockShardedTreeStore {
    fn shard_index(&self) -> usize {
        panic!("MockShardedTreeStore is not a single shard");
    }

    fn get_node(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let shard_idx = crate::sharded_storage::calculate_shard_index(node_key);
        self.shards[shard_idx].get_node(node_key)
    }

    fn write_batch(&self, _batch: &[(NodeKey, Node)]) -> Result<()> {
        // This is a no-op for the mock implementation
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl ShardedTreeReader for MockShardedTreeStore {
    fn get_node_option_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Option<Node>> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        self.shards[shard_idx].get_node(node_key)
    }

    fn get_value_option(&self, _max_version: crate::Version, _key_hash: crate::KeyHash) -> Result<Option<crate::OwnedValue>> {
        // Mock implementation - always returns None
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, crate::node_type::LeafNode)>> {
        // Mock implementation - always returns None
        Ok(None)
    }
}

impl ShardedTreeWriter for MockShardedTreeStore {
    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        self.shards[shard_idx].write_batch(batch)
    }
}

impl ShardedTreeStore for MockShardedTreeStore {
    fn num_shards(&self) -> usize {
        self.num_shards
    }

    fn get_shard(&self, shard_idx: usize) -> Result<&dyn Shard> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        Ok(&*self.shards[shard_idx])
    }
}

/// A simple in-memory implementation of sharded tree store.
pub struct InMemoryShardedTreeStore {
    shards: Vec<std::sync::Mutex<std::collections::BTreeMap<NodeKey, Node>>>,
    num_shards: usize,
}

impl InMemoryShardedTreeStore {
    /// Creates a new in-memory sharded tree store with the specified number of shards.
    pub fn new(num_shards: usize) -> Self {
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(std::sync::Mutex::new(Default::default()));
        }

        Self {
            shards,
            num_shards,
        }
    }

    /// Gets all nodes in the specified shard.
    pub fn get_shard_nodes(&self, shard_idx: usize) -> Option<std::sync::MutexGuard<'_, std::collections::BTreeMap<NodeKey, Node>>> {
        self.shards.get(shard_idx).map(|shard| shard.lock().unwrap())
    }
}

impl ShardedTreeReader for InMemoryShardedTreeStore {
    fn get_node_option_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Option<Node>> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        let nodes = self.shards[shard_idx].lock().unwrap();
        Ok(nodes.get(node_key).cloned())
    }

    fn get_value_option(&self, _max_version: crate::Version, _key_hash: crate::KeyHash) -> Result<Option<crate::OwnedValue>> {
        // In-memory implementation - always returns None
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, crate::node_type::LeafNode)>> {
        // In-memory implementation - always returns None
        Ok(None)
    }
}

impl ShardedTreeWriter for InMemoryShardedTreeStore {
    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        let mut nodes = self.shards[shard_idx].lock().unwrap();

        for (node_key, node) in batch {
            nodes.insert(node_key.clone(), node.clone());
        }

        Ok(())
    }
}

impl ShardedTreeStore for InMemoryShardedTreeStore {
    fn num_shards(&self) -> usize {
        self.num_shards
    }

    fn get_shard(&self, shard_idx: usize) -> Result<&dyn Shard> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        // This is a simplified implementation for testing
        // In a real implementation, you would return a proper Shard implementation
        Err(anyhow::anyhow!("InMemoryShardedTreeStore does not implement Shard trait for individual shards"))
    }
}
