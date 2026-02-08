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
    shards: Vec<Box<dyn Shard + Sync>>,
    values: std::sync::Mutex<std::collections::HashMap<(crate::Version, crate::KeyHash), crate::OwnedValue>>,
    num_shards: usize,
}

impl MockShardedTreeStore {
    /// Creates a new mock sharded tree store with the specified number of shards.
    pub fn new(num_shards: usize) -> Self {
        let mut shards = Vec::with_capacity(num_shards);
        for i in 0..num_shards {
            let shard: Box<dyn Shard + Sync> = Box::new(MockShard::new(i));
            shards.push(shard);
        }

        // Initialize shard 0 with the genesis root node
        let genesis_root_key = NodeKey::new_empty_path(0);
        shards[0].write_batch(&[(genesis_root_key, Node::new_null())]).unwrap();

        Self {
            shards,
            values: std::sync::Mutex::new(Default::default()),
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

    fn get_value_option(&self, max_version: crate::Version, key_hash: crate::KeyHash) -> Result<Option<crate::OwnedValue>> {
        // Mock implementation - search for the most recent version <= max_version
        for version in (0..=max_version).rev() {
            let value_key = (version, key_hash);
            if let Some(value) = self.values.lock().unwrap().get(&value_key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, crate::node_type::LeafNode)>> {
        // Mock implementation - always returns None
        Ok(None)
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards)
    }

    fn num_shards(&self) -> usize {
        self.num_shards
    }
}

impl ShardedTreeWriter for MockShardedTreeStore {
    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        self.shards[shard_idx].write_batch(batch)
    }
    
    fn write_values(&self, node_batch: &crate::writer::NodeBatch) -> Result<()> {
        let mut values = self.values.lock().unwrap();

        for ((version, key_hash), value_option) in node_batch.values() {
            if let Some(value) = value_option {
                values.insert((*version, *key_hash), value.clone());
            }
        }

        Ok(())
    }
    
    fn group_nodes_by_shard(
        &self,
        node_batch: &crate::writer::NodeBatch,
    ) -> std::collections::HashMap<usize, Vec<(NodeKey, Node)>> {
        let mut shard_batches = std::collections::HashMap::new();
        
        for (node_key, node) in node_batch.nodes() {
            let shard_idx = crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards);
            shard_batches
                .entry(shard_idx)
                .or_insert_with(Vec::new)
                .push((node_key.clone(), node.clone()));
        }
        
        shard_batches
    }

    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards)
    }

    fn num_shards(&self) -> usize {
        self.num_shards
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
    values: std::sync::Mutex<std::collections::HashMap<(crate::Version, crate::KeyHash), crate::OwnedValue>>,
    rightmost_leaf: std::sync::Mutex<Option<(NodeKey, crate::node_type::LeafNode)>>,
    num_shards: usize,
}

impl InMemoryShardedTreeStore {
    /// Creates a new in-memory sharded tree store with the specified number of shards.
    pub fn new(num_shards: usize) -> Self {
        let mut shards: Vec<std::sync::Mutex<std::collections::BTreeMap<NodeKey, Node>>> = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(std::sync::Mutex::new(Default::default()));
        }

        // Initialize shard 0 with the genesis root node
        let genesis_root_key = NodeKey::new_empty_path(0);
        shards[0].lock().unwrap().insert(genesis_root_key, Node::new_null());

        Self {
            shards,
            values: std::sync::Mutex::new(Default::default()),
            rightmost_leaf: std::sync::Mutex::new(None),
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

    fn get_value_option(&self, max_version: crate::Version, key_hash: crate::KeyHash) -> Result<Option<crate::OwnedValue>> {
        // In-memory implementation - search for the most recent version <= max_version
        for version in (0..=max_version).rev() {
            let value_key = (version, key_hash);
            if let Some(value) = self.values.lock().unwrap().get(&value_key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, crate::node_type::LeafNode)>> {
        // In-memory implementation - return the stored rightmost leaf
        Ok(self.rightmost_leaf.lock().unwrap().clone())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards)
    }

    fn num_shards(&self) -> usize {
        self.num_shards
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
    
    fn write_values(&self, node_batch: &crate::writer::NodeBatch) -> Result<()> {
        let mut values = self.values.lock().unwrap();

        for ((version, key_hash), value_option) in node_batch.values() {
            if let Some(value) = value_option {
                values.insert((*version, *key_hash), value.clone());
            }
        }

        Ok(())
    }
    
    fn group_nodes_by_shard(
        &self,
        node_batch: &crate::writer::NodeBatch,
    ) -> std::collections::HashMap<usize, Vec<(NodeKey, Node)>> {
        let mut shard_batches = std::collections::HashMap::new();
        
        for (node_key, node) in node_batch.nodes() {
            let shard_idx = crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards);
            shard_batches
                .entry(shard_idx)
                .or_insert_with(Vec::new)
                .push((node_key.clone(), node.clone()));
        }
        
        shard_batches
    }

    fn get_shard_index(&self, node_key: &NodeKey) -> usize {
        crate::sharded_storage::calculate_shard_index_with_count(node_key, self.num_shards)
    }

    fn num_shards(&self) -> usize {
        self.num_shards
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
