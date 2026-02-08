#![cfg(feature = "rocksdb")]

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{Cache, DB, DBCompressionType, Options, WriteBatch, WriteOptions};

use crate::node_type::{Node, NodeKey};
use crate::sharded_storage::Shard;

/// A RocksDB implementation of a shard.
pub struct RocksDBShard {
    db: rocksdb::DB,
    shard_idx: usize,
    cf_handle: rocksdb::ColumnFamily,
}

impl RocksDBShard {
    /// Creates a new RocksDB shard with the specified database and column family.
    pub fn new(db: rocksdb::DB, shard_idx: usize, cf_handle: rocksdb::ColumnFamily) -> Self {
        Self {
            db,
            shard_idx,
            cf_handle,
        }
    }

    /// Gets the underlying RocksDB instance.
    pub fn db(&self) -> &rocksdb::DB {
        &self.db
    }

    /// Gets the column family handle for this shard.
    pub fn cf_handle(&self) -> &rocksdb::ColumnFamily {
        &self.cf_handle
    }
}

impl Shard for RocksDBShard {
    fn shard_index(&self) -> usize {
        self.shard_idx
    }

    fn get_node(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let mut key = vec![];
        node_key.serialize(&mut key)?;

        match self.db.get_cf(&self.cf_handle, key) {
            Ok(Some(value)) => {
                let node = Node::deserialize(&mut value.as_ref())?;
                Ok(Some(node))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("RocksDB get error: {:?}", e)),
        }
    }

    fn write_batch(&self, batch: &[(NodeKey, Node)]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let mut write_batch = WriteBatch::default();

        for (node_key, node) in batch {
            let mut key = vec![];
            node_key.serialize(&mut key)?;
            let mut value = vec![];
            node.serialize(&mut value)?;
            write_batch.put_cf(&self.cf_handle, key, value);
        }

        let write_options = WriteOptions::default();
        self.db.write_opt(write_batch, &write_options)
            .map_err(|e| anyhow::anyhow!("RocksDB write error: {:?}", e))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A RocksDB implementation of sharded tree store.
pub struct RocksDBShardedTreeStore {
    db: rocksdb::DB,
    num_shards: usize,
}

impl RocksDBShardedTreeStore {
    /// Creates a new RocksDB sharded tree store with the specified path and number of shards.
    pub fn new(path: &str, num_shards: usize) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        // Performance optimizations
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB write buffer
        opts.set_max_open_files(10000);
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_arena_block_size(16 * 1024); // 16KB arena blocks
        
        // Memory management
        let cache = rocksdb::Cache::new_lru_cache(1024 * 1024 * 1024); // 1GB cache
        opts.set_row_cache(&cache);

        // Create column family names for each shard plus a values column family
        let mut cf_names = Vec::with_capacity(num_shards + 1);
        cf_names.push("values".to_string());
        for i in 0..num_shards {
            cf_names.push(format!("shard_{}", i));
        }

        // Open the database with the specified column families
        let db = DB::open_cf(&opts, path, &cf_names)?;

        Ok(Self {
            db,
            num_shards,
        })
    }

    /// Creates a new RocksDB sharded tree store with custom options.
    pub fn new_with_options(path: &str, num_shards: usize, mut opts: Options) -> Result<Self> {
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create column family names for each shard plus a values column family
        let mut cf_names = Vec::with_capacity(num_shards + 1);
        cf_names.push("values".to_string());
        for i in 0..num_shards {
            cf_names.push(format!("shard_{}", i));
        }

        // Open the database with the specified column families
        let db = DB::open_cf(&opts, path, &cf_names)?;

        Ok(Self {
            db,
            num_shards,
        })
    }

    /// Gets the underlying RocksDB instance.
    pub fn db(&self) -> &rocksdb::DB {
        &self.db
    }

    /// Gets the column family handle for the specified shard.
    pub fn get_cf_handle(&self, shard_idx: usize) -> Option<&rocksdb::ColumnFamily> {
        if shard_idx < self.num_shards {
            let cf_name = format!("shard_{}", shard_idx);
            self.db.cf_handle(&cf_name)
        } else {
            None
        }
    }
}

impl crate::sharded_storage::ShardedTreeReader for RocksDBShardedTreeStore {
    fn get_node_option_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Option<Node>> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        let cf_handle = self.get_cf_handle(shard_idx).ok_or_else(|| anyhow::anyhow!("Failed to get column family handle for shard {}", shard_idx))?;
        let mut key = vec![];
        node_key.serialize(&mut key)?;

        match self.db.get_cf(cf_handle, key) {
            Ok(Some(value)) => {
                let node = Node::deserialize(&mut value.as_ref())?;
                Ok(Some(node))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("RocksDB get error: {:?}", e)),
        }
    }

    fn get_value_option(&self, max_version: crate::Version, key_hash: crate::KeyHash) -> Result<Option<crate::OwnedValue>> {
        // For now, we'll store values in a separate column family
        // This is a simplified implementation - in a real scenario, we'd need to handle versioning
        let value_cf_name = "values";
        if let Some(cf_handle) = self.db.cf_handle(value_cf_name) {
            let key = format!("{:?}:{}", key_hash, max_version);
            
            match self.db.get_cf(cf_handle, key) {
                Ok(Some(value)) => Ok(Some(crate::OwnedValue::from(value))),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("RocksDB get error: {:?}", e)),
            }
        } else {
            // Values column family doesn't exist, return None
            Ok(None)
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, crate::node_type::LeafNode)>> {
        // This is a simplified implementation
        // In a real scenario, we'd need to scan all shards to find the rightmost leaf
        Ok(None)
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl crate::sharded_storage::ShardedTreeWriter for RocksDBShardedTreeStore {
    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        if batch.is_empty() {
            return Ok(());
        }

        let cf_handle = self.get_cf_handle(shard_idx).ok_or_else(|| anyhow::anyhow!("Failed to get column family handle for shard {}", shard_idx))?;
        let mut write_batch = WriteBatch::default();

        for (node_key, node) in batch {
            let mut key = vec![];
            node_key.serialize(&mut key)?;
            let mut value = vec![];
            node.serialize(&mut value)?;
            write_batch.put_cf(cf_handle, key, value);
        }

        let write_options = WriteOptions::default();
        self.db.write_opt(write_batch, &write_options)
            .map_err(|e| anyhow::anyhow!("RocksDB write error: {:?}", e))
    }
}

impl crate::sharded_storage::ShardedTreeStore for RocksDBShardedTreeStore {
    fn num_shards(&self) -> usize {
        self.num_shards
    }

    fn get_shard(&self, shard_idx: usize) -> Result<&dyn crate::sharded_storage::Shard> {
        if shard_idx >= self.num_shards {
            return Err(anyhow::anyhow!("Invalid shard index: {}", shard_idx));
        }

        // This is a simplified implementation
        // In a real scenario, we'd return a proper RocksDBShard instance
        Err(anyhow::anyhow!("RocksDBShardedTreeStore does not implement Shard trait for individual shards"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::{node_type::{LeafNode, Node}, types::Version, sharded_storage::{ShardedTreeReader, ShardedTreeWriter}};

    #[test]
    fn test_rocksdb_shard() -> Result<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_str().unwrap();

        // Create a new RocksDB sharded tree store
        let store = RocksDBShardedTreeStore::new(path, 16)?;

        // Test that we can get column family handles for all shards
        for i in 0..16 {
            assert!(store.get_cf_handle(i).is_some());
        }

        Ok(())
    }

    #[test]
    fn test_rocksdb_sharded_tree_store_basic() -> Result<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_str().unwrap();

        // Create a new RocksDB sharded tree store
        let store = RocksDBShardedTreeStore::new(path, 16)?;

        // Create a test node
        let version = 1;
        let mut nibble_path = crate::types::nibble::nibble_path::NibblePath::new(vec![]);
        nibble_path.push(crate::types::nibble::Nibble::from(1));
        nibble_path.push(crate::types::nibble::Nibble::from(2));
        nibble_path.push(crate::types::nibble::Nibble::from(3));
        let node_key = NodeKey::new(version, nibble_path);
        let leaf_node = LeafNode::new(
            crate::KeyHash([0u8; 32]),
            crate::ValueHash([1u8; 32]),
        );
        let node = Node::Leaf(leaf_node);

        // Calculate shard index (should be 1 based on first nibble)
        let shard_idx = crate::sharded_storage::calculate_shard_index(&node_key);
        assert_eq!(shard_idx, 1);

        // Write the node to the store
        <RocksDBShardedTreeStore as ShardedTreeWriter>::write_shard_batch(&store, shard_idx, &[(node_key.clone(), node.clone())])?;

        // Read the node back from the store
        let read_node = <RocksDBShardedTreeStore as ShardedTreeReader>::get_node_option_from_shard(&store, shard_idx, &node_key)?;
        assert!(read_node.is_some());
        assert_eq!(read_node.unwrap(), node);

        // Test reading from non-existent shard
        let result = <RocksDBShardedTreeStore as ShardedTreeReader>::get_node_option_from_shard(&store, 100, &node_key);
        assert!(result.is_err());

        // Test writing to non-existent shard
        let result = <RocksDBShardedTreeStore as ShardedTreeWriter>::write_shard_batch(&store, 100, &[(node_key, node)]);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_rocksdb_sharded_tree_store_batch() -> Result<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_str().unwrap();

        // Create a new RocksDB sharded tree store
        let store = RocksDBShardedTreeStore::new(path, 16)?;

        // Create multiple test nodes
        let version = 1;
        let mut batch = Vec::new();

        for i in 0..10 {
            let nibble_path = crate::types::nibble::nibble_path::NibblePath::new(vec![i as u8, 1, 2]);
            let node_key = NodeKey::new(version, nibble_path);
            let leaf_node = LeafNode::new(
                crate::KeyHash([i as u8; 32]),
                crate::ValueHash([(i + 1) as u8; 32]),
            );
            let node = Node::Leaf(leaf_node);
            batch.push((node_key.clone(), node));
        }

        // Group nodes by shard
        let mut shard_batches = std::collections::HashMap::new();
        for (node_key, node) in &batch {
            let shard_idx = crate::sharded_storage::calculate_shard_index(node_key);
            shard_batches.entry(shard_idx).or_insert_with(Vec::new).push((node_key.clone(), node.clone()));
        }

        // Write each shard batch
        for (shard_idx, shard_batch) in shard_batches {
            <RocksDBShardedTreeStore as ShardedTreeWriter>::write_shard_batch(&store, shard_idx, &shard_batch)?;
        }

        // Read back all nodes
        for (node_key, expected_node) in batch {
            let shard_idx = crate::sharded_storage::calculate_shard_index(&node_key);
            let read_node = <RocksDBShardedTreeStore as ShardedTreeReader>::get_node_option_from_shard(&store, shard_idx, &node_key)?;
            assert!(read_node.is_some());
            assert_eq!(read_node.unwrap(), expected_node);
        }

        Ok(())
    }

    #[test]
    fn test_rocksdb_sharded_tree_store_empty_batch() -> Result<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_str().unwrap();

        // Create a new RocksDB sharded tree store
        let store = RocksDBShardedTreeStore::new(path, 16)?;

        // Test writing an empty batch
        let result = <RocksDBShardedTreeStore as ShardedTreeWriter>::write_shard_batch(&store, 0, &[]);
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_rocksdb_sharded_tree_store_value() -> Result<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_str().unwrap();

        // Create a new RocksDB sharded tree store
        let store = RocksDBShardedTreeStore::new(path, 16)?;

        // Test getting a value (should return None since we haven't stored any)
        let version = 1;
        let key_hash = crate::KeyHash([0u8; 32]);
        let value = <RocksDBShardedTreeStore as ShardedTreeReader>::get_value_option(&store, version, key_hash)?;
        assert!(value.is_none());

        Ok(())
    }
}
