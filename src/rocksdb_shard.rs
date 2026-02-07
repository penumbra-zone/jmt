#![cfg(feature = "rocksdb")]

use anyhow::Result;
use rocksdb::{DB, Options, WriteBatch, WriteOptions};

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
        let key = node_key.serialize()?;

        match self.db.get_cf(&self.cf_handle, key) {
            Ok(Some(value)) => {
                let node = Node::deserialize(&value)?;
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
            let key = node_key.serialize()?;
            let value = node.serialize()?;
            write_batch.put_cf(&self.cf_handle, key, value);
        }

        let write_options = WriteOptions::default();
        self.db.write_opt(write_batch, &write_options)
            .map_err(|e| anyhow::anyhow!("RocksDB write error: {:?}", e))
    }
}

/// A RocksDB implementation of sharded tree store.
pub struct RocksDBShardedTreeStore {
    db: rocksdb::DB,
    cfs: Vec<rocksdb::ColumnFamily>,
    num_shards: usize,
}

impl RocksDBShardedTreeStore {
    /// Creates a new RocksDB sharded tree store with the specified path and number of shards.
    pub fn new(path: &str, num_shards: usize) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create column family names for each shard
        let mut cf_names = Vec::with_capacity(num_shards);
        for i in 0..num_shards {
            cf_names.push(format!("shard_{}", i));
        }

        // Open the database with the specified column families
        let db = DB::open_cf(&opts, path, &cf_names)?;

        // Get handles to all column families
        let mut cfs = Vec::with_capacity(num_shards);
        for i in 0..num_shards {
            let cf_name = format!("shard_{}", i);
            let cf_handle = db.cf_handle(&cf_name)
                .ok_or_else(|| anyhow::anyhow!("Failed to get column family handle for {}", cf_name))?;
            cfs.push(cf_handle);
        }

        Ok(Self {
            db,
            cfs,
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
            Some(&self.cfs[shard_idx])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
}
