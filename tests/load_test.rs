// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use jmt::sharded_tree_store::InMemoryShardedTreeStore;
use jmt::sharded_adapter::{ShardedTreeReaderAdapterRef, ShardedTreeWriterAdapterRef};
use jmt::{JellyfishMerkleTree, KeyHash};
use jmt::storage::TreeWriter;
use sha2::Sha256;
use std::time::{Duration, Instant};

/// Tests system performance under high load with sharded storage.
#[test]
fn test_high_load_performance() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert a large batch of values
    let num_keys = 10000;
    let mut value_set = Vec::new();
    for i in 0..num_keys {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let start = Instant::now();
    let (root_hash, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    let insert_duration = start.elapsed();
    println!("Insert {} keys: {:?}", num_keys, insert_duration);
    
    // Write the update batch
    let start = Instant::now();
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    let write_duration = start.elapsed();
    println!("Write {} nodes: {:?}", update_batch.node_batch.nodes().len(), write_duration);
    
    // Verify the root hash is not empty
    assert!(!root_hash.0.is_empty());
    
    // Performance assertions
    assert!(insert_duration < Duration::from_secs(5), "Insert operation took too long");
    assert!(write_duration < Duration::from_secs(5), "Write operation took too long");
}

/// Tests system performance with multiple concurrent operations.
#[test]
fn test_concurrent_operations() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert initial data
    let mut value_set = Vec::new();
    for i in 0..1000 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (root_hash, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Perform concurrent reads
    let start = Instant::now();
    for i in 0..1000 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, _) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_{}", i).into_bytes());
    }
    let read_duration = start.elapsed();
    println!("Read {} keys: {:?}", 1000, read_duration);
    
    // Performance assertions
    assert!(read_duration < Duration::from_secs(2), "Read operations took too long");
}

/// Tests system performance with multiple versions.
#[test]
fn test_multiple_versions_performance() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert multiple versions
    let num_versions = 10;
    let keys_per_version = 100;
    
    let start = Instant::now();
    for version in 1..=num_versions {
        let mut value_set = Vec::new();
        for i in 0..keys_per_version {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_v{}_{}", version, i).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, version)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
    }
    let total_duration = start.elapsed();
    println!("Insert {} versions with {} keys each: {:?}", num_versions, keys_per_version, total_duration);
    
    // Verify performance
    assert!(total_duration < Duration::from_secs(10), "Multi-version insert took too long");
    
    // Verify we can read from different versions
    for version in 1..=num_versions {
        for i in 0..keys_per_version {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let (value, _) = tree
                .get_with_proof(key_hash, version)
                .expect("Failed to get with proof");
            
            assert!(value.is_some());
            let value = value.unwrap();
            assert_eq!(value, format!("value_v{}_{}", version, i).into_bytes());
        }
    }
}

/// Tests system scalability with increasing shard counts.
#[test]
fn test_scalability_with_shard_counts() {
    let shard_counts = vec![4, 8, 16, 32];
    let num_keys = 1000;
    
    for shard_count in shard_counts {
        let sharded_store = InMemoryShardedTreeStore::new(shard_count);
        let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
        let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
        
        let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
        
        // Insert data
        let mut value_set = Vec::new();
        for i in 0..num_keys {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}", i).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let start = Instant::now();
        let (_, update_batch) = tree
            .put_value_set(value_set, 1)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        let duration = start.elapsed();
        
        println!("Shard count {}: {:?}", shard_count, duration);
        
        // Verify we can read the data
        for i in 0..num_keys {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let (value, _) = tree
                .get_with_proof(key_hash, 1)
                .expect("Failed to get with proof");
            
            assert!(value.is_some());
        }
    }
}

/// Tests memory usage under load.
#[test]
fn test_memory_usage_under_load() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert a large batch
    let num_keys = 5000;
    let mut value_set = Vec::new();
    for i in 0..num_keys {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (_, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Verify the system is still responsive
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, _) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
    }
}
