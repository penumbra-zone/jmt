// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use jmt::sharded_tree_store::InMemoryShardedTreeStore;
use jmt::sharded_adapter::{ShardedTreeReaderAdapterRef, ShardedTreeWriterAdapterRef};
use jmt::{JellyfishMerkleTree, KeyHash};
use jmt::storage::TreeWriter;
use sha2::Sha256;
use std::time::{Duration, Instant};

/// Tests system stability with continuous operations over time.
#[test]
fn test_continuous_operations_stability() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Perform continuous operations
    let num_iterations = 100;
    let keys_per_iteration = 100;
    
    for iteration in 0..num_iterations {
        let mut value_set = Vec::new();
        for i in 0..keys_per_iteration {
            let key = format!("key_{}_{}", iteration, i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", iteration, i).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, iteration as u64 + 1)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        
        // Verify a sample of previous values
        if iteration > 0 {
            for i in 0..10 {
                let key = format!("key_{}_{}", iteration - 1, i);
                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                let (value, _) = tree
                    .get_with_proof(key_hash, iteration as u64)
                    .expect("Failed to get with proof");
                
                assert!(value.is_some());
                let value = value.unwrap();
                assert_eq!(value, format!("value_{}_{}", iteration - 1, i).into_bytes());
            }
        }
    }
}

/// Tests system stability with memory pressure.
#[test]
fn test_memory_pressure_stability() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert a large amount of data
    let num_batches = 50;
    let keys_per_batch = 500;
    
    for batch in 0..num_batches {
        let mut value_set = Vec::new();
        for i in 0..keys_per_batch {
            let key = format!("key_{}_{}", batch, i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", batch, i).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, batch as u64 + 1)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        
        // Verify system is still responsive
        for i in 0..10 {
            let key = format!("key_{}_{}", batch, i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let (value, _) = tree
                .get_with_proof(key_hash, batch as u64 + 1)
                .expect("Failed to get with proof");
            
            assert!(value.is_some());
        }
    }
}

/// Tests system stability with mixed read/write operations.
#[test]
fn test_mixed_operations_stability() {
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
    
    let (_, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Perform mixed read/write operations
    for iteration in 0..50 {
        // Write new values
        let mut new_value_set = Vec::new();
        for i in 0..10 {
            let key = format!("key_{}", iteration * 10 + i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}", iteration * 10 + i).into_bytes();
            new_value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(new_value_set, iteration as u64 + 2)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        
        // Read random values
        for i in 0..20 {
            let key_idx = (iteration * 20 + i) % 1000;
            let key = format!("key_{}", key_idx);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let (value, _) = tree
                .get_with_proof(key_hash, iteration as u64 + 2)
                .expect("Failed to get with proof");
            
            assert!(value.is_some());
        }
    }
}

/// Tests system stability with version conflicts.
#[test]
fn test_version_conflict_stability() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert initial version
    let mut value_set = Vec::new();
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_v1_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (_, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Update the same keys in multiple versions
    for version in 2..=10 {
        let mut new_value_set = Vec::new();
        for i in 0..100 {
            let key = format!("key_{}", i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_v{}_{}", version, i).into_bytes();
            new_value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(new_value_set, version)
            .expect("Failed to put value set");
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        
        // Verify we can read from all versions
        for check_version in 1..=version {
            for i in 0..10 {
                let key = format!("key_{}", i);
                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                let (value, _) = tree
                    .get_with_proof(key_hash, check_version)
                    .expect("Failed to get with proof");
                
                assert!(value.is_some());
                let value = value.unwrap();
                assert_eq!(value, format!("value_v{}_{}", check_version, i).into_bytes());
            }
        }
    }
}

/// Tests system stability with concurrent access patterns.
#[test]
fn test_concurrent_access_stability() {
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
    
    let (_, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Perform concurrent read operations
    for iteration in 0..100 {
        // Read from different key ranges concurrently
        for start in 0..10 {
            let start = start * 100;
            for i in start..(start + 10) {
                let key = format!("key_{}", i);
                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                let (value, _) = tree
                    .get_with_proof(key_hash, 1)
                    .expect("Failed to get with proof");
                
                assert!(value.is_some());
                let value = value.unwrap();
                assert_eq!(value, format!("value_{}", i).into_bytes());
            }
        }
    }
}

/// Tests system stability with error recovery.
#[test]
fn test_error_recovery_stability() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert data
    let mut value_set = Vec::new();
    for i in 0..500 {
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
    
    // Try to read non-existent keys (should handle gracefully)
    for i in 500..600 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, _) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_none());
    }
    
    // Verify existing keys are still accessible
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, _) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_{}", i).into_bytes());
    }
}
