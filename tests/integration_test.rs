// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use jmt::mock::MockTreeStore;
use jmt::sharded_tree_store::{InMemoryShardedTreeStore, MockShardedTreeStore};
use jmt::sharded_adapter::{ShardedTreeReaderAdapterRef, ShardedTreeWriterAdapterRef};
use jmt::{JellyfishMerkleTree, KeyHash};
use jmt::storage::{TreeReader, TreeWriter};
use sha2::Sha256;

/// Tests end-to-end integration of sharded storage with JMT.
#[test]
fn test_end_to_end_sharded_integration() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert some values
    let mut value_set = Vec::new();
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
            value_set.push((key_hash, value));
    }
    
    let (root_hashes, update_batch) = tree
        .batch_put_value_sets(vec![value_set], None, 1)
        .expect("Failed to put value sets");
    
    assert_eq!(root_hashes.len(), 1);
    // Verify the root hash is not empty
    assert!(!root_hashes[0].0.is_empty());
    
    // Write the update batch
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Verify that we can retrieve the values
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, proof) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_{}", i).into_bytes());
        assert!(proof.verify(root_hashes[0], key_hash, Some(value.as_slice())).is_ok());
    }
}

/// Tests compatibility of sharded storage with existing JMT API.
#[test]
fn test_api_compatibility() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Test put_value_set
    let mut value_set = Vec::new();
    for i in 0..10 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (root_hash, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    // Verify the root hash is not empty
    assert!(!root_hash.0.is_empty());
    
    // Write the update batch
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Test get_with_proof
    let key = format!("key_5");
    let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
    let (value, proof) = tree
        .get_with_proof(key_hash, 1)
        .expect("Failed to get with proof");
    
    assert!(value.is_some());
    let value = value.unwrap();
    assert_eq!(value, format!("value_5").into_bytes());
    assert!(proof.verify(root_hash, key_hash, Some(value.as_slice())).is_ok());
}

/// Tests backward compatibility with non-sharded storage.
#[test]
fn test_backward_compatibility() {
    // Test with non-sharded storage
    let mock_store = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&mock_store);
    
    let mut value_set = Vec::new();
    for i in 0..10 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (root_hash, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    mock_store
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Test with sharded storage
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    let mut value_set = Vec::new();
    for i in 0..10 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (root_hash_sharded, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Both should produce the same root hash
    assert_eq!(root_hash, root_hash_sharded);
}

/// Tests multiple versions with sharded storage.
#[test]
fn test_multiple_versions_sharded() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert first version
    let mut value_set_v1 = Vec::new();
    for i in 0..10 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_v1_{}", i).into_bytes();
        value_set_v1.push((key_hash, Some(value)));
    }
    
    let (root_hash_v1, update_batch_v1) = tree
        .put_value_set(value_set_v1, 1)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch_v1.node_batch)
        .expect("Failed to write node batch");
    
    // Insert second version
    let mut value_set_v2 = Vec::new();
    for i in 5..15 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_v2_{}", i).into_bytes();
        value_set_v2.push((key_hash, Some(value)));
    }
    
    let (root_hash_v2, update_batch_v2) = tree
        .put_value_set(value_set_v2, 2)
        .expect("Failed to put value set");
    
    writer_adapter
        .write_node_batch(&update_batch_v2.node_batch)
        .expect("Failed to write node batch");
    
    // Verify version 1
    let key = format!("key_5");
    let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
    let (value_v1, _) = tree
        .get_with_proof(key_hash, 1)
        .expect("Failed to get with proof");
    
    assert!(value_v1.is_some());
    let value_v1 = value_v1.unwrap();
    assert_eq!(value_v1, format!("value_v1_5").into_bytes());
    
    // Verify version 2
    let (value_v2, _) = tree
        .get_with_proof(key_hash, 2)
        .expect("Failed to get with proof");
    
    assert!(value_v2.is_some());
    let value_v2 = value_v2.unwrap();
    assert_eq!(value_v2, format!("value_v2_5").into_bytes());
    
    // Root hashes should be different
    assert_ne!(root_hash_v1, root_hash_v2);
}

/// Tests large batch operations with sharded storage.
#[test]
fn test_large_batch_operations_sharded() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert a large batch
    let mut value_set = Vec::new();
    for i in 0..10000 {
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
    
    // Verify some random values
    let test_indices = [0, 100, 1000, 5000, 9999];
    for i in test_indices {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, proof) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_{}", i).into_bytes());
        assert!(proof.verify(root_hash, key_hash, Some(value.as_slice())).is_ok());
    }
}

/// Tests parallel operations with sharded storage.
#[test]
fn test_parallel_operations_sharded() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert multiple versions in parallel
    let mut value_sets = Vec::new();
    for version in 1..=10 {
        let mut value_set = Vec::new();
        for i in 0..100 {
            let key = format!("key_{}_v{}", i, version);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_v{}", i, version).into_bytes();
            value_set.push((key_hash, value));
        }
        value_sets.push(value_set);
    }
    
    let (root_hashes, update_batch) = tree
        .batch_put_value_sets(value_sets, None, 1)
        .expect("Failed to put value sets");
    
    assert_eq!(root_hashes.len(), 10);
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Verify all versions
    for version in 1..=10 {
        let key = format!("key_50_v{}", version);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, proof) = tree
            .get_with_proof(key_hash, version)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_50_v{}", version).into_bytes());
        assert!(proof.verify(root_hashes[version as usize - 1], key_hash, Some(value.as_slice())).is_ok());
    }
}

/// Tests mock sharded tree store.
#[test]
fn test_mock_sharded_tree_store() {
    let mut sharded_store = MockShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert some values
    let mut value_set = Vec::new();
    for i in 0..50 {
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
    
    // Verify that we can retrieve values
    for i in 0..50 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, proof) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        assert!(value.is_some());
        let value = value.unwrap();
        assert_eq!(value, format!("value_{}", i).into_bytes());
        assert!(proof.verify(root_hash, key_hash, Some(value.as_slice())).is_ok());
    }
}
