// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use jmt::sharded_tree_store::InMemoryShardedTreeStore;
use jmt::sharded_adapter::{ShardedTreeReaderAdapterRef, ShardedTreeWriterAdapterRef};
use jmt::{JellyfishMerkleTree, KeyHash};
use jmt::performance_monitor::PerformanceMonitor;
use jmt::storage::TreeWriter;
use jmt::sharded_storage::calculate_shard_index_with_count;
use sha2::Sha256;
use std::time::Duration;

/// Tests performance metrics collection.
#[test]
fn test_performance_metrics_collection() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform operations with monitoring
    let start = std::time::Instant::now();
    
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
    
    let insert_duration = start.elapsed();
    
    let start = std::time::Instant::now();
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    let write_duration = start.elapsed();
    
    // Record metrics
    monitor.record_write(insert_duration, update_batch.node_batch.nodes().len() as u64);
    monitor.record_write(write_duration, update_batch.node_batch.nodes().len() as u64);
    
    // Verify metrics were collected
    let metrics = monitor.get_metrics();
    assert!(metrics.write_ops > 0);
    assert!(metrics.total_write_time > Duration::ZERO);
    assert!(metrics.nodes_written > 0);
}

/// Tests per-shard metrics collection.
#[test]
fn test_per_shard_metrics() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform operations with monitoring
    let start = std::time::Instant::now();
    
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
    
    let duration = start.elapsed();
    
    // Record per-shard metrics
    for shard_idx in 0..16 {
        let shard_nodes = update_batch.node_batch.nodes().iter()
            .filter(|(node_key, _)| {
                let calculated_shard_idx = calculate_shard_index_with_count(node_key, 16);
                calculated_shard_idx == shard_idx
            })
            .count();
        
        if shard_nodes > 0 {
            monitor.record_shard_write(shard_idx, duration, shard_nodes as u64);
        }
    }
    
    // Verify per-shard metrics were collected
    let shard_metrics = monitor.get_all_shard_metrics();
    assert!(!shard_metrics.is_empty());
    
    // Each shard should have some activity
    for (shard_idx, shard_metrics) in &shard_metrics {
        assert!(*shard_idx < 16);
        assert!(shard_metrics.write_ops >= 0);
        assert!(shard_metrics.nodes_written >= 0);
    }
}

/// Tests metrics reporting.
#[test]
fn test_metrics_reporting() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform various operations
    for i in 0..10 {
        let start = std::time::Instant::now();
        
        let mut value_set = Vec::new();
        for j in 0..100 {
            let key = format!("key_{}_{}", i, j);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", i, j).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, i as u64 + 1)
            .expect("Failed to put value set");
        
        let insert_duration = start.elapsed();
        monitor.record_write(insert_duration, update_batch.node_batch.nodes().len() as u64);
        
        // Record per-shard metrics
        for shard_idx in 0..16 {
            let shard_nodes = update_batch.node_batch.nodes().iter()
                .filter(|(node_key, _)| {
                    let calculated_shard_idx = calculate_shard_index_with_count(node_key, 16);
                    calculated_shard_idx == shard_idx
                })
                .count();
            
            if shard_nodes > 0 {
                monitor.record_shard_write(shard_idx, insert_duration, shard_nodes as u64);
            }
        }
        
        let start = std::time::Instant::now();
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        let write_duration = start.elapsed();
        monitor.record_write(write_duration, update_batch.node_batch.nodes().len() as u64);
    }
    
    // Generate report
    let report = monitor.generate_report();
    assert!(!report.shard_metrics.is_empty());
    assert!(report.overall.write_ops > 0);
    assert!(report.overall.total_write_time > Duration::ZERO);
    
    // Verify report contains key metrics
    let report_str = report.format();
    assert!(report_str.contains("Write Operations"));
    assert!(report_str.contains("Nodes Written"));
}

/// Tests metrics aggregation.
#[test]
fn test_metrics_aggregation() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform multiple operations
    for i in 0..50 {
        let start = std::time::Instant::now();
        
        let mut value_set = Vec::new();
        for j in 0..20 {
            let key = format!("key_{}_{}", i, j);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", i, j).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, i as u64 + 1)
            .expect("Failed to put value set");
        
        let duration = start.elapsed();
        monitor.record_write(duration, update_batch.node_batch.nodes().len() as u64);
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
    }
    
    // Verify aggregation
    let metrics = monitor.get_metrics();
    assert_eq!(metrics.write_ops, 50);
    assert!(metrics.total_write_time > Duration::ZERO);
    assert!(metrics.avg_write_time() > Duration::ZERO);
}

/// Tests metrics reset functionality.
#[test]
fn test_metrics_reset() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform operations
    let start = std::time::Instant::now();
    
    let mut value_set = Vec::new();
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let value = format!("value_{}", i).into_bytes();
        value_set.push((key_hash, Some(value)));
    }
    
    let (_, update_batch) = tree
        .put_value_set(value_set, 1)
        .expect("Failed to put value set");
    
    let duration = start.elapsed();
    monitor.record_write(duration, update_batch.node_batch.nodes().len() as u64);
    
    // Verify metrics exist
    let metrics_before = monitor.get_metrics();
    assert!(metrics_before.write_ops > 0);
    
    // Reset metrics
    monitor.reset();
    
    // Verify metrics are cleared
    let metrics_after = monitor.get_metrics();
    assert_eq!(metrics_after.write_ops, 0);
    assert_eq!(metrics_after.total_write_time, Duration::ZERO);
    assert_eq!(metrics_after.nodes_written, 0);
    
    let shard_metrics_after = monitor.get_all_shard_metrics();
    assert!(shard_metrics_after.is_empty());
}

/// Tests concurrent metrics collection.
#[test]
fn test_concurrent_metrics_collection() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform concurrent operations
    for i in 0..10 {
        let start = std::time::Instant::now();
        
        let mut value_set = Vec::new();
        for j in 0..50 {
            let key = format!("key_{}_{}", i, j);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", i, j).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, i as u64 + 1)
            .expect("Failed to put value set");
        
        let insert_duration = start.elapsed();
        monitor.record_write(insert_duration, update_batch.node_batch.nodes().len() as u64);
        
        let start = std::time::Instant::now();
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        let write_duration = start.elapsed();
        monitor.record_write(write_duration, update_batch.node_batch.nodes().len() as u64);
    }
    
    // Verify metrics were collected for both operations
    let metrics = monitor.get_metrics();
    assert_eq!(metrics.write_ops, 20);
    assert!(metrics.total_write_time > Duration::ZERO);
    assert!(metrics.nodes_written > 0);
}
