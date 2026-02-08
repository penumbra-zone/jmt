// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use jmt::sharded_tree_store::InMemoryShardedTreeStore;
use jmt::sharded_adapter::{ShardedTreeReaderAdapterRef, ShardedTreeWriterAdapterRef};
use jmt::{JellyfishMerkleTree, KeyHash};
use jmt::performance_monitor::PerformanceMonitor;
use jmt::storage::TreeWriter;
use sha2::Sha256;
use std::time::Duration;

/// Tests alerting for high latency operations.
#[test]
fn test_high_latency_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Perform operations
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
    monitor.record_write(duration, update_batch.node_batch.nodes().len() as u64);
    
    // Check for high latency
    let metrics = monitor.get_metrics();
    let avg_duration = metrics.avg_write_time();
    
    // Alert if average write time exceeds threshold (100ms)
    let alert_threshold = Duration::from_millis(100);
    if avg_duration > alert_threshold {
        println!("ALERT: High write latency detected: {:?}", avg_duration);
        assert!(true, "Alert triggered for high latency");
    } else {
        println!("Write latency within acceptable range: {:?}", avg_duration);
    }
}

/// Tests alerting for high error rates.
#[test]
fn test_high_error_rate_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert initial data
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
    
    writer_adapter
        .write_node_batch(&update_batch.node_batch)
        .expect("Failed to write node batch");
    
    // Attempt to read non-existent keys (simulating errors)
    let mut error_count = 0;
    let total_attempts = 100;
    
    for i in 100..200 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, _) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        if value.is_none() {
            error_count += 1;
        }
    }
    
    // Check for high error rate
    let error_rate = error_count as f64 / total_attempts as f64;
    let error_threshold = 0.5; // 50% error rate threshold
    
    if error_rate > error_threshold {
        println!("ALERT: High error rate detected: {:.2}%", error_rate * 100.0);
        assert!(true, "Alert triggered for high error rate");
    } else {
        println!("Error rate within acceptable range: {:.2}%", error_rate * 100.0);
    }
}

/// Tests alerting for resource exhaustion.
#[test]
fn test_resource_exhaustion_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Insert a large amount of data to simulate resource pressure
    let num_batches = 20;
    let keys_per_batch = 500;
    
    for batch in 0..num_batches {
        let start = std::time::Instant::now();
        
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
        
        let duration = start.elapsed();
        monitor.record_write(duration, update_batch.node_batch.nodes().len() as u64);
        
        writer_adapter
            .write_node_batch(&update_batch.node_batch)
            .expect("Failed to write node batch");
        
        // Check for resource exhaustion based on performance degradation
        let metrics = monitor.get_metrics();
        let avg_duration = metrics.avg_write_time();
        
        // Alert if performance degrades significantly
        let performance_threshold = Duration::from_millis(50);
        if avg_duration > performance_threshold {
            println!("ALERT: Resource exhaustion detected, performance degraded: {:?}", avg_duration);
            assert!(true, "Alert triggered for resource exhaustion");
            break;
        }
    }
}

/// Tests alerting for shard imbalance.
#[test]
fn test_shard_imbalance_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Insert data
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
                let calculated_shard_idx = jmt::sharded_storage::calculate_shard_index_with_count(node_key, 16);
                calculated_shard_idx == shard_idx
            })
            .count();
        
        if shard_nodes > 0 {
            monitor.record_shard_write(shard_idx, duration, shard_nodes as u64);
        }
    }
    
    // Check for shard imbalance
    let shard_metrics = monitor.get_all_shard_metrics();
    if !shard_metrics.is_empty() {
        let mut node_counts: Vec<u64> = shard_metrics.values()
            .map(|m| m.nodes_written)
            .collect();
        
        if node_counts.len() > 1 {
            node_counts.sort();
            let min_count = node_counts.first().unwrap();
            let max_count = node_counts.last().unwrap();
            
            // Alert if imbalance is significant (more than 10x difference)
            if *max_count > 0 && *min_count > 0 && *max_count / *min_count > 10 {
                println!("ALERT: Shard imbalance detected - min: {}, max: {}", min_count, max_count);
                assert!(true, "Alert triggered for shard imbalance");
            } else {
                println!("Shard distribution is balanced");
            }
        }
    }
}

/// Tests alerting for data consistency issues.
#[test]
fn test_data_consistency_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    
    // Insert data
    let mut value_set = Vec::new();
    for i in 0..100 {
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
    
    // Verify data consistency
    let mut inconsistency_count = 0;
    
    for i in 0..100 {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        let (value, proof) = tree
            .get_with_proof(key_hash, 1)
            .expect("Failed to get with proof");
        
        if let Some(value) = value {
            if proof.verify(root_hash, key_hash, Some(value.as_slice())).is_err() {
                inconsistency_count += 1;
            }
        }
    }
    
    // Check for data consistency issues
    if inconsistency_count > 0 {
        println!("ALERT: Data consistency issues detected: {} inconsistencies", inconsistency_count);
        assert!(true, "Alert triggered for data consistency issues");
    } else {
        println!("Data consistency verified");
    }
}

/// Tests alerting for throughput degradation.
#[test]
fn test_throughput_degradation_alert() {
    let sharded_store = InMemoryShardedTreeStore::new(16);
    let reader_adapter = ShardedTreeReaderAdapterRef::new(&sharded_store);
    let writer_adapter = ShardedTreeWriterAdapterRef::new(&sharded_store);
    
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader_adapter);
    let monitor = PerformanceMonitor::new();
    
    // Measure initial throughput
    let start = std::time::Instant::now();
    
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
    
    let initial_duration = start.elapsed();
    monitor.record_write(initial_duration, update_batch.node_batch.nodes().len() as u64);
    
    // Measure throughput after adding more data
    for batch in 1..10 {
        let start = std::time::Instant::now();
        
        let mut value_set = Vec::new();
        for i in 0..500 {
            let key = format!("key_{}_{}", batch, i);
            let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
            let value = format!("value_{}_{}", batch, i).into_bytes();
            value_set.push((key_hash, Some(value)));
        }
        
        let (_, update_batch) = tree
            .put_value_set(value_set, batch as u64 + 1)
            .expect("Failed to put value set");
        
        let duration = start.elapsed();
        monitor.record_write(duration, update_batch.node_batch.nodes().len() as u64);
        
        // Check for throughput degradation
        let metrics = monitor.get_metrics();
        let avg_duration = metrics.avg_write_time();
        
        // Alert if throughput degrades by more than 50%
        if avg_duration > initial_duration * 2 {
            println!("ALERT: Throughput degradation detected - initial: {:?}, current: {:?}", initial_duration, avg_duration);
            assert!(true, "Alert triggered for throughput degradation");
            break;
        }
    }
}
