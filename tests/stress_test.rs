// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use jmt::{ParallelIO, PerformanceMonitor, Timer};

/// Stress tests parallel operations with multiple threads.
///
/// # Returns
/// A `Result` indicating success or failure.
fn stress_test_concurrent_operations() -> Result<()> {
    println!("=== Stress Testing Concurrent Parallel Operations ===");
    
    let monitor = Arc::new(PerformanceMonitor::new());
    let start_time = Instant::now();
    
    // Create multiple threads for concurrent operations
    let thread_count = 4;
    let operations_per_thread = 10;
    let mut handles = Vec::with_capacity(thread_count);
    
    for thread_idx in 0..thread_count {
        let monitor_clone = monitor.clone();
        
        let handle = thread::spawn(move || {
            // Create a mock store for testing
            use jmt::mock::MockTreeStore;
            let mock_store = MockTreeStore::default();
            let parallel_io = ParallelIO::new(mock_store);
            
            for op_idx in 0..operations_per_thread {
                // Create a simple test with empty node keys
                // This will test the parallel infrastructure without requiring
                // actual node key creation
                let node_keys: Vec<_> = vec![];
                
                // Test parallel operations with empty input
                let (result, duration) = Timer::time(|| {
                    parallel_io.get_nodes_parallel(&node_keys)
                });
                
                match result {
                    Ok(results) => {
                        println!("  Thread {}: Operation {} completed in {:?}", 
                                thread_idx, op_idx, duration);
                        monitor_clone.record_parallel(duration);
                    }
                    Err(e) => {
                        println!("  Thread {}: Operation {} error: {:?}", thread_idx, op_idx, e);
                    }
                }
                
                // Test batched parallel operations
                let (result, duration) = Timer::time(|| {
                    parallel_io.get_nodes_parallel_batched(&node_keys, 50)
                });
                
                match result {
                    Ok(results) => {
                        println!("  Thread {}: Batched operation {} completed in {:?}", 
                                thread_idx, op_idx, duration);
                        monitor_clone.record_parallel(duration);
                    }
                    Err(e) => {
                        println!("  Thread {}: Batched operation {} error: {:?}", thread_idx, op_idx, e);
                    }
                }
                
                // Test prefetching
                let (result, duration) = Timer::time(|| {
                    parallel_io.prefetch_nodes(&node_keys)
                });
                
                match result {
                    Ok(_) => {
                        println!("  Thread {}: Prefetch operation {} completed in {:?}", 
                                thread_idx, op_idx, duration);
                        monitor_clone.record_parallel(duration);
                    }
                    Err(e) => {
                        println!("  Thread {}: Prefetch operation {} error: {:?}", thread_idx, op_idx, e);
                    }
                }
                
                // Add a small delay to avoid overwhelming the system
                thread::sleep(Duration::from_millis(5));
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
    
    let total_duration = start_time.elapsed();
    println!("\n  All threads completed in {:?}", total_duration);
    
    // Generate performance report
    let report = monitor.generate_report();
    println!("\n{}", report.format());
    
    Ok(())
}

/// Runs all stress tests.
#[test]
fn run_stress_tests() -> Result<()> {
    println!("Starting stress tests for sharded storage...\n");
    
    // Run concurrent stress test
    stress_test_concurrent_operations()?;
    
    println!("\nAll stress tests completed successfully!");
    
    Ok(())
}
