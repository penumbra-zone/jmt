// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "parallel")]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use jmt::mock::MockTreeStore;
use jmt::{JellyfishMerkleTree, KeyHash, OwnedValue, PerformanceMonitor, Timer};
use sha2::Sha256;

/// Generates a set of key-value pairs for benchmarking.
fn generate_value_set(start: usize, size: usize, value_len: usize) -> Vec<(KeyHash, OwnedValue)> {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let mut value_set = Vec::with_capacity(size);
    
    for i in start..(start + size) {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        
        let mut value = vec![0u8; value_len];
        rng.fill(&mut value[..]);
        
        value_set.push((key_hash, value.into()));
    }
    
    value_set
}

/// Benchmarks batch updates on a tree with 100k initial leaf nodes.
fn bench_batch_updates_on_large_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_updates_on_large_tree");
    
    // Initial tree size: 100,000 leaf nodes
    let initial_tree_size = 100_000;
    
    // Update sizes to test
    let update_sizes = [100, 500, 1000, 5000, 10000];
    
    for update_size in update_sizes.iter() {
        group.throughput(Throughput::Elements(*update_size as u64));
        
        // Benchmark batch update operation
        group.bench_with_input(BenchmarkId::new("batch_update", update_size), update_size, |b, &_size| {
            b.iter(|| {
                // Create a fresh tree for each iteration
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                
                // Create initial tree with 100k leaf nodes
                let initial_values = generate_value_set(0, initial_tree_size, 32);
                let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
                
                // Perform batch update
                let update_values = generate_value_set(initial_tree_size, *update_size, 32);
                black_box(
                    tree.batch_put_value_sets(
                        vec![update_values],
                        None,
                        2,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks batch updates with different update patterns on large tree.
fn bench_update_patterns_on_large_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_patterns_on_large_tree");
    
    let initial_tree_size = 100_000;
    let update_size = 1000;
    
    // Test different update patterns
    let patterns = [
        ("sequential_sequential", "Sequential updates to sequential keys"),
        ("sequential_random", "Sequential updates to random keys"),
        ("random_sequential", "Random updates to sequential keys"),
        ("random_random", "Random updates to random keys"),
    ];
    
    for (pattern_name, pattern_desc) in patterns.iter() {
        println!("Testing pattern: {} - {}", pattern_name, pattern_desc);
        
        group.bench_function(*pattern_name, |b| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                
                // Create initial tree
                let initial_values = generate_value_set(0, initial_tree_size, 32);
                let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
                
                // Generate updates based on pattern
                let update_values = match *pattern_name {
                    "sequential_sequential" => {
                        // Sequential updates to sequential keys
                        generate_value_set(initial_tree_size, update_size, 32)
                    }
                    "sequential_random" => {
                        // Sequential updates to random keys
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        (0..update_size)
                            .map(|_| {
                                let key = format!("key_{}", rng.gen_range(0..initial_tree_size));
                                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                let mut value = vec![0u8; 32];
                                rng.fill(&mut value[..]);
                                (key_hash, value.into())
                            })
                            .collect()
                    }
                    "random_sequential" => {
                        // Random updates to sequential keys
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        let base_values = generate_value_set(initial_tree_size, update_size, 32);
                        base_values
                            .into_iter()
                            .map(|(key_hash, value)| {
                                // Randomly decide whether to update or insert
                                if rng.gen_bool(0.5) {
                                    (key_hash, value)
                                } else {
                                    // Generate new key
                                    let key = format!("new_key_{}", rng.gen_range(0..1000000));
                                    let new_key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                    (new_key_hash, value)
                                }
                            })
                            .collect()
                    }
                    _ => {
                        // Random updates to random keys
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        (0..update_size)
                            .map(|_| {
                                let key = format!("key_{}", rng.gen_range(0..initial_tree_size));
                                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                let mut value = vec![0u8; 32];
                                rng.fill(&mut value[..]);
                                (key_hash, value.into())
                            })
                            .collect()
                    }
                };
                
                black_box(
                    tree.batch_put_value_sets(
                        vec![update_values],
                        None,
                        2,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks performance of batch updates with monitoring.
fn bench_batch_updates_with_monitoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_updates_with_monitoring");
    
    let initial_tree_size = 100_000;
    let update_size = 1000;
    
    // Without monitoring
    group.bench_function("without_monitoring", |b| {
        b.iter(|| {
            let reader = MockTreeStore::default();
            let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
            
            // Create initial tree
            let initial_values = generate_value_set(0, initial_tree_size, 32);
            let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
            
            // Perform batch update
            let update_values = generate_value_set(initial_tree_size, update_size, 32);
            black_box(
                tree.batch_put_value_sets(
                    vec![update_values],
                    None,
                    2,
                )
            )
        })
    });
    
    // With monitoring
    group.bench_function("with_monitoring", |b| {
        b.iter(|| {
            let reader = MockTreeStore::default();
            let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
            let monitor = PerformanceMonitor::new();
            
            // Create initial tree
            let initial_values = generate_value_set(0, initial_tree_size, 32);
            let (result, init_duration) = Timer::time(|| {
                tree.batch_put_value_sets(vec![initial_values], None, 1)
            });
            
            if let Ok(_) = result {
                monitor.record_write(init_duration, initial_tree_size as u64);
            }
            
            // Perform batch update
            let update_values = generate_value_set(initial_tree_size, update_size, 32);
            let (result, update_duration) = Timer::time(|| {
                tree.batch_put_value_sets(
                    vec![update_values],
                    None,
                    2,
                )
            });
            
            if let Ok(_) = result {
                monitor.record_write(update_duration, update_size as u64);
            }
            
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmarks memory usage during batch updates on large tree.
fn bench_memory_usage_during_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage_during_updates");
    
    let initial_tree_size = 100_000;
    let update_size = 1000;
    
    // Small updates
    group.bench_function("small_updates", |b| {
        b.iter(|| {
            let reader = MockTreeStore::default();
            let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
            
            // Create initial tree
            let initial_values = generate_value_set(0, initial_tree_size, 32);
            let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
            
            // Perform small batch update
            let update_values = generate_value_set(initial_tree_size, update_size, 32);
            black_box(
                tree.batch_put_value_sets(
                    vec![update_values],
                    None,
                    2,
                )
            )
        })
    });
    
    // Large updates
    group.bench_function("large_updates", |b| {
        b.iter(|| {
            let reader = MockTreeStore::default();
            let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
            
            // Create initial tree
            let initial_values = generate_value_set(0, initial_tree_size, 32);
            let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
            
            // Perform large batch update
            let update_values = generate_value_set(initial_tree_size, update_size * 10, 32);
            black_box(
                tree.batch_put_value_sets(
                    vec![update_values],
                    None,
                    2,
                )
            )
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_batch_updates_on_large_tree,
    bench_update_patterns_on_large_tree,
    bench_batch_updates_with_monitoring,
    bench_memory_usage_during_updates
);
criterion_main!(benches);
