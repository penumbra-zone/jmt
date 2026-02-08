// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use jmt::mock::MockTreeStore;
use jmt::{JellyfishMerkleTree, KeyHash, OwnedValue};
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

/// Benchmarks sequential vs parallel batch insert operations.
#[cfg(feature = "parallel")]
fn bench_sequential_vs_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_vs_parallel");
    
    for size in [100, 1000, 5000, 10000].iter() {
        let value_set = generate_value_set(0, *size, 32);
        
        // Sequential benchmark (original version)
        group.bench_with_input(BenchmarkId::new("sequential", size), size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set_clone = value_set.clone();
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set_clone],
                        None,
                        1,
                    )
                )
            })
        });
        
        // Parallel benchmark (with parallel optimization)
        group.bench_with_input(BenchmarkId::new("parallel", size), size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set_clone = value_set.clone();
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set_clone],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks sequential batch insert operations (original version).
#[cfg(not(feature = "parallel"))]
fn bench_sequential_vs_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_vs_parallel");
    
    for size in [100, 1000, 5000, 10000].iter() {
        let value_set = generate_value_set(0, *size, 32);
        
        // Sequential benchmark (original version only)
        group.bench_with_input(BenchmarkId::new("sequential", size), size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set_clone = value_set.clone();
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set_clone],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks performance with different tree sizes.
fn bench_performance_by_tree_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_by_tree_size");
    
    let tree_sizes = [1000, 5000, 10000, 50000, 100000];
    let update_size = 1000;
    
    for tree_size in tree_sizes.iter() {
        group.throughput(Throughput::Elements(*tree_size as u64));
        
        group.bench_with_input(BenchmarkId::new("tree_size", tree_size), tree_size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                
                // Create initial tree
                let initial_values = generate_value_set(0, *tree_size, 32);
                black_box(
                    tree.batch_put_value_sets(
                        vec![initial_values],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks batch updates on trees of different sizes.
fn bench_batch_updates_by_tree_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_updates_by_tree_size");
    
    let tree_sizes = [1000, 5000, 10000, 50000, 100000];
    let update_size = 1000;
    
    for tree_size in tree_sizes.iter() {
        group.throughput(Throughput::Elements(update_size as u64));
        
        group.bench_with_input(BenchmarkId::new("tree_size", tree_size), tree_size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                
                // Create initial tree
                let initial_values = generate_value_set(0, *tree_size, 32);
                let _ = tree.batch_put_value_sets(vec![initial_values], None, 1);
                
                // Perform batch update
                let update_values = generate_value_set(*tree_size, update_size, 32);
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

/// Benchmarks performance with different batch sizes.
fn bench_performance_by_batch_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_by_batch_size");
    
    let batch_sizes = [100, 500, 1000, 2000, 5000, 10000];
    
    for batch_size in batch_sizes.iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        
        group.bench_with_input(BenchmarkId::new("batch_size", batch_size), batch_size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set = generate_value_set(0, *batch_size, 32);
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks performance with different value sizes.
fn bench_performance_by_value_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_by_value_size");
    
    let value_sizes = [32, 128, 512, 1024, 4096];
    let batch_size = 1000;
    
    for value_size in value_sizes.iter() {
        group.bench_with_input(BenchmarkId::new("value_size", value_size), value_size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set = generate_value_set(0, batch_size, *value_size);
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

/// Benchmarks performance with different update patterns.
fn bench_performance_by_update_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_by_update_pattern");
    
    let initial_tree_size = 10000;
    let update_size = 1000;
    
    let patterns = [
        ("sequential_insert", "Sequential insert of new keys"),
        ("sequential_update", "Sequential update of existing keys"),
        ("random_insert", "Random insert of new keys"),
        ("random_update", "Random update of existing keys"),
        ("mixed", "Mixed insert and update operations"),
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
                    "sequential_insert" => {
                        // Sequential insert of new keys
                        generate_value_set(initial_tree_size, update_size, 32)
                    }
                    "sequential_update" => {
                        // Sequential update of existing keys
                        generate_value_set(0, update_size, 32)
                    }
                    "random_insert" => {
                        // Random insert of new keys
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        (0..update_size)
                            .map(|i| {
                                let key = format!("new_key_{}", i);
                                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                let mut value = vec![0u8; 32];
                                rng.fill(&mut value[..]);
                                (key_hash, value.into())
                            })
                            .collect()
                    }
                    "random_update" => {
                        // Random update of existing keys
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        (0..update_size)
                            .map(|_| {
                                let key_idx = rng.gen_range(0..initial_tree_size);
                                let key = format!("key_{}", key_idx);
                                let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                let mut value = vec![0u8; 32];
                                rng.fill(&mut value[..]);
                                (key_hash, value.into())
                            })
                            .collect()
                    }
                    _ => {
                        // Mixed insert and update operations
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        (0..update_size)
                            .map(|i| {
                                if rng.gen_bool(0.5) {
                                    // Insert new key
                                    let key = format!("new_key_{}", i);
                                    let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                    let mut value = vec![0u8; 32];
                                    rng.fill(&mut value[..]);
                                    (key_hash, value.into())
                                } else {
                                    // Update existing key
                                    let key_idx = rng.gen_range(0..initial_tree_size);
                                    let key = format!("key_{}", key_idx);
                                    let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
                                    let mut value = vec![0u8; 32];
                                    rng.fill(&mut value[..]);
                                    (key_hash, value.into())
                                }
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

/// Benchmarks memory usage with different batch sizes.
fn bench_memory_usage_by_batch_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage_by_batch_size");
    
    let batch_sizes = [100, 500, 1000, 5000, 10000];
    
    for batch_size in batch_sizes.iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        
        group.bench_with_input(BenchmarkId::new("batch_size", batch_size), batch_size, |b, &_size| {
            b.iter(|| {
                let reader = MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set = generate_value_set(0, *batch_size, 32);
                black_box(
                    tree.batch_put_value_sets(
                        vec![value_set],
                        None,
                        1,
                    )
                )
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_performance_by_tree_size,
    bench_batch_updates_by_tree_size,
    bench_performance_by_batch_size,
    bench_performance_by_value_size,
    bench_performance_by_update_pattern,
    bench_memory_usage_by_batch_size,
    bench_sequential_vs_parallel
);
criterion_main!(benches);
