// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jmt::{KeyHash, OwnedValue, Sha256, Version};
use tempfile::tempdir;

/// Generates a set of key-value pairs with the specified size and value length.
///
/// # Arguments
/// * `size` - The number of key-value pairs to generate.
/// * `value_len` - The length of each value in bytes.
///
/// # Returns
/// A vector of `(KeyHash, OwnedValue)` pairs.
fn generate_value_set(size: usize, value_len: usize) -> Vec<(KeyHash, OwnedValue)> {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let mut value_set = Vec::with_capacity(size);
    
    for i in 0..size {
        let key = format!("key_{}", i);
        let key_hash = KeyHash::with::<Sha256>(key.as_bytes());
        
        let mut value = vec![0u8; value_len];
        rng.fill(&mut value[..]);
        
        value_set.push((key_hash, value.into()));
    }
    
    value_set
}

/// Benchmarks parallel vs sequential operations.
///
/// # Arguments
/// * `c` - The criterion benchmark group.
fn bench_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_operations");
    
    // Test different batch sizes
    for size in [100, 1000, 5000].iter() {
        // Generate test data
        let value_set = generate_value_set(*size, 32);
        
        // Benchmark with in-memory MockTreeStore
        group.bench_with_input(criterion::BenchmarkId::new("mock_store", size), size, |b, &_size| {
            b.iter(|| {
                let reader = jmt::mock::MockTreeStore::default();
                let tree = jmt::JellyfishMerkleTree::<_, Sha256>::new(&reader);
                let value_set_clone = value_set.clone();
                let _ = black_box(
                    tree.batch_put_value_sets(
                        vec![value_set_clone],
                        None,
                        1,
                    )
                );
            })
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_parallel_operations);
criterion_main!(benches);
