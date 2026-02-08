#![cfg(all(feature = "rocksdb", feature = "mocks"))]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use jmt::{JellyfishMerkleTree, RocksDBShardedTreeStore, ShardedTreeReaderAdapter};
use sha2::Sha256;
use tempfile::tempdir;

mod common;
use common::*;

fn bench_rocksdb_vs_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("rocksdb_vs_memory");
    
    for size in [100, 1000, 10000].iter() {
        let value_set = generate_value_set_with_distribution(*size, 32, KeyDistribution::Random);
        
        // Benchmark with in-memory MockTreeStore
        group.bench_with_input(BenchmarkId::new("mock_store", size), size, |b, &_size| {
            b.iter(|| {
                let reader = jmt::mock::MockTreeStore::default();
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
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
        
        // Benchmark with RocksDB sharded store
        group.bench_with_input(BenchmarkId::new("rocksdb_sharded", size), size, |b, &_size| {
            b.iter(|| {
                // Create a temporary directory for RocksDB
                let temp_dir = tempdir().expect("Failed to create temp dir");
                let path = temp_dir.path().to_str().expect("Invalid temp dir path");
                
                // Create RocksDB sharded store
                let store = RocksDBShardedTreeStore::new(path, 16).expect("Failed to create RocksDB store");
                let adapter = ShardedTreeReaderAdapter::new(store);
                
                // Create tree with RocksDB store
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&adapter);
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

fn bench_rocksdb_shard_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("rocksdb_shard_count");
    
    let value_set = generate_value_set_with_distribution(10000, 32, KeyDistribution::Random);
    
    for shard_count in [4, 8, 16, 32].iter() {
        group.bench_with_input(BenchmarkId::new("shard_count", shard_count), shard_count, |b, &count| {
            b.iter(|| {
                // Create a temporary directory for RocksDB
                let temp_dir = tempdir().expect("Failed to create temp dir");
                let path = temp_dir.path().to_str().expect("Invalid temp dir path");
                
                // Create RocksDB sharded store with specified shard count
                let store = RocksDBShardedTreeStore::new(path, count).expect("Failed to create RocksDB store");
                let adapter = ShardedTreeReaderAdapter::new(store);
                
                // Create tree with RocksDB store
                let tree = JellyfishMerkleTree::<_, Sha256>::new(&adapter);
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

fn bench_rocksdb_read_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("rocksdb_read_performance");
    
    // Generate a value set and store it in RocksDB
    let value_set = generate_value_set_with_distribution(10000, 32, KeyDistribution::Random);
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let path = temp_dir.path().to_str().expect("Invalid temp dir path");
    
    // Create and populate RocksDB store
    let store = RocksDBShardedTreeStore::new(path, 16).expect("Failed to create RocksDB store");
    let adapter = ShardedTreeReaderAdapter::new(store);
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&adapter);
    let _ = tree.batch_put_value_sets(
        vec![value_set.clone()],
        None,
        1,
    );
    
    // Extract keys for reading
    let keys: Vec<_> = value_set.iter().map(|(k, _)| *k).collect();
    
    // Benchmark random reads
    group.bench_function("random_reads", |b| {
        b.iter(|| {
            for key in keys.iter().take(100) {
                let _ = black_box(tree.get(*key, 1));
            }
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_rocksdb_vs_memory,
    bench_rocksdb_shard_count,
    bench_rocksdb_read_performance
);
criterion_main!(benches);