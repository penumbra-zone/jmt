#![cfg(feature = "parallel")]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use jmt::mock::MockTreeStore;
use jmt::JellyfishMerkleTree;
use sha2::Sha256;

mod common;
use common::*;

fn bench_random_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_distribution");
    
    for size in [100, 1000, 10000, 100000].iter() {
        let value_set = generate_value_set_with_distribution(*size, 32, KeyDistribution::Random);
        let distribution = compute_key_distribution(&value_set);
        
        println!("Random distribution for size {}: {:?}", size, distribution);
        
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

fn bench_concentrated_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("concentrated_distribution");
    
    for size in [100, 1000, 10000].iter() {
        let value_set = generate_concentrated_keys(*size, 32, 2);
        let distribution = compute_key_distribution(&value_set);
        
        println!("Concentrated distribution for size {}: {:?}", size, distribution);
        
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

fn bench_sparse_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_distribution");
    
    for size in [100, 1000, 10000].iter() {
        let value_set = generate_sparse_keys(*size, 32);
        let distribution = compute_key_distribution(&value_set);
        
        println!("Sparse distribution for size {}: {:?}", size, distribution);
        
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

fn bench_value_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_sizes");
    
    for value_size in [32, 128, 512, 2048].iter() {
        let value_set = generate_value_set(1000, *value_size);
        
        group.bench_with_input(BenchmarkId::new("sequential", value_size), value_size, |b, &_value_size| {
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

fn bench_warmup_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("warmup_comparison");
    
    let value_set = generate_value_set(10000, 32);
    
    group.bench_function("cold_start", |b| {
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
    
    group.bench_function("warm_start", |b| {
        let reader = MockTreeStore::default();
        let tree = JellyfishMerkleTree::<_, Sha256>::new(&reader);
        let _ = tree.batch_put_value_sets(
            vec![value_set.clone()],
            None,
            1,
        );
        
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
    
    group.finish();
}

criterion_group!(
    benches,
    bench_random_distribution,
    bench_concentrated_distribution,
    bench_sparse_distribution,
    bench_value_sizes,
    bench_warmup_comparison
);
criterion_main!(benches);
