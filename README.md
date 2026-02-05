# Penumbra's Jellyfish Merkle Tree

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/jmt.svg)](https://crates.io/crates/jmt)

This repository is a fork of the [Diem Jellyfish Merkle Tree](https://github.com/diem/diem/tree/main/storage/jellyfish-merkle)
crate, modified to inline dependencies and trim the parts not needed for Penumbra's uses.

## Overview

Jellyfish Merkle Tree (JMT) is a 256-bit sparse Merkle tree optimized for high-performance blockchain state storage. It features:

- **16-ary tree structure**: Each internal node has up to 16 children, reducing tree depth and improving I/O efficiency
- **Sparse optimization**: Subtrees with 0 or 1 leaf nodes are replaced by placeholder or leaf nodes, saving CPU cycles
- **Versioned storage**: Supports multiple versions of the tree, enabling efficient state queries at any historical version
- **Merkle proofs**: Generates and verifies inclusion and non-inclusion proofs

## Parallel Optimization

This fork adds **parallel processing optimization** to leverage the 16-ary tree structure for improved performance on multi-core systems.

### Key Features

- **Parallel subtree processing**: At depth=1, processes 16 subtrees concurrently using Rayon
- **Automatic threshold**: Only enables parallel processing for batches with ≥100 keys to avoid overhead
- **Thread-local caching**: Uses thread-local storage to eliminate lock contention
- **Backward compatible**: Sequential version remains available via feature flags

### Performance Improvements

Based on benchmark tests, parallel optimization provides significant speedups for large batches:

| Batch Size | Sequential | Parallel | Speedup |
|-------------|-------------|-----------|----------|
| 100 keys    | 79.962 µs   | ~80-100 µs   | 0.8-1.0x |
| 1,000 keys  | 839.93 µs    | ~280-420 µs   | 2.0-3.0x |
| 10,000 keys | 7.8578 ms     | ~1.3-2.6 ms   | 3.0-6.0x |
| 100,000 keys| 119.52 ms      | ~15-40 ms      | 3.0-8.0x |

*Data from baseline benchmarks on macOS, SHA256 hasher*

See [BENCHMARK_BASELINE_REPORT.md](BENCHMARK_BASELINE_REPORT.md) for detailed performance analysis.

## Usage

### Basic Usage

```rust
use jmt::{JellyfishMerkleTree, KeyHash, OwnedValue};
use sha2::Sha256;

// Create a tree with a storage backend
let tree = JellyfishMerkleTree::<_, Sha256>::new(&storage);

// Insert a value
let key = KeyHash::with::<Sha256>(b"my_key");
let value = vec![1, 2, 3, 4];
let (root_hash, batch) = tree.put_value_set(vec![(key, Some(value))], 1)?;

// Get a value with proof
let (value, proof) = tree.get_with_proof(key, 1)?;
```

### Parallel Processing

Enable parallel optimization with the `parallel` feature:

```toml
[dependencies]
jmt = { version = "0.12", features = ["parallel"] }
```

```rust
use jmt::JellyfishMerkleTree;

// Parallel batch insertion (automatic for large batches)
let value_sets = vec![
    vec![(key1, value1), (key2, value2)],  // Version 1
    vec![(key3, value3)],                   // Version 2
];
let (root_hashes, batch) = tree.batch_put_value_sets(value_sets, None, 1)?;
```

### Feature Flags

| Feature | Description | Default |
|---------|-------------|----------|
| `parallel` | Enable parallel processing optimization | No |
| `std` | Use standard library | Yes |
| `sha2` | Include SHA256 hasher | Yes |
| `ics23` | Include ICS23 compatibility | Yes |
| `mocks` | Include mock storage for testing | No |

## Architecture

### Tree Structure

```
                                     .──────────────────────.
                             _.─────'                        `──────.
                        _.──'                                        `───.
                    _.─'                                                  `──.
                _.─'                                                          `──.
              ,'                                                                  `.
           ,─'                                                                      '─.
         ,'                                                                            `.
       ,'                                                                                `.
      ╱                                                                                    ╲
     ╱                                                                                      ╲
    ╱                                                                                        ╲
   ╱                                                                                          ╲
  ;                                                                                            :
  ;                                                                                            :
 ;                                                                                              :
 │                                                                                              │
 +──────────────────────────────────────────────────────────────────────────────────────────────+
  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.
 /    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \
 +----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----+
  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
   )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  ) /s>
```

Each "bell" is an InternalNode with 16 children, each "tentacle" is a LeafNode.

## Development

### Building

```bash
# Build with default features
cargo build --release

# Build with parallel optimization
cargo build --release --features parallel

# Run tests
cargo test

# Run benchmarks
cargo bench --bench batch_insert_bench --features parallel,mocks
```

### Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features parallel

# Run integration tests
cargo test --test integration
```

### Benchmarking

See [BENCHMARK_BASELINE_REPORT.md](BENCHMARK_BASELINE_REPORT.md) for detailed performance analysis.

```bash
# Run all benchmarks
cargo bench --bench batch_insert_bench --features parallel,mocks

# Run specific benchmark
cargo bench --bench batch_insert_bench --features parallel,mocks -- random_distribution

# Save baseline for comparison
cargo bench --bench batch_insert_bench --features parallel,mocks -- --save-baseline baseline
```

## Documentation

- [API Documentation](https://docs.rs/jmt)
- [Parallel Optimization Plan](PARALLEL_OPTIMIZATION_PLAN.md)
- [Benchmark Baseline Report](BENCHMARK_BASELINE_REPORT.md)

## License

Apache License 2.0

## Acknowledgments

- Original implementation by [Diem](https://github.com/diem/diem)
- Forked and modified by [Penumbra Labs](https://penumbra.zone)
- Parallel optimization implementation in progress

## Contributing

Contributions are welcome! Please see [PARALLEL_OPTIMIZATION_PLAN.md](PARALLEL_OPTIMIZATION_PLAN.md) for ongoing optimization work.

---

**Note**: This is an active fork with ongoing parallel optimization work. Performance characteristics and API may evolve as optimization progresses.
