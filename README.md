# ParallelJMT

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/jmt.svg)](https://crates.io/crates/jmt)

This repository is a high-performance implementation of [Jellyfish Merkle Tree](https://github.com/diem/diem/tree/main/storage/jellyfish-merkle)
with parallel processing optimizations for multi-core systems. Originally forked from [Penumbra's JMT](https://github.com/penumbra-zone/jmt), which itself was forked from the Diem project.

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
- **TreeCache merging**: Collects and merges nodes from all subtrees to ensure correctness
- **Backward compatible**: Sequential version remains available via feature flags

### Performance Analysis

Based on benchmark tests with MockTreeStore (in-memory storage), parallel optimization provides minimal speedup in memory-only scenarios:

| Batch Size | Sequential | Parallel | Speedup | Distribution |
|-------------|-------------|-----------|----------|--------------|
| 100 keys    | 60.477 µs   | 60.477 µs | 1.00x | Random |
| 1,000 keys  | 643.32 µs    | 638.62 µs | 1.01x | Random |
| 10,000 keys | 6.9972 ms     | 6.9375 ms | 1.01x | Random |
| 100,000 keys| 94.656 ms      | 93.087 ms | 1.02x | Random |

*Data from parallel performance tests on macOS, SHA256 hasher, MockTreeStore*

**Key Findings:**
- Parallel overhead (thread creation, synchronization, data merging) offsets computational gains in memory-only scenarios
- Performance improvements are expected to be more significant with persistent storage (e.g., RocksDB) where I/O latency can be parallelized
- Current threshold of 100 keys may need adjustment for optimal performance

See [docs/PARALLEL_PERFORMANCE_REPORT.md](docs/PARALLEL_PERFORMANCE_REPORT.md) for detailed performance analysis and optimization recommendations.

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

See [docs/PARALLEL_PERFORMANCE_REPORT.md](docs/PARALLEL_PERFORMANCE_REPORT.md) for detailed performance analysis and optimization recommendations.

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
- [Parallel Optimization Plan](docs/PARALLEL_OPTIMIZATION_PLAN.md)
- [Parallel Performance Report](docs/PARALLEL_PERFORMANCE_REPORT.md)
- [Benchmark Baseline Report](docs/BENCHMARK_BASELINE_REPORT.md)

## License

Apache License 2.0

## Acknowledgments

- Original Jellyfish Merkle Tree implementation by [Diem](https://github.com/diem/diem)
- Forked and modified by [Penumbra Labs](https://penumbra.zone) with dependency inlining
- Parallel optimization implementation with TreeCache merging support for multi-core systems

## Contributing

Contributions are welcome! Please see [docs/PARALLEL_OPTIMIZATION_PLAN.md](docs/PARALLEL_OPTIMIZATION_PLAN.md) for ongoing optimization work.

---

**Note**: This is a high-performance implementation of Jellyfish Merkle Tree with parallel processing optimizations. The parallel version ensures correctness through proper TreeCache merging and has been tested with comprehensive test suites. Performance improvements are expected to be more significant with persistent storage backends where I/O latency can be parallelized.
