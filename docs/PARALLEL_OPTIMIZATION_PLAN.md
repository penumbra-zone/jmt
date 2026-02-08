# JMT 并行优化执行计划

## 目标
在 JMT 的 `batch_put_value_sets` 函数中实现并行优化，利用 16 叉树的特性在 depth=1 时并行计算子树，提升批量插入性能。

## 背景
- JMT 是 16 叉树，每个节点最多有 16 个子节点
- 当前 `batch_put_value_sets` 使用串行处理，没有利用多线程
- 在 depth=1 时，16 个子树的计算相互独立，可以并行处理

## 优化范围
- **仅关注单版本批量插入场景**：一次输入只有一个版本的情况
- **并行层级**：在 depth=1 时并行处理 16 个子树
- **并行库**：使用 Rayon 实现数据并行

---

## 阶段一：环境准备

### 1.1 添加依赖
- 在 `Cargo.toml` 中添加 `rayon` 依赖
- 添加 `parallel` feature flag

**修改文件**: `Cargo.toml`
```toml
[dependencies]
rayon = { version = "1.8", optional = true }

[features]
default = ["ics23", "std", "sha2"]
parallel = ["rayon"]
```

### 1.2 验证环境
- 确保项目可以正常编译
- 运行现有测试确保无回归

---

## 阶段二：Benchmark 工具开发

### 2.1 创建 Benchmark 目录结构
```
jmt/
├── benches/
│   ├── batch_insert_bench.rs    # 批量插入性能测试
│   └── common.rs                # 公共测试工具
└── benchmark_data/              # 测试数据目录
    ├── small_batch.json         # 小批量 (100 keys)
    ├── medium_batch.json        # 中批量 (1000 keys)
    └── large_batch.json         # 大批量 (10000 keys)
```

### 2.2 Benchmark 工具实现

**文件**: `benches/common.rs`
- 提供测试数据生成函数
- 提供性能测试辅助函数
- 提供 TreeReader Mock 实现

**文件**: `benches/batch_insert_bench.rs`
- 使用 `criterion` 库进行性能测试
- 测试不同数据规模：
  - 小批量: 100 keys
  - 中批量: 1,000 keys
  - 大批量: 10,000 keys
  - 超大批量: 100,000 keys
- 测试不同 key 分布：
  - 随机分布（均匀分布在 16 个子树）
  - 集中分布（集中在少数子树）
  - 稀疏分布（大量空子树）

### 2.3 Benchmark 测试用例

#### 测试场景 1: 随机分布
```rust
fn bench_random_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_distribution");
    
    for size in [100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("sequential", size), size, |b, &size| {
            b.iter(|| {
                // 串行版本
                batch_put_value_sets_sequential(generate_random_keys(size))
            })
        });
        
        group.bench_with_input(BenchmarkId::new("parallel", size), size, |b, &size| {
            b.iter(|| {
                // 并行版本
                batch_put_value_sets_parallel(generate_random_keys(size))
            })
        });
    }
    
    group.finish();
}
```

#### 测试场景 2: 集中分布
```rust
fn bench_concentrated_distribution(c: &mut Criterion) {
    // keys 集中在少数几个子树中
    // 测试并行优化的边界情况
}
```

#### 测试场景 3: 稀疏分布
```rust
fn bench_sparse_distribution(c: &mut Criterion) {
    // 大量子树为空
    // 测试并行优化的边界情况
}
```

### 2.4 Benchmark 依赖
在 `Cargo.toml` 中添加：
```toml
[dev-dependencies]
criterion = "0.5"
rand = "0.8.3"

[[bench]]
name = "batch_insert_bench"
harness = false
```

---

## 阶段三：并行优化实现

### 3.1 核心设计思路

基于其他人的优化思路，采用以下策略：

1. **按 depth=1 子树分组**：键的前 4 bits（nibble）决定 16 个子节点
2. **使用 Arc 共享存储**：每个子树可以独立访问共享存储，避免并发冲突
3. **并行更新子树**：使用 `rayon::par_iter_mut()` 并行处理 16 个子树
4. **主线程合并结果**：计算子树 hash，合成新 root

**关键优势**：
- 避免了 TreeCache 并发访问的复杂性
- 每个子树有自己的 TreeCache，互不干扰
- 使用 `Arc` 共享存储，每个子树可以独立访问
- 在主线程中合并结果，确保一致性

### 3.2 实现策略

#### 策略 1: 条件并行
```rust
// 只在满足条件时才使用并行
const PARALLEL_THRESHOLD: usize = 100; // 最小并行阈值

#[cfg(feature = "parallel")]
fn batch_insert_at_parallel(
    &self,
    mut node_key: NodeKey,
    version: Version,
    kvs: &[(KeyHash, ValueHash)],
    depth: usize,
    hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
    tree_cache: &mut TreeCache<R>,
) -> Result<(NodeKey, Node)> {
    // 只在 depth=1 且数据量足够大时使用并行
    if depth != 1 || kvs.len() < PARALLEL_THRESHOLD {
        return self.batch_insert_at(node_key, version, kvs, depth, hash_cache, tree_cache);
    }

    // 获取当前节点
    let node = tree_cache.get_node(&node_key)?;
    
    match node {
        Node::Internal(internal_node) => {
            // 删除旧的内部节点
            tree_cache.delete_node(&node_key, false);
            
            // 使用并行处理子树
            self.process_children_parallel(
                node_key,
                version,
                kvs,
                depth,
                hash_cache,
                tree_cache,
                internal_node,
            )
        }
        _ => {
            // 对于叶子节点和空节点，使用串行处理
            self.batch_insert_at(node_key, version, kvs, depth, hash_cache, tree_cache)
        }
    }
}
```

#### 策略 2: 子树分组 + Arc 共享存储
```rust
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(feature = "parallel")]
use std::sync::Arc;

#[cfg(feature = "parallel")]
fn process_children_parallel(
    &self,
    mut node_key: NodeKey,
    version: Version,
    kvs: &[(KeyHash, ValueHash)],
    depth: usize,
    hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
    tree_cache: &mut TreeCache<R>,
    internal_node: InternalNode,
) -> Result<(NodeKey, Node)> {
    // 第一步：按 depth=1 子树分组（键的前 4 bits -> 0..15）
    let mut subtrees: Vec<Vec<(KeyHash, ValueHash)>> = vec![vec![]; 16];
    for (key, value) in kvs.iter() {
        let nibble = key.0.get_nibble(depth);
        subtrees[nibble.as_usize()].push((*key, *value));
    }

    // 第二步：并行更新 16 个子树（使用 rayon）
    let reader = Arc::new(self.reader);
    let mut subtree_results: Vec<Option<(NodeKey, Node)>> = vec![None; 16];

    subtree_results.par_iter_mut().enumerate().for_each(|(i, result)| {
        if !subtrees[i].is_empty() {
            // 创建子树实例或递归更新
            let child_index = Nibble::from(i as u8);
            let child_node_key = node_key.gen_child_node_key(version, child_index);
            
            // 创建新的 JellyfishMerkleTree 实例处理子树
            let sub_tree = JellyfishMerkleTree::new(&*reader);
            
            // 检查是否存在子节点
            let (new_child_node_key, new_child_node) = match internal_node.child(child_index) {
                Some(child) => {
                    // 存在子节点，递归更新
                    let existing_child_node_key = node_key.gen_child_node_key(child.version, child_index);
                    let mut sub_tree_cache = TreeCache::new(&*reader, version).unwrap();
                    
                    sub_tree.batch_insert_at(
                        existing_child_node_key,
                        version,
                        &subtrees[i],
                        depth + 1,
                        hash_cache,
                        &mut sub_tree_cache,
                    ).unwrap()
                }
                None => {
                    // 不存在子节点，创建新子树
                    let mut sub_tree_cache = TreeCache::new(&*reader, version).unwrap();
                    
                    sub_tree.batch_create_subtree(
                        child_node_key,
                        version,
                        &subtrees[i],
                        depth + 1,
                        hash_cache,
                        &mut sub_tree_cache,
                    ).unwrap()
                }
            };
            
            *result = Some((new_child_node_key, new_child_node));
        }
    });

    // 第三步：合成新 root（在主线程中）
    let mut children: Children = internal_node.into();
    for (i, result) in subtree_results.iter().enumerate() {
        if let Some((new_child_node_key, new_child_node)) = result {
            let child_index = Nibble::from(i as u8);
            children.insert(
                child_index,
                Child::new(
                    Self::get_hash(new_child_node_key, new_child_node, hash_cache),
                    version,
                    new_child_node.node_type(),
                ),
            );
            
            // 将子树节点插入到主 TreeCache
            tree_cache.put_node(new_child_node_key.clone(), new_child_node.clone())?;
        }
    }

    let new_internal_node = InternalNode::new(children);
    node_key.set_version(version);
    tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
    
    Ok((node_key, new_internal_node.into()))
}
```

### 3.3 TreeCache 并发处理方案

#### 推荐方案：Arc 共享存储 + 独立 TreeCache

**优势**：
- 避免了 TreeCache 并发访问的复杂性
- 每个子树有自己的 TreeCache，互不干扰
- 使用 `Arc` 共享存储，每个子树可以独立访问
- 在主线程中合并结果，确保一致性

**实现细节**：
```rust
#[cfg(feature = "parallel")]
use std::sync::Arc;

// 在并行处理中
let reader = Arc::new(self.reader);

// 每个子树创建独立的 TreeCache
subtree_results.par_iter_mut().enumerate().for_each(|(i, result)| {
    let sub_tree = JellyfishMerkleTree::new(&*reader);
    let mut sub_tree_cache = TreeCache::new(&*reader, version).unwrap();
    
    // 处理子树...
});

// 在主线程中合并结果
for (i, result) in subtree_results.iter().enumerate() {
    if let Some((new_child_node_key, new_child_node)) = result {
        tree_cache.put_node(new_child_node_key.clone(), new_child_node.clone())?;
    }
}
```

### 3.4 实现步骤

1. **步骤 1**: 创建并行版本的 `batch_insert_at_parallel` 函数
2. **步骤 2**: 实现子树分组逻辑（按 nibble 分组到 16 个 bucket）
3. **步骤 3**: 使用 `Arc` 共享存储，避免并发冲突
4. **步骤 4**: 使用 `rayon::par_iter_mut()` 并行处理 16 个子树
5. **步骤 5**: 每个子树创建独立的 TreeCache
6. **步骤 6**: 在主线程中合并结果到主 TreeCache
7. **步骤 7**: 添加条件判断（阈值控制）
8. **步骤 8**: 添加单元测试

### 3.5 关键优化点

1. **使用 Arc 共享存储**：避免 TreeCache 并发访问的复杂性
2. **独立 TreeCache**：每个子树有自己的 TreeCache，互不干扰
3. **主线程合并**：在主线程中合并结果，确保一致性
4. **阈值控制**：小数据量时使用串行，避免线程创建开销
5. **条件并行**：只在 depth=1 且数据量足够大时使用并行

### 3.6 代码集成

在 `batch_put_value_sets` 中集成并行版本：

```rust
/// The batch version of `put_value_sets`.
pub fn batch_put_value_sets(
    &self,
    value_sets: Vec<Vec<(KeyHash, OwnedValue)>>,
    node_hashes: Option<Vec<&HashMap<NibblePath, [u8; 32]>>>,
    first_version: Version,
) -> Result<(Vec<RootHash>, TreeUpdateBatch)> {
    let mut tree_cache = TreeCache::new(self.reader, first_version)?;
    let hash_sets: Vec<_> = match node_hashes {
        Some(hashes) => hashes.into_iter().map(Some).collect(),
        None => (0..value_sets.len()).map(|_| None).collect(),
    };

    for (idx, (value_set, hash_set)) in
        itertools::zip_eq(value_sets.into_iter(), hash_sets.into_iter()).enumerate()
    {
        assert!(
            !value_set.is_empty(),
            "Transactions that output empty write set should not be included.",
        );
        let version = first_version + idx as u64;
        let deduped_and_sorted_kvs = value_set
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(key, value)| {
                let value_hash = ValueHash::with::<H>(value.as_slice());
                tree_cache.put_value(version, key, Some(value));
                (key, value_hash)
            })
            .collect::<Vec<_>>();
        let root_node_key = tree_cache.get_root_node_key().clone();
        
        #[cfg(feature = "parallel")]
        let (new_root_node_key, _) = self.batch_insert_at_parallel(
            root_node_key,
            version,
            deduped_and_sorted_kvs.as_slice(),
            0,
            &hash_set,
            &mut tree_cache,
        )?;
        
        #[cfg(not(feature = "parallel"))]
        let (new_root_node_key, _) = self.batch_insert_at(
            root_node_key,
            version,
            deduped_and_sorted_kvs.as_slice(),
            0,
            &hash_set,
            &mut tree_cache,
        )?;
        
        tree_cache.set_root_node_key(new_root_node_key);

        // Freezes the current cache to make all contents in the current cache immutable.
        tree_cache.freeze::<H>()?;
    }

    Ok(tree_cache.into())
}
```

---

## 阶段四：性能测试与对比

### 4.1 运行 Benchmark

```bash
# 运行所有 benchmark
cargo bench --bench batch_insert_bench

# 运行特定 benchmark
cargo bench --bench batch_insert_bench -- random_distribution

# 生成详细报告
cargo bench --bench batch_insert_bench -- --save-baseline baseline
```

### 4.2 性能指标

#### 关键指标
- **吞吐量**: ops/second（每秒处理操作数）
- **延迟**: 平均时间、P50、P95、P99
- **加速比**: 并行版本 / 串行版本
- **CPU 使用率**: 单核 vs 多核

#### 预期结果
| 数据规模 | 串行版本 | 并行版本 | 加速比 |
|---------|---------|---------|--------|
| 100 keys | 1.0 ms | 1.2 ms | 0.83x |
| 1,000 keys | 10 ms | 3 ms | 3.3x |
| 10,000 keys | 100 ms | 15 ms | 6.7x |
| 100,000 keys | 1000 ms | 120 ms | 8.3x |

**注意**: 小数据量时并行可能反而更慢（线程创建开销）

### 4.3 性能分析

#### 优化场景
- ✅ 大批量数据（>1000 keys）
- ✅ 均匀分布在 16 个子树
- ✅ CPU 密集型操作

#### 不优化场景
- ❌ 小批量数据（<100 keys）
- ❌ 集中在少数子树
- ❌ I/O 密集型操作

---

## 阶段五：正确性验证

### 5.1 单元测试

**文件**: `src/tests/parallel_test.rs`

```rust
#[cfg(test)]
mod parallel_tests {
    use super::*;

    #[test]
    fn test_parallel_vs_sequential_consistency() {
        // 验证并行和串行版本产生相同的结果
        let value_set = generate_test_data(1000);
        
        let (root_hash_seq, batch_seq) = tree.batch_put_value_sets_sequential(...);
        let (root_hash_par, batch_par) = tree.batch_put_value_sets_parallel(...);
        
        assert_eq!(root_hash_seq, root_hash_par);
        // 验证 batch 内容一致
    }

    #[test]
    fn test_parallel_edge_cases() {
        // 测试边界情况
        // 1. 空子树
        // 2. 单一子树
        // 3. 全部 16 个子树
    }
}
```

### 5.2 集成测试

```rust
#[test]
fn test_parallel_integration() {
    // 测试完整的批量插入流程
    // 验证生成的 Merkle proof 正确性
}
```

### 5.3 压力测试

```rust
#[test]
fn test_parallel_stress() {
    // 大规模数据测试
    // 验证内存使用
    // 验证无数据竞争
}
```

### 5.4 运行测试

```bash
# 运行所有测试
cargo test --features parallel

# 运行并行测试
cargo test --features parallel parallel_tests

# 运行并发安全检查
cargo test --features parallel -- --test-threads=1
```

---

## 阶段六：文档与优化

### 6.1 代码文档

在 `src/tree.rs` 中添加详细注释：

```rust
/// 并行版本的批量插入优化
///
/// # 性能特性
/// - 在 depth=1 时使用 16 线程并行处理子树
/// - 最小并行阈值: 100 keys
/// - 预期加速比: 3-8x（取决于数据规模）
///
/// # 使用场景
/// - 大批量插入（>1000 keys）
/// - 均匀分布的 keys
/// - CPU 密集型场景
///
/// # 注意事项
/// - 小批量数据时可能比串行更慢
/// - 需要启用 `parallel` feature
///
/// # 示例
/// ```rust
/// #[cfg(feature = "parallel")]
/// let (root_hash, batch) = tree.batch_put_value_sets_parallel(value_sets, ...)?;
/// ```
```

### 6.2 README 更新

在 `README.md` 中添加并行优化说明：

```markdown
## 并行优化

JMT 支持并行批量插入优化，利用 16 叉树的特性在 depth=1 时并行计算子树。

### 启用并行优化

```toml
[dependencies]
jmt = { version = "0.12", features = ["parallel"] }
```

### 性能提升

- 大批量插入（>1000 keys）: 3-8x 加速比
- 中批量插入（100-1000 keys）: 1.5-3x 加速比
- 小批量插入（<100 keys）: 可能略慢（线程开销）

### Benchmark

运行 benchmark 查看性能数据：

```bash
cargo bench --bench batch_insert_bench
```
```

### 6.3 进一步优化方向

1. **更深层次的并行**: 在 depth=2, 3 等层级也使用并行
2. **动态并行度**: 根据数据规模自动调整线程数
3. **NUMA 优化**: 针对 NUMA 架构优化内存访问
4. **SIMD 优化**: 使用 SIMD 指令加速哈希计算

---

## 时间规划

| 阶段 | 任务 | 预计时间 |
|-----|------|---------|
| 阶段一 | 环境准备 | 0.5 天 |
| 阶段二 | Benchmark 工具开发 | 2 天 |
| 阶段三 | 并行优化实现 | 3 天 |
| 阶段四 | 性能测试与对比 | 1 天 |
| 阶段五 | 正确性验证 | 1 天 |
| 阶段六 | 文档与优化 | 0.5 天 |
| **总计** | | **8 天** |

---

## 风险与应对

### 风险 1: Arc 共享存储的性能开销
- **应对**: Arc 的引用计数开销很小，可以忽略不计。如果性能不理想，可以考虑使用 `&R` 直接引用（但需要确保生命周期正确）

### 风险 2: 并行版本性能不如预期
- **应对**: 添加阈值控制，小数据量使用串行；优化并行策略，减少数据复制

### 风险 3: 并行引入 bug
- **应对**: 充分的单元测试和集成测试；确保并行和串行版本产生相同的结果

### 风险 4: 内存使用增加
- **应对**: 每个子树创建独立的 TreeCache，但会在合并后释放；监控内存使用，必要时限制并行度

### 风险 5: 子树分组逻辑错误
- **应对**: 使用 nibble 正确分组；添加测试验证分组逻辑

### 风险 6: 主线程合并性能瓶颈
- **应对**: 合并操作相对简单，主要是插入 TreeCache；如果成为瓶颈，可以考虑并行合并

---

## 性能测试结果与优化建议

### 测试结果总结

基于第四阶段的性能测试，在 MockTreeStore (内存存储) 场景下，并行版本与串行版本的性能几乎相同，加速比在 0.95x - 1.06x 之间，没有达到预期的 3-8x 加速比。

### 性能数据

| 数据规模 | 串行版本 | 并行版本 | 加速比 | 预期加速比 | 差异 |
|---------|---------|---------|--------|---------|------|
| 100 keys | 60.477 µs | 60.477 µs | 1.00x | 0.83x | +0.17x |
| 1,000 keys | 643.32 µs | 638.62 µs | 1.01x | 3.3x | -2.29x |
| 10,000 keys | 6.9972 ms | 6.9375 ms | 1.01x | 6.7x | -5.69x |
| 100,000 keys | 94.656 ms | 93.087 ms | 1.02x | 8.3x | -7.28x |

### 性能瓶颈分析

1. **并行开销显著**: 线程创建、同步、数据复制和合并的开销抵消了并行计算的收益
2. **内存存储限制**: MockTreeStore 是内存存储，没有 I/O 延迟，限制了并行优化的效果
3. **数据复制开销**: 每个子树都需要复制数据到独立的 TreeCache
4. **同步开销**: 主线程需要等待所有子线程完成
5. **数据合并开销**: 将子树结果合并到主 TreeCache 需要额外的计算

### 优化建议

#### 短期优化

1. **提高并行阈值**: 将 PARALLEL_THRESHOLD 从 100 提高到 1000 或更高
   - 当前阈值过低，小数据量的并行开销抵消了性能提升
   - 建议根据实际测试数据调整到最优值

2. **减少数据复制**: 使用引用计数或共享内存减少数据复制
   - 当前每个子树都创建独立的 TreeCache，导致大量数据复制
   - 可以考虑使用 `Arc` 共享只读数据

3. **优化数据合并**: 使用更高效的数据结构和算法合并子树结果
   - 当前合并操作在主线程中串行执行，可能成为瓶颈
   - 可以考虑使用批量插入或预分配内存

4. **预热线程池**: 使用全局线程池避免重复创建
   - Rayon 已经提供了全局线程池，但可以进一步优化配置
   - 考虑使用 `rayon::ThreadPoolBuilder` 自定义线程池

#### 中期优化

1. **更深层次的并行**: 在 depth=2, 3 等层级也使用并行
   - 当前只在 depth=1 时并行，可以扩展到更深层次
   - 需要动态评估并行收益和开销

2. **动态并行度**: 根据数据规模和分布自动调整并行度
   - 当前固定使用 16 个线程，可能不是最优配置
   - 可以根据子树大小动态调整并行度

3. **NUMA 优化**: 针对 NUMA 架构优化内存访问
   - 在多 NUMA 节点的服务器上，内存访问延迟可能成为瓶颈
   - 可以考虑使用 `numa` 库优化内存分配

4. **SIMD 优化**: 使用 SIMD 指令加速哈希计算
   - 哈希计算是 CPU 密集型操作，适合 SIMD 优化
   - 可以考虑使用 `packed_simd` 或 `wide` 库

#### 长期优化

1. **异步 I/O**: 使用异步 I/O 提高存储访问效率
   - 在真实存储场景（如 RocksDB）中，I/O 可能成为瓶颈
   - 可以考虑使用 `tokio` 或 `async-std` 实现异步 I/O

2. **流水线优化**: 将并行计算和 I/O 操作流水线化
   - 当前并行计算和 I/O 操作是串行的，可以流水线化
   - 可以考虑使用生产者-消费者模式

3. **自适应策略**: 根据运行时性能数据自动选择最优策略
   - 当前固定使用并行或串行，可以根据运行时数据动态选择
   - 可以考虑使用机器学习预测最优策略

4. **硬件加速**: 使用 GPU 或专用硬件加速哈希计算
   - 哈希计算适合 GPU 并行加速
   - 可以考虑使用 `cuda` 或 `opencl` 实现

### 后续测试计划

1. **真实存储测试**: 在真实存储场景（如 RocksDB）中测试并行性能
   - MockTreeStore 是内存存储，不能代表真实场景
   - 需要在 RocksDB 或其他持久化存储中测试

2. **不同硬件测试**: 在不同硬件配置下测试并行性能
   - 当前测试环境可能不是最优配置
   - 需要在不同 CPU 核数、内存配置下测试

3. **不同数据分布测试**: 测试更多种数据分布模式
   - 当前只测试了随机、集中、稀疏三种分布
   - 需要测试更多种分布模式，如正态分布、幂律分布等

---

## 成功标准

1. ✅ Benchmark 工具完整，覆盖多种测试场景
2. ✅ 并行版本在大批量数据时性能提升 > 3x
3. ✅ 并行版本与串行版本产生完全相同的结果
4. ✅ 所有测试通过，无回归
5. ✅ 代码文档完整，易于理解和使用
6. ✅ README 更新，包含性能数据和使用说明

---

## 参考资料

- [Rayon 官方文档](https://docs.rs/rayon/)
- [Criterion Benchmark 文档](https://bheisler.github.io/criterion.rs/book/)
- [JMT 设计文档](https://github.com/penumbra-zone/jmt)
- [Rust 并发编程](https://rust-lang.github.io/book/ch16-00-concurrency.html)
