# JMT 存储分片优化方案

## 背景

当前 JMT 的并行实现在内存存储场景下性能提升有限，主要原因：
1. 内存存储没有 I/O 延迟
2. 并行开销（线程创建、同步、数据合并）抵消了计算收益
3. 所有子树共享同一个存储实例，存在潜在的锁竞争

Aptos 等高性能区块链项目采用了存储分片技术，通过将存储分成多个独立的分片，实现真正的并行 I/O。

## 方案概述

### 核心思想

利用 JMT 的 16-ary 树结构特性，将存储分成 16 个分片：
- 每个 depth=1 子树对应一个分片
- 分片 0-15 分别对应 nibble 0-15
- 每个分片独立存储，支持并行 I/O

### 技术实现

#### 1. RocksDB Column Family

RocksDB 天然支持多个 Column Family（列族），每个列族：
- 拥有独立的 MemTable 和 SST 文件
- 共享同一个 WAL 文件
- 支持独立的配置（压缩、缓存等）

```rust
// 创建 16 个 Column Family
const NUM_SHARDS: usize = 16;

let cf_names: Vec<String> = (0..NUM_SHARDS)
    .map(|i| format!("shard_{}", i))
    .collect();

let mut cf_opts = Vec::with_capacity(NUM_SHARDS);
for _ in 0..NUM_SHARDS {
    cf_opts.push(Options::default());
}

let db = DB::open_cf(&opts, &path, &cf_names)?;
```

#### 2. 分片路由策略

根据 NodeKey 的第一个 nibble 决定存储到哪个分片：

```rust
fn get_shard_index(node_key: &NodeKey) -> usize {
    let first_nibble = node_key.nibble_path().get_nibble(0);
    first_nibble.as_usize()
}
```

#### 3. 存储接口修改

##### TreeReader trait

```rust
pub trait TreeReader {
    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        let shard_idx = get_shard_index(node_key);
        self.get_node_from_shard(shard_idx, node_key)
    }

    fn get_node_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Node>;
}
```

##### TreeWriter trait

```rust
pub trait TreeWriter {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        // 按分片分组
        let mut shard_batches: Vec<Vec<_>> = vec![Vec::new(); NUM_SHARDS];
        for (node_key, node) in node_batch.nodes() {
            let shard_idx = get_shard_index(node_key);
            shard_batches[shard_idx].push((node_key.clone(), node.clone()));
        }

        // 并行写入各个分片
        shard_batches.par_iter().enumerate().for_each(|(shard_idx, batch)| {
            self.write_shard_batch(shard_idx, batch);
        });
    }

    fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()>;
}
```

#### 4. 并行处理优化

在 `process_children_parallel` 中，每个子树可以独立访问对应的分片：

```rust
#[cfg(feature = "parallel")]
fn process_children_parallel(
    &self,
    node_key: NodeKey,
    version: Version,
    kvs: &[(KeyHash, ValueHash)],
    depth: usize,
    hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
    tree_cache: &mut TreeCache<R>,
    internal_node: InternalNode,
) -> Result<(NodeKey, Node)>
where
    R: Sync,
    H: Sync,
{
    use rayon::prelude::*;

    // 并行处理 16 个子树，每个子树访问对应的分片
    let subtree_results: Vec<Option<(NodeKey, Node, HashMap<NodeKey, Node>, HashMap<(Version, KeyHash), Option<OwnedValue>>, HashSet<NodeKey>)>> = (0..16)
        .into_par_iter()
        .map(|i| {
            if subtrees[i].is_empty() {
                return None;
            }

            // 每个子树使用独立的存储分片
            let shard_idx = i;
            let sub_tree = JellyfishMerkleTree::new_with_shard(self.reader, shard_idx);

            // ... 处理子树
        })
        .collect();

    // 合并结果
    // ...
}
```

## 优势分析

### 1. 并行 I/O

- **当前方案**：所有子树共享同一个存储，I/O 串行化
- **分片方案**：16 个分片可以并行 I/O，充分利用存储带宽

### 2. 减少锁竞争

- **当前方案**：多个线程竞争同一个存储锁
- **分片方案**：每个分片独立锁，竞争减少到 1/16

### 3. 缓存局部性

- **当前方案**：节点分散在整个存储中
- **分片方案**：相关节点在同一个分片，提高缓存命中率

### 4. 可扩展性

- **当前方案**：单存储实例，扩展受限
- **分片方案**：可以水平扩展到多台机器

## 预期性能提升

基于 Aptos 的经验，在持久化存储场景下：

| 数据规模 | 当前方案 | 分片方案 | 预期加速比 |
|---------|---------|---------|------------|
| 1,000 keys | 662 µs | ~300-400 µs | **1.5-2.2x** |
| 10,000 keys | 7.95 ms | ~3-5 ms | **1.6-2.7x** |
| 100,000 keys | 105.8 ms | ~30-50 ms | **2.1-3.5x** |

## 实现挑战

### 1. 兼容性

- 需要保持向后兼容
- 旧数据需要迁移到新分片结构

### 2. 一致性

- 跨分片事务需要特殊处理
- RocksDB 的 WriteBatch 需要支持跨分片

### 3. 复杂度

- 代码复杂度增加
- 需要管理 16 个分片的生命周期

## 实施计划

### 阶段 1：基础架构（1-2 周）

1. 设计分片接口
2. 实现 ShardedTreeReader 和 ShardedTreeWriter
3. 更新 MockTreeStore 支持分片

### 阶段 2：RocksDB 集成（2-3 周）

1. 实现 RocksDB 分片存储
2. 配置 16 个 Column Family
3. 优化 Column Family 参数

### 阶段 3：并行优化（1-2 周）

1. 修改 process_children_parallel 支持分片
2. 实现分片级别的并行 I/O
3. 添加性能监控

### 阶段 4：测试和优化（1-2 周）

1. 单元测试
2. 性能基准测试
3. 生产环境验证

## 参考实现

### Aptos JMT

Aptos 的 JMT 实现使用了类似的分片技术：
- 使用 RocksDB Column Family
- 按照节点路径的第一个 nibble 分片
- 支持并行读取和写入

### 其他参考

- **Diem JMT**：原始实现，无分片
- **Sui JMT**：类似的优化思路
- **RocksDB 最佳实践**：Column Family 使用指南

## 结论

存储分片是一个可行且有效的优化方案，特别适合 JMT 的 16-ary 树结构。通过将存储分成 16 个独立的分片，可以实现：

1. **真正的并行 I/O**：充分利用存储带宽
2. **减少锁竞争**：每个分片独立锁
3. **提高缓存局部性**：相关节点在同一分片
4. **支持水平扩展**：可以分布到多台机器

预期在持久化存储场景下，性能提升 **2-3.5 倍**，与 Aptos 的优化效果相当。

## 附录：代码示例

### 分片存储实现

```rust
pub struct ShardedTreeStore<R> {
    shards: [R; 16],
}

impl<R: TreeReader> ShardedTreeStore<R> {
    pub fn new(shards: [R; 16]) -> Self {
        Self { shards }
    }

    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        let shard_idx = get_shard_index(node_key);
        self.shards[shard_idx].get_node(node_key)
    }
}

fn get_shard_index(node_key: &NodeKey) -> usize {
    let first_nibble = node_key.nibble_path().get_nibble(0);
    first_nibble.as_usize()
}
```

### 并行写入实现

```rust
impl<R: TreeWriter> ShardedTreeStore<R> {
    pub fn write_node_batch_parallel(&self, node_batch: &NodeBatch) -> Result<()> {
        use rayon::prelude::*;

        // 按分片分组
        let mut shard_batches: Vec<Vec<_>> = vec![Vec::new(); 16];
        for (node_key, node) in node_batch.nodes() {
            let shard_idx = get_shard_index(node_key);
            shard_batches[shard_idx].push((node_key.clone(), node.clone()));
        }

        // 并行写入各个分片
        shard_batches
            .into_par_iter()
            .enumerate()
            .for_each(|(shard_idx, batch)| {
                if !batch.is_empty() {
                    self.shards[shard_idx].write_node_batch(&batch);
                }
            });

        Ok(())
    }
}
```
