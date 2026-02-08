# JMT 存储分片优化详细设计方案

## 一、方案大纲

### 1. 项目背景与目标

- **背景**：当前 JMT 并行实现在内存存储场景下性能提升有限，主要原因是内存存储没有 I/O 延迟，并行开销抵消了计算收益。在持久化存储场景下，I/O 成为主要瓶颈，需要通过存储分片实现真正的并行 I/O。

- **目标**：
  - 实现基于 RocksDB Column Family 的存储分片
  - 将存储分成 16 个独立分片，对应 JMT 的 16-ary 树结构
  - 支持分片级别的并行读写
  - 提升持久化存储场景下的性能 2-3.5 倍
  - 保持向后兼容性

### 2. 技术方案

- **存储分片架构**：使用 RocksDB Column Family 实现 16 个存储分片
- **分片路由策略**：基于 NodeKey 的第一个 nibble 进行分片
- **并行处理模型**：每个分片独立访问，支持真正的并行 I/O
- **一致性保证**：利用 RocksDB 的事务支持确保跨分片一致性

### 3. 系统架构

- **核心组件**：
  - ShardedTreeReader：分片存储读取接口
  - ShardedTreeWriter：分片存储写入接口
  - ShardedTreeStore：分片存储实现
  - RocksDBShard：RocksDB 分片实现

- **数据流**：
  - 写入：数据按分片分组 → 并行写入各分片
  - 读取：根据 NodeKey 路由到对应分片 → 并行读取

### 4. 关键技术实现

- **RocksDB Column Family 管理**：创建和配置 16 个 Column Family
- **分片路由算法**：基于 NodeKey 的 nibble 路径计算分片索引
- **并行 I/O 实现**：使用 Rayon 实现分片级并行读写
- **事务管理**：跨分片事务处理
- **数据迁移**：从旧存储格式迁移到新分片格式

### 5. 性能优化

- **缓存策略**：每个分片独立缓存配置
- **压缩策略**：针对不同分片的访问模式设置不同压缩参数
- **批量处理**：分片级别的批量写入
- **预热策略**：系统启动时预热热点分片

### 6. 测试与验证

- **单元测试**：验证分片路由、并行读写等核心功能
- **性能基准测试**：对比优化前后的性能提升
- **集成测试**：与现有系统集成测试
- **压力测试**：大规模数据下的性能验证

### 7. 实施计划

- **阶段 1**：基础架构设计与实现
- **阶段 2**：RocksDB 集成与测试
- **阶段 3**：并行优化与调优
- **阶段 4**：系统集成与验证
- **阶段 5**：生产环境部署与监控

### 8. 风险评估与应对

- **技术风险**：RocksDB 性能、跨分片一致性
- **兼容性风险**：与现有系统的兼容性
- **运维风险**：分片管理、监控
- **应对策略**：详细的测试计划、灰度部署、回滚机制

## 二、详细设计

### 1. 存储分片架构

#### 1.1 RocksDB Column Family 设计

- **Column Family 命名**：
  - 格式：`shard_{index}`，其中 index 为 0-15
  - 示例：`shard_0`, `shard_1`, ..., `shard_15`

- **Column Family 配置**：
  - 共享 WAL 文件
  - 每个 Column Family 独立 MemTable 和 SST 文件
  - 可配置的内存限制、压缩策略

- **创建流程**：
  ```rust
  pub fn create_rocksdb_with_shards(path: &str) -> Result<DB> {
      let mut opts = Options::default();
      opts.create_if_missing(true);
      opts.set_max_open_files(1000);
      
      let mut cf_opts = Options::default();
      cf_opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB per CF
      cf_opts.set_compression_type(CompressionType::Snappy);
      
      let cf_names: Vec<String> = (0..16).map(|i| format!("shard_{}", i)).collect();
      let mut cfs = Vec::new();
      
      for name in &cf_names {
          cfs.push((name, &cf_opts));
      }
      
      DB::open_cf_with_opts(&opts, path, cfs)
  }
  ```

#### 1.2 分片路由策略

- **路由算法**：
  - 提取 NodeKey 的 nibble 路径
  - 获取第一个 nibble 值（0-15）
  - 映射到对应的分片索引

- **实现**：
  ```rust
  pub fn get_shard_index(node_key: &NodeKey) -> usize {
      let nibble_path = node_key.nibble_path();
      if nibble_path.is_empty() {
          // 根节点存储在默认分片
          return 0;
      }
      let first_nibble = nibble_path.get_nibble(0);
      first_nibble.as_usize()
  }
  ```

- **特殊情况处理**：
  - 根节点：存储在分片 0
  - 空 nibble 路径：存储在分片 0
  - 异常 nibble 值：使用默认分片 0

### 2. 核心组件设计

#### 2.1 ShardedTreeReader

- **接口定义**：
  ```rust
  pub trait ShardedTreeReader {
      fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
          let shard_idx = get_shard_index(node_key);
          self.get_node_from_shard(shard_idx, node_key)
      }
      
      fn get_node_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Node>;
      
      fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
          let shard_idx = get_shard_index(node_key);
          self.get_node_option_from_shard(shard_idx, node_key)
      }
      
      fn get_node_option_from_shard(&self, shard_idx: usize, node_key: &NodeKey) -> Result<Option<Node>>;
      
      // 其他方法...
  }
  ```

- **实现**：
  - 基于 RocksDB 的分片读取实现
  - 支持并行读取多个分片

#### 2.2 ShardedTreeWriter

- **接口定义**：
  ```rust
  pub trait ShardedTreeWriter {
      fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
          // 按分片分组
          let mut shard_batches = self.group_nodes_by_shard(node_batch);
          
          // 并行写入各分片
          shard_batches
              .into_iter()
              .collect::<Vec<_>>()
              .into_par_iter()
              .try_for_each(|(shard_idx, batch)| {
                  self.write_shard_batch(shard_idx, &batch)
              })
      }
      
      fn group_nodes_by_shard(&self, node_batch: &NodeBatch) -> HashMap<usize, Vec<(NodeKey, Node)>>;
      fn write_shard_batch(&self, shard_idx: usize, batch: &[(NodeKey, Node)]) -> Result<()>;
      
      // 其他方法...
  }
  ```

- **实现**：
  - 按分片分组节点
  - 使用 Rayon 并行写入各分片
  - 支持批量写入优化

#### 2.3 ShardedTreeStore

- **结构定义**：
  ```rust
  pub struct ShardedTreeStore {
      db: DB,
      cfs: [ColumnFamily; 16],
      default_cf: ColumnFamily,
  }
  ```

- **核心方法**：
  - `new()`: 创建分片存储实例
  - `get_shard()`: 获取指定分片
  - `write_batch()`: 写入节点批量
  - `read_node()`: 读取节点

#### 2.4 RocksDBShard

- **结构定义**：
  ```rust
  pub struct RocksDBShard {
      db: Arc<DB>,
      cf: ColumnFamily,
      shard_idx: usize,
  }
  ```

- **核心方法**：
  - `put()`: 写入键值对
  - `get()`: 读取键值对
  - `batch_write()`: 批量写入
  - `batch_read()`: 批量读取

### 3. 并行处理模型

#### 3.1 写入并行化

- **流程**：
  1. 接收 NodeBatch
  2. 按分片分组节点
  3. 为每个分片创建独立的 WriteBatch
  4. 并行执行各分片的 WriteBatch
  5. 提交事务

- **实现**：
  ```rust
  pub fn parallel_write(&self, node_batch: &NodeBatch) -> Result<()> {
      let shard_batches = self.group_nodes_by_shard(node_batch);
      
      shard_batches
          .into_par_iter()
          .try_for_each(|(shard_idx, nodes)| {
              let mut write_batch = WriteBatch::default();
              
              for (node_key, node) in nodes {
                  let key = node_key.as_bytes();
                  let value = node.serialize();
                  write_batch.put_cf(&self.cfs[shard_idx], key, value);
              }
              
              self.db.write(&write_batch)
          })
  }
  ```

#### 3.2 读取并行化

- **流程**：
  1. 接收多个 NodeKey
  2. 按分片分组 NodeKey
  3. 并行从各分片读取数据
  4. 合并结果

- **实现**：
  ```rust
  pub fn parallel_read(&self, node_keys: &[NodeKey]) -> Result<Vec<Option<Node>>> {
      let mut shard_keys = HashMap::new();
      let mut key_indices = Vec::new();
      
      // 分组并记录原始索引
      for (idx, node_key) in node_keys.iter().enumerate() {
          let shard_idx = get_shard_index(node_key);
          shard_keys.entry(shard_idx).or_insert_with(Vec::new).push((idx, node_key));
      }
      
      // 并行读取
      let mut results = vec![None; node_keys.len()];
      
      shard_keys
          .into_par_iter()
          .for_each(|(shard_idx, keys)| {
              let cf = &self.cfs[shard_idx];
              
              for (idx, node_key) in keys {
                  let key = node_key.as_bytes();
                  if let Ok(Some(value)) = self.db.get_cf(cf, key) {
                      let node = Node::deserialize(&value);
                      results[idx] = Some(node);
                  }
              }
          });
      
      Ok(results)
  }
  ```

### 4. 一致性保证

#### 4.1 跨分片事务

- **挑战**：需要确保跨分片操作的原子性

- **解决方案**：
  - 使用 RocksDB 的 WriteBatch 支持跨 Column Family 写入
  - 所有分片共享同一个 WAL 文件，确保原子性

- **实现**：
  ```rust
  pub fn write_cross_shard_batch(&self, batches: &HashMap<usize, Vec<(NodeKey, Node)>>) -> Result<()> {
      let mut write_batch = WriteBatch::default();
      
      for (shard_idx, nodes) in batches {
          let cf = &self.cfs[*shard_idx];
          
          for (node_key, node) in nodes {
              let key = node_key.as_bytes();
              let value = node.serialize();
              write_batch.put_cf(cf, key, value);
          }
      }
      
      self.db.write(&write_batch)
  }
  ```

#### 4.2 读取一致性

- **挑战**：确保跨分片读取的一致性

- **解决方案**：
  - 使用 RocksDB 的快照机制
  - 所有读取操作基于同一个快照

- **实现**：
  ```rust
  pub fn read_consistent(&self, keys: &[NodeKey]) -> Result<Vec<Option<Node>>> {
      let snapshot = self.db.snapshot();
      let mut results = Vec::new();
      
      for node_key in keys {
          let shard_idx = get_shard_index(node_key);
          let cf = &self.cfs[shard_idx];
          let key = node_key.as_bytes();
          
          if let Ok(Some(value)) = snapshot.get_cf(cf, key) {
              let node = Node::deserialize(&value);
              results.push(Some(node));
          } else {
              results.push(None);
          }
      }
      
      Ok(results)
  }
  ```

### 5. 数据迁移

#### 5.1 迁移策略

- **目标**：从旧存储格式迁移到新分片格式

- **策略**：
  1. 渐进式迁移：新写入使用分片格式，读取时兼容旧格式
  2. 后台迁移：系统启动时在后台迁移旧数据
  3. 双写模式：一段时间内同时写入旧格式和新格式

#### 5.2 迁移实现

- **读取兼容**：
  ```rust
  pub fn get_node_compatible(&self, node_key: &NodeKey) -> Result<Option<Node>> {
      // 先尝试从分片读取
      let shard_idx = get_shard_index(node_key);
      let cf = &self.cfs[shard_idx];
      let key = node_key.as_bytes();
      
      if let Ok(Some(value)) = self.db.get_cf(cf, key) {
          return Ok(Some(Node::deserialize(&value)));
      }
      
      // 尝试从默认列族读取（旧格式）
      if let Ok(Some(value)) = self.db.get_cf(&self.default_cf, key) {
          return Ok(Some(Node::deserialize(&value)));
      }
      
      Ok(None)
  }
  ```

- **后台迁移**：
  ```rust
  pub fn start_background_migration(&self) {
      tokio::spawn(async move {
          // 扫描默认列族中的所有数据
          // 按分片重新写入到对应 Column Family
          // 验证迁移结果
          // 清理旧数据
      });
  }
  ```

### 6. 性能优化

#### 6.1 缓存策略

- **MemTable 优化**：
  - 为每个分片配置独立的 MemTable 大小
  - 热点分片配置更大的 MemTable

- **Block Cache 优化**：
  - 使用共享的 Block Cache
  - 针对不同分片设置不同的缓存优先级

- **实现**：
  ```rust
  pub fn configure_cache() -> Options {
      let mut opts = Options::default();
      
      // 共享 Block Cache
      let block_cache = Cache::new_lru_cache(128 * 1024 * 1024); // 128MB
      opts.set_block_cache(&block_cache);
      
      // MemTable 配置
      opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB per CF
      
      opts
  }
  ```

#### 6.2 压缩策略

- **压缩配置**：
  - 针对不同分片的访问模式设置不同压缩策略
  - 热点分片使用较轻的压缩（Snappy）
  - 冷数据分片使用较重的压缩（ZSTD）

- **实现**：
  ```rust
  pub fn configure_compression(shard_idx: usize) -> Options {
      let mut opts = Options::default();
      
      // 热点分片使用 Snappy
      if shard_idx < 8 {
          opts.set_compression_type(CompressionType::Snappy);
      } else {
          // 冷数据分片使用 ZSTD
          opts.set_compression_type(CompressionType::Zstd);
          opts.set_compression_level(3);
      }
      
      opts
  }
  ```

#### 6.3 批量处理

- **写入批量**：
  - 合并小批量为大批量
  - 减少磁盘 I/O 次数

- **读取批量**：
  - 批量读取同一分片的数据
  - 减少网络往返

- **实现**：
  ```rust
  pub fn batch_write_optimized(&self, nodes: &[(NodeKey, Node)]) -> Result<()> {
      let mut shard_batches = HashMap::new();
      
      for (node_key, node) in nodes {
          let shard_idx = get_shard_index(node_key);
          shard_batches.entry(shard_idx).or_insert_with(Vec::new).push((node_key.clone(), node.clone()));
      }
      
      // 合并小批量
      let mut optimized_batches = HashMap::new();
      for (shard_idx, batch) in shard_batches {
          if batch.len() < 100 {
              // 合并到默认分片
              optimized_batches.entry(0).or_insert_with(Vec::new).extend(batch);
          } else {
              optimized_batches.insert(shard_idx, batch);
          }
      }
      
      self.write_cross_shard_batch(&optimized_batches)
  }
  ```

### 7. 测试与验证

#### 7.1 单元测试

- **测试范围**：
  - 分片路由算法
  - 并行读写功能
  - 跨分片事务
  - 数据迁移
  - 一致性保证

- **测试用例**：
  - 基本分片路由测试
  - 并行写入性能测试
  - 并行读取性能测试
  - 跨分片一致性测试
  - 数据迁移测试

#### 7.2 性能基准测试

- **测试场景**：
  - 不同数据规模（100, 1000, 10000, 100000 keys）
  - 不同分布模式（随机、集中、稀疏）
  - 不同硬件配置（SSD, HDD）

- **测试指标**：
  - 写入吞吐量（keys/s）
  - 读取吞吐量（keys/s）
  - 延迟分布
  - 资源使用（CPU, 内存, I/O）

- **对比**：
  - 优化前 vs 优化后
  - 不同分片数量的性能对比
  - 与 Aptos JMT 的性能对比

#### 7.3 集成测试

- **测试场景**：
  - 与现有 JMT 接口集成
  - 与区块链系统集成
  - 生产环境模拟

- **测试用例**：
  - JMT 完整操作流程测试
  - 区块链状态更新测试
  - 系统重启恢复测试
  - 网络分区恢复测试

### 8. 实施计划

#### 8.1 阶段划分

- **阶段 1**：基础架构设计与实现（2 周）
  - 设计分片存储接口
  - 实现核心组件
  - 编写单元测试

- **阶段 2**：RocksDB 集成与测试（3 周）
  - 集成 RocksDB Column Family
  - 实现分片存储
  - 性能基准测试

- **阶段 3**：并行优化与调优（2 周）
  - 实现并行 I/O
  - 性能优化
  - 压力测试

- **阶段 4**：系统集成与验证（2 周）
  - 与现有系统集成
  - 集成测试
  - 生产环境验证

- **阶段 5**：部署与监控（1 周）
  - 生产环境部署
  - 监控系统集成
  - 应急方案测试

#### 8.2 关键里程碑

1. **M1**：基础架构完成（2 周）
2. **M2**：RocksDB 集成完成（3 周）
3. **M3**：并行优化完成（2 周）
4. **M4**：系统集成完成（2 周）
5. **M5**：生产环境部署（1 周）

### 9. 风险评估与应对

#### 9.1 技术风险

- **RocksDB 性能**：
  - **风险**：Column Family 过多可能影响 RocksDB 性能
  - **应对**：进行充分的性能测试，优化 Column Family 配置

- **跨分片一致性**：
  - **风险**：跨分片事务可能影响性能
  - **应对**：尽量减少跨分片操作，使用批量操作减少事务次数

- **数据迁移**：
  - **风险**：数据迁移可能导致服务中断
  - **应对**：使用后台异步迁移，保持双写模式确保安全

#### 9.2 兼容性风险

- **API 兼容性**：
  - **风险**：新存储格式可能破坏现有 API
  - **应对**：保持向后兼容，提供迁移工具

- **数据格式兼容性**：
  - **风险**：旧数据可能无法读取
  - **应对**：实现兼容层，支持读取旧格式数据

#### 9.3 运维风险

- **分片管理**：
  - **风险**：分片管理复杂度增加
  - **应对**：提供分片管理工具，自动化分片监控

- **监控**：
  - **风险**：分片级监控复杂度增加
  - **应对**：开发专门的分片监控工具，集成到现有监控系统

- **故障恢复**：
  - **风险**：分片故障可能影响整个系统
  - **应对**：实现分片级故障隔离，提供快速恢复机制

### 10. 结论与建议

#### 10.1 技术可行性

- **结论**：存储分片方案技术上完全可行
  - RocksDB Column Family 天然支持多分片
  - JMT 的 16-ary 树结构非常适合分片设计
  - 并行 I/O 可以显著提升性能

- **优势**：
  - 充分利用现代硬件的并行能力
  - 扩展性好，支持水平扩展
  - 维护成本可控

#### 10.2 性能预期

- **预期提升**：
  - 写入性能：2-3.5 倍提升
  - 读取性能：1.5-2.5 倍提升
  - 系统吞吐量：2-3 倍提升

- **影响因素**：
  - 硬件配置：SSD 性能提升更明显
  - 数据分布：均匀分布性能提升更明显
  - 批量大小：大批量性能提升更明显

#### 10.3 实施建议

- **优先事项**：
  1. 完成基础架构实现
  2. 进行充分的性能测试
  3. 实现数据迁移工具
  4. 建立监控系统

- **最佳实践**：
  - 从小规模开始部署，逐步扩大
  - 保持双写模式一段时间确保安全
  - 建立完善的监控和告警机制
  - 定期进行性能优化和调优

- **未来展望**：
  - 支持动态分片调整
  - 实现跨机器分片分布
  - 集成更高级的存储技术（如 PMEM）

## 三、附录

### A. 代码示例

#### A.1 分片路由实现

```rust
pub fn get_shard_index(node_key: &NodeKey) -> usize {
    let nibble_path = node_key.nibble_path();
    if nibble_path.is_empty() {
        return 0;
    }
    let first_nibble = nibble_path.get_nibble(0);
    first_nibble.as_usize()
}
```

#### A.2 并行写入实现

```rust
pub fn parallel_write(&self, nodes: &[(NodeKey, Node)]) -> Result<()> {
    let mut shard_batches = HashMap::new();
    
    for (node_key, node) in nodes {
        let shard_idx = get_shard_index(node_key);
        shard_batches.entry(shard_idx).or_insert_with(Vec::new).push((node_key.clone(), node.clone()));
    }
    
    shard_batches
        .into_par_iter()
        .try_for_each(|(shard_idx, batch)| {
            let mut write_batch = WriteBatch::default();
            let cf = &self.cfs[shard_idx];
            
            for (node_key, node) in batch {
                let key = node_key.as_bytes();
                let value = node.serialize();
                write_batch.put_cf(cf, key, value);
            }
            
            self.db.write(&write_batch)
        })
}
```

#### A.3 数据迁移实现

```rust
pub fn migrate_data(&self) -> Result<()> {
    let mut iter = self.db.iterator_cf(&self.default_cf, IterMode::Start);
    let mut batch_size = 0;
    let mut write_batch = WriteBatch::default();
    
    while let Some((key, value)) = iter.next() {
        let node_key = NodeKey::from_bytes(&key);
        let node = Node::deserialize(&value);
        let shard_idx = get_shard_index(&node_key);
        let cf = &self.cfs[shard_idx];
        
        write_batch.put_cf(cf, key, value);
        batch_size += 1;
        
        if batch_size >= 1000 {
            self.db.write(&write_batch)?;
            write_batch.clear();
            batch_size = 0;
        }
    }
    
    if batch_size > 0 {
        self.db.write(&write_batch)?;
    }
    
    Ok(())
}
```

### B. 参考资料

1. **RocksDB Documentation**：https://github.com/facebook/rocksdb/wiki
2. **Aptos JMT Implementation**：https://github.com/aptos-labs/aptos-core/tree/main/storage/jellyfish-merkle
3. **Diem JMT Implementation**：https://github.com/diem/diem/tree/main/storage/jellyfish-merkle
4. **Rayon Documentation**：https://docs.rs/rayon/latest/rayon/
5. **RocksDB Column Family Best Practices**：https://rocksdb.org/blog/2017/02/21/column-families.html
6. **Parallelism in Merkle Trees**：https://arxiv.org/abs/2107.01760
7. **Blockchain Storage Optimization**：https://eprint.iacr.org/2020/1542.pdf
8. **RocksDB Performance Tuning Guide**：https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide
9. **Memory Management in RocksDB**：https://github.com/facebook/rocksdb/wiki/Memory-usage-in-RocksDB
10. **Compression in RocksDB**：https://github.com/facebook/rocksdb/wiki/Compression

### C. 术语表

| 术语 | 解释 |
|------|------|
| JMT | Jellyfish Merkle Tree，一种 256-bit 稀疏 Merkle 树，优化用于高性能区块链状态存储 |
| Column Family | RocksDB 中的列族，每个列族有独立的 MemTable 和 SST 文件 |
| NodeKey | JMT 中节点的唯一标识，包含版本和 nibble 路径 |
| Nibble | 半字节，4 位二进制数据，JMT 中用于路径编码 |
| 16-ary | 16 叉树结构，JMT 的核心特性之一 |
| WAL | Write-Ahead Log，RocksDB 用于崩溃恢复的日志文件 |
| MemTable | RocksDB 中的内存表，新写入的数据首先存储在这里 |
| SST | Sorted String Table，RocksDB 中持久化的数据文件 |
| Rayon | Rust 中的并行计算库，用于实现分片级并行处理 |
| Shard | 分片，存储的逻辑分区 |
| Transaction | 事务，一组原子性的操作 |
| Consistency | 一致性，确保数据的正确性和可靠性 |