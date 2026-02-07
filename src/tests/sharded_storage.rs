use anyhow::Result;

use jmt::node_type::{InternalNode, LeafNode, Node, NodeKey};
use jmt::sharded_storage::{calculate_shard_index, ShardedTreeReader, ShardedTreeWriter};
use jmt::sharded_tree_store::{InMemoryShardedTreeStore, MockShardedTreeStore};
use jmt::types::nibble::NibblePath;
use jmt::{KeyHash, OwnedValue, Version};

/// Tests the shard index calculation based on NodeKey's nibble path.
#[test]
fn test_shard_index_calculation() {
    // Test root node (empty nibble path) - should go to shard 0
    let root_node_key = NodeKey::new(Version::new(0), NibblePath::new());
    assert_eq!(calculate_shard_index(&root_node_key), 0);

    // Test nodes with different first nibbles
    for i in 0..16 {
        let nibble_path = NibblePath::new_with_nibbles(&[i as u8]);
        let node_key = NodeKey::new(Version::new(1), nibble_path);
        assert_eq!(calculate_shard_index(&node_key), i);
    }

    // Test nodes with longer nibble paths
    for i in 0..16 {
        let nibble_path = NibblePath::new_with_nibbles(&[i as u8, 1, 2, 3]);
        let node_key = NodeKey::new(Version::new(2), nibble_path);
        assert_eq!(calculate_shard_index(&node_key), i);
    }
}

/// Tests the in-memory sharded tree store.
#[test]
fn test_in_memory_sharded_tree_store() -> Result<()> {
    let store = InMemoryShardedTreeStore::new(16);

    // Create test nodes with different nibble paths
    let mut test_nodes = Vec::new();
    for i in 0..16 {
        let nibble_path = NibblePath::new_with_nibbles(&[i as u8]);
        let node_key = NodeKey::new(Version::new(1), nibble_path);
        let leaf_node = LeafNode::new(KeyHash::default(), OwnedValue::empty());
        let node = Node::Leaf(leaf_node);
        test_nodes.push((node_key, node));
    }

    // Write nodes to the store
    for (node_key, node) in &test_nodes {
        let shard_idx = store.get_shard_index(node_key);
        store.write_shard_batch(shard_idx, &[(node_key.clone(), node.clone())])?;
    }

    // Verify nodes can be read back from the correct shards
    for (node_key, expected_node) in &test_nodes {
        let shard_idx = store.get_shard_index(node_key);
        let actual_node = store.get_node_from_shard(shard_idx, node_key)?;
        assert_eq!(actual_node, *expected_node);
    }

    Ok(())
}

/// Tests the mock sharded tree store.
#[test]
fn test_mock_sharded_tree_store() -> Result<()> {
    let store = MockShardedTreeStore::new(16);

    // Create test nodes
    let nibble_path = NibblePath::new_with_nibbles(&[5]);
    let node_key = NodeKey::new(Version::new(1), nibble_path);
    let leaf_node = LeafNode::new(KeyHash::default(), OwnedValue::empty());
    let node = Node::Leaf(leaf_node);

    // Write node to the store
    let shard_idx = store.get_shard_index(&node_key);
    store.write_shard_batch(shard_idx, &[(node_key.clone(), node.clone())])?;

    // Verify node can be read back
    let actual_node = store.get_node(&node_key)?;
    assert_eq!(actual_node, node);

    Ok(())
}

/// Tests parallel writing to sharded storage.
#[test]
fn test_parallel_writing() -> Result<()> {
    let store = InMemoryShardedTreeStore::new(16);

    // Create a large batch of nodes
    let mut test_nodes = Vec::new();
    for i in 0..100 {
        let nibble = i % 16;
        let nibble_path = NibblePath::new_with_nibbles(&[nibble as u8, (i / 16) as u8]);
        let node_key = NodeKey::new(Version::new(1), nibble_path);
        let leaf_node = LeafNode::new(KeyHash::default(), OwnedValue::from(vec![i as u8]));
        let node = Node::Leaf(leaf_node);
        test_nodes.push((node_key, node));
    }

    // Create a node batch
    let mut nodes_map = std::collections::BTreeMap::new();
    let values_map = std::collections::BTreeMap::new();
    for (node_key, node) in &test_nodes {
        nodes_map.insert(node_key.clone(), node.clone());
    }
    let node_batch = jmt::writer::NodeBatch::new(nodes_map, values_map);

    // Write the batch in parallel
    store.write_node_batch(&node_batch)?;

    // Verify all nodes were written correctly
    for (node_key, expected_node) in &test_nodes {
        let actual_node = store.get_node(node_key)?;
        assert_eq!(actual_node, *expected_node);
    }

    Ok(())
}

/// Tests edge cases for sharded storage.
#[test]
fn test_sharded_storage_edge_cases() -> Result<()> {
    let store = InMemoryShardedTreeStore::new(16);

    // Test with empty batch
    let empty_batch = jmt::writer::NodeBatch::default();
    store.write_node_batch(&empty_batch)?;

    // Test with nodes that have the same shard index
    let mut nodes_map = std::collections::BTreeMap::new();
    let values_map = std::collections::BTreeMap::new();

    for i in 0..10 {
        let nibble_path = NibblePath::new_with_nibbles(&[3, i as u8]);
        let node_key = NodeKey::new(Version::new(1), nibble_path);
        let leaf_node = LeafNode::new(KeyHash::default(), OwnedValue::from(vec![i as u8]));
        let node = Node::Leaf(leaf_node);
        nodes_map.insert(node_key, node);
    }

    let node_batch = jmt::writer::NodeBatch::new(nodes_map, values_map);
    store.write_node_batch(&node_batch)?;

    Ok(())
}

/// Tests internal nodes in sharded storage.
#[test]
fn test_internal_nodes_in_sharded_storage() -> Result<()> {
    let store = InMemoryShardedTreeStore::new(16);

    // Create an internal node
    let nibble_path = NibblePath::new_with_nibbles(&[7]);
    let node_key = NodeKey::new(Version::new(1), nibble_path);
    
    let mut internal_node = InternalNode::default();
    // Add some children to the internal node
    for i in 0..4 {
        let child_nibble = i as u8;
        let child_hash = [i as u8; 32];
        internal_node = internal_node.with_child(child_nibble, child_hash);
    }

    let node = Node::Internal(internal_node);

    // Write the internal node
    let shard_idx = store.get_shard_index(&node_key);
    store.write_shard_batch(shard_idx, &[(node_key.clone(), node.clone())])?;

    // Verify the internal node can be read back
    let actual_node = store.get_node(&node_key)?;
    assert_eq!(actual_node, node);

    Ok(())
}
