// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use proptest::{collection::hash_set, prelude::*};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::runtime::Runtime;

use super::helper::{
    arb_existent_kvs_and_nonexistent_keys, arb_tree_with_index, test_get_leaf_count,
    test_get_range_proof, test_get_with_proof,
};
use crate::{
    mock::MockTreeStore,
    node_type::{Child, Node, NodeKey, NodeType},
    storage::{TreeReader, TreeUpdateBatch},
    tests::helper::{
        arb_kv_pair_with_distinct_last_nibble, test_get_with_proof_with_distinct_last_nibble,
    },
    types::{
        nibble::{nibble_path::NibblePath, Nibble},
        Version, PRE_GENESIS_VERSION,
    },
    JellyfishMerkleTree, KeyHash, MissingRootError,
};

fn update_nibble(original_key: &KeyHash, n: usize, nibble: u8) -> KeyHash {
    assert!(nibble < 16);
    let mut key = original_key.0;
    key[n / 2] = if n % 2 == 0 {
        key[n / 2] & 0x0f | nibble << 4
    } else {
        key[n / 2] & 0xf0 | nibble
    };
    KeyHash(key)
}

#[tokio::test]
async fn test_insert_to_empty_tree() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    // Tree is initially empty. Root is a null node. We'll insert a key-value pair which creates a
    // leaf node.
    let key = b"testkey";
    let value = vec![1u8, 2u8, 3u8, 4u8];

    // batch version
    let (_new_root_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key.into(), value.clone())]],
            None,
            0, /* version */
        )
        .await
        .unwrap();
    assert!(batch.stale_node_index_batch.is_empty());

    db.write_tree_update_batch(batch).await.unwrap();

    assert_eq!(
        tree.get(KeyHash::from(key), 0).await.unwrap().unwrap(),
        value
    );
}

#[tokio::test]
async fn test_insert_to_pre_genesis() {
    // Set up DB with pre-genesis state (one single leaf node).
    let db = MockTreeStore::default();
    let key1 = KeyHash([0x00u8; 32]);
    let value1 = vec![1u8, 2u8];
    let pre_genesis_root_key = NodeKey::new_empty_path(PRE_GENESIS_VERSION);
    db.put_node(pre_genesis_root_key, Node::new_leaf(key1, value1.clone()))
        .await
        .unwrap();

    // Genesis inserts one more leaf.
    let tree = JellyfishMerkleTree::new(&db);
    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![3u8, 4u8];
    // batch version
    let (_root_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2.clone())]],
            None,
            0, /* version */
        )
        .await
        .unwrap();

    // Check pre-genesis node prunes okay.
    assert_eq!(batch.stale_node_index_batch.len(), 1);
    db.write_tree_update_batch(batch).await.unwrap();
    assert_eq!(db.num_nodes().await, 4);
    db.purge_stale_nodes(0).await.unwrap();
    assert_eq!(db.num_nodes().await, 3);

    // Check mixed state reads okay.
    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 0).await.unwrap().unwrap(), value2);
}

#[tokio::test]
async fn test_insert_at_leaf_with_internal_created() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8, 2u8];

    let (_root0_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key1, value1.clone())]],
            None,
            0, /* version */
        )
        .await
        .unwrap();

    assert!(batch.stale_node_index_batch.is_empty());
    db.write_tree_update_batch(batch).await.unwrap();
    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);

    // Insert at the previous leaf node. Should generate an internal node at the root.
    // Change the 1st nibble to 15.
    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![3u8, 4u8];

    let (_root1_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2.clone())]],
            None,
            1, /* version */
        )
        .await
        .unwrap();
    assert_eq!(batch.stale_node_index_batch.len(), 1);
    db.write_tree_update_batch(batch).await.unwrap();

    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);
    assert!(tree.get(key2, 0).await.unwrap().is_none());
    assert_eq!(tree.get(key2, 1).await.unwrap().unwrap(), value2);

    // get # of nodes
    assert_eq!(db.num_nodes().await, 4 /* 1 + 3 */);

    let internal_node_key = NodeKey::new_empty_path(1);

    let leaf1 = Node::new_leaf(key1, value1);
    let leaf2 = Node::new_leaf(key2, value2);
    let mut children = HashMap::new();
    children.insert(
        Nibble::from(0),
        Child::new(leaf1.hash(), 1 /* version */, NodeType::Leaf),
    );
    children.insert(
        Nibble::from(15),
        Child::new(leaf2.hash(), 1 /* version */, NodeType::Leaf),
    );
    let internal = Node::new_internal(children);
    assert_eq!(
        db.get_node_option(&NodeKey::new_empty_path(0))
            .await
            .unwrap()
            .unwrap(),
        leaf1
    );
    assert_eq!(
        db.get_node_option(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(0)))
            .await
            .unwrap()
            .unwrap(),
        leaf1
    );
    assert_eq!(
        db.get_node_option(
            &internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(15))
        )
        .await
        .unwrap()
        .unwrap(),
        leaf2
    );
    assert_eq!(
        db.get_node_option(&internal_node_key)
            .await
            .unwrap()
            .unwrap(),
        internal
    );
}

#[tokio::test]
async fn test_insert_at_leaf_with_multiple_internals_created() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    // 1. Insert the first leaf into empty tree
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8, 2u8];

    let (_root0_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key1, value1.clone())]],
            None,
            0, /* version */
        )
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();
    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);

    // 2. Insert at the previous leaf node. Should generate a branch node at root.
    // Change the 2nd nibble to 1.
    let key2 = update_nibble(&key1, 1 /* nibble_index */, 1 /* nibble */);
    let value2 = vec![3u8, 4u8];

    let (_root1_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2.clone())]],
            None,
            1, /* version */
        )
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();
    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);
    assert!(tree.get(key2, 0).await.unwrap().is_none());
    assert_eq!(tree.get(key2, 1).await.unwrap().unwrap(), value2);

    assert_eq!(db.num_nodes().await, 5);

    let internal_node_key = NodeKey::new(1, NibblePath::new_odd(vec![0x00]));

    let leaf1 = Node::new_leaf(key1, value1.clone());
    let leaf2 = Node::new_leaf(key2, value2.clone());
    let internal = {
        let mut children = HashMap::new();
        children.insert(
            Nibble::from(0),
            Child::new(leaf1.hash(), 1 /* version */, NodeType::Leaf),
        );
        children.insert(
            Nibble::from(1),
            Child::new(leaf2.hash(), 1 /* version */, NodeType::Leaf),
        );
        Node::new_internal(children)
    };

    let root_internal = {
        let mut children = HashMap::new();
        children.insert(
            Nibble::from(0),
            Child::new(
                internal.hash(),
                1, /* version */
                NodeType::Internal { leaf_count: 2 },
            ),
        );
        Node::new_internal(children)
    };

    assert_eq!(
        db.get_node_option(&NodeKey::new_empty_path(0))
            .await
            .unwrap()
            .unwrap(),
        leaf1
    );
    assert_eq!(
        db.get_node_option(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(0)))
            .await
            .unwrap()
            .unwrap(),
        leaf1,
    );
    assert_eq!(
        db.get_node_option(&internal_node_key.gen_child_node_key(1 /* version */, Nibble::from(1)))
            .await
            .unwrap()
            .unwrap(),
        leaf2,
    );
    assert_eq!(
        db.get_node_option(&internal_node_key)
            .await
            .unwrap()
            .unwrap(),
        internal
    );
    assert_eq!(
        db.get_node_option(&NodeKey::new_empty_path(1))
            .await
            .unwrap()
            .unwrap(),
        root_internal,
    );

    // 3. Update leaf2 with new value
    let value2_update = vec![5u8, 6u8];
    let (_root2_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key2, value2_update.clone())]],
            None,
            2, /* version */
        )
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();
    assert!(tree.get(key2, 0).await.unwrap().is_none());
    assert_eq!(tree.get(key2, 1).await.unwrap().unwrap(), value2);
    assert_eq!(tree.get(key2, 2).await.unwrap().unwrap(), value2_update);

    // Get # of nodes.
    assert_eq!(db.num_nodes().await, 8);

    // Purge retired nodes.
    db.purge_stale_nodes(1).await.unwrap();
    assert_eq!(db.num_nodes().await, 7);
    db.purge_stale_nodes(2).await.unwrap();
    assert_eq!(db.num_nodes().await, 4);
    assert_eq!(tree.get(key1, 2).await.unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 2).await.unwrap().unwrap(), value2_update);
}

#[tokio::test]
async fn test_batch_insertion() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2        <- nibble 0
    //                      /   |   \
    //              internal    3    4               <- nibble 1
    //                 |
    //              internal                         <- nibble 2
    //              /      \
    //        internal      6                        <- nibble 3
    //           |
    //        internal                               <- nibble 4
    //        /      \
    //       1        5                              <- nibble 5
    //
    // Total: 12 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 2);
    let value2 = vec![2u8];
    let value2_update = vec![22u8];

    let key3 = update_nibble(&key1, 1, 3);
    let value3 = vec![3u8];

    let key4 = update_nibble(&key1, 1, 4);
    let value4 = vec![4u8];

    let key5 = update_nibble(&key1, 5, 5);
    let value5 = vec![5u8];

    let key6 = update_nibble(&key1, 3, 6);
    let value6 = vec![6u8];

    let batches = vec![
        vec![(key1, value1)],
        vec![(key2, value2)],
        vec![(key3, value3)],
        vec![(key4, value4)],
        vec![(key5, value5)],
        vec![(key6, value6)],
        vec![(key2, value2_update)],
    ];
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();

    let mut to_verify = one_batch.clone();
    // key2 was updated so we remove it.
    to_verify.remove(1);

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_root, batch) = tree
            .put_value_set(one_batch, 0 /* version */)
            .await
            .unwrap();
        db.write_tree_update_batch(batch).await.unwrap();

        for (k, v) in to_verify.iter() {
            assert_eq!(tree.get(*k, 0).await.unwrap().unwrap(), *v)
        }

        // get # of nodes
        assert_eq!(db.num_nodes().await, 12);
    }

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_roots, batch) = tree
            .batch_put_value_sets(batches, None, 0 /* first_version */)
            .await
            .unwrap();
        db.write_tree_update_batch(batch).await.unwrap();

        for (k, v) in to_verify.iter() {
            assert_eq!(tree.get(*k, 6).await.unwrap().unwrap(), *v)
        }

        // get # of nodes
        assert_eq!(
            db.num_nodes().await,
            26 /* 1 + 3 + 4 + 3 + 8 + 5 + 2 */
        );

        // Purge retired nodes('p' means purged and 'a' means added).
        // The initial state of the tree at version 0
        // ```test
        //   1(root)
        // ```
        db.purge_stale_nodes(1).await.unwrap();
        // ```text
        //   1 (p)           internal(a)
        //           ->     /        \
        //                 1(a)       2(a)
        // add 3, prune 1
        // ```
        assert_eq!(db.num_nodes().await, 25);
        db.purge_stale_nodes(2).await.unwrap();
        // ```text
        //     internal(p)             internal(a)
        //    /        \              /        \
        //   1(p)       2   ->   internal(a)    2
        //                       /       \
        //                      1(a)      3(a)
        // add 4, prune 2
        // ```
        assert_eq!(db.num_nodes().await, 23);
        db.purge_stale_nodes(3).await.unwrap();
        // ```text
        //         internal(p)                internal(a)
        //        /        \                 /        \
        //   internal(p)    2   ->     internal(a)     2
        //   /       \                /   |   \
        //  1         3              1    3    4(a)
        // add 3, prune 2
        // ```
        assert_eq!(db.num_nodes().await, 21);
        db.purge_stale_nodes(4).await.unwrap();
        // ```text
        //            internal(p)                         internal(a)
        //           /        \                          /        \
        //     internal(p)     2                    internal(a)    2
        //    /   |   \                            /   |   \
        //   1(p) 3    4           ->      internal(a) 3    4
        //                                     |
        //                                 internal(a)
        //                                     |
        //                                 internal(a)
        //                                     |
        //                                 internal(a)
        //                                 /      \
        //                                1(a)     5(a)
        // add 8, prune 3
        // ```
        assert_eq!(db.num_nodes().await, 18);
        db.purge_stale_nodes(5).await.unwrap();
        // ```text
        //                  internal(p)                             internal(a)
        //                 /        \                              /        \
        //            internal(p)    2                        internal(a)    2
        //           /   |   \                               /   |   \
        //   internal(p) 3    4                      internal(a) 3    4
        //       |                                      |
        //   internal(p)                 ->          internal(a)
        //       |                                   /      \
        //   internal                          internal      6(a)
        //       |                                |
        //   internal                          internal
        //   /      \                          /      \
        //  1        5                        1        5
        // add 5, prune 4
        // ```
        assert_eq!(db.num_nodes().await, 14);
        db.purge_stale_nodes(6).await.unwrap();
        // ```text
        //                         internal(p)                               internal(a)
        //                        /        \                                /        \
        //                   internal       2(p)                       internal       2(a)
        //                  /   |   \                                 /   |   \
        //          internal    3    4                        internal    3    4
        //             |                                         |
        //          internal                      ->          internal
        //          /      \                                  /      \
        //    internal      6                           internal      6
        //       |                                         |
        //    internal                                  internal
        //    /      \                                  /      \
        //   1        5                                1        5
        // add 2, prune 2
        // ```
        assert_eq!(db.num_nodes().await, 12);

        for (k, v) in to_verify.iter() {
            assert_eq!(tree.get(*k, 6).await.unwrap().unwrap(), *v)
        }
    }
}

#[tokio::test]
async fn test_non_existence() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);
    // ```text
    //                     internal(root)
    //                    /        \
    //                internal      2
    //                   |
    //                internal
    //                /      \
    //               1        3
    // Total: 7 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![2u8];

    let key3 = update_nibble(&key1, 2, 3);
    let value3 = vec![3u8];

    let (roots, batch) = tree
        .batch_put_value_sets(
            vec![vec![
                (key1, value1.clone()),
                (key2, value2.clone()),
                (key3, value3.clone()),
            ]],
            None,
            0, /* version */
        )
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();
    assert_eq!(tree.get(key1, 0).await.unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 0).await.unwrap().unwrap(), value2);
    assert_eq!(tree.get(key3, 0).await.unwrap().unwrap(), value3);
    // get # of nodes
    assert_eq!(db.num_nodes().await, 6);

    // test non-existing nodes.
    // 1. Non-existing node at root node
    {
        let non_existing_key = update_nibble(&key1, 0, 1);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).await.unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
    // 2. Non-existing node at non-root internal node
    {
        let non_existing_key = update_nibble(&key1, 1, 15);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).await.unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
    // 3. Non-existing node at leaf node
    {
        let non_existing_key = update_nibble(&key1, 2, 4);
        let (value, proof) = tree.get_with_proof(non_existing_key, 0).await.unwrap();
        assert_eq!(value, None);
        assert!(proof
            .verify_nonexistence(roots[0], non_existing_key)
            .is_ok());
    }
}

#[tokio::test]
async fn test_missing_root() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);
    let err = tree
        .get_with_proof(KeyHash::from(b"testkey"), 0)
        .await
        .err()
        .unwrap()
        .downcast::<MissingRootError>()
        .unwrap();
    assert_eq!(err.version, 0);
}

#[tokio::test]
async fn test_put_value_sets() {
    let mut keys = vec![];
    let mut values = vec![];
    let total_updates = 20;
    for i in 0..total_updates {
        keys.push(format!("key{}", i).into());
        values.push(format!("value{}", i).into_bytes());
    }

    let mut root_hashes_one_by_one = vec![];
    let mut batch_one_by_one = TreeUpdateBatch::default();
    {
        let mut iter = keys.clone().into_iter().zip(values.clone().into_iter());
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);
        for version in 0..10 {
            let mut keyed_value_set = vec![];
            for _ in 0..total_updates / 10 {
                keyed_value_set.push(iter.next().unwrap());
            }
            let (root, batch) = tree
                .put_value_set(keyed_value_set, version as Version)
                .await
                .unwrap();
            db.write_tree_update_batch(batch.clone()).await.unwrap();
            root_hashes_one_by_one.push(root);
            batch_one_by_one.node_batch.extend(batch.node_batch);
            batch_one_by_one
                .stale_node_index_batch
                .extend(batch.stale_node_index_batch);
            batch_one_by_one.node_stats.extend(batch.node_stats);
        }
    }
    {
        let mut iter = keys.into_iter().zip(values.into_iter());
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);
        let mut value_sets = vec![];
        for _ in 0..10 {
            let mut keyed_value_set = vec![];
            for _ in 0..total_updates / 10 {
                keyed_value_set.push(iter.next().unwrap());
            }
            value_sets.push(keyed_value_set);
        }
        let (root_hashes, batch) = tree
            .batch_put_value_sets(value_sets, None, 0 /* version */)
            .await
            .unwrap();
        assert_eq!(root_hashes, root_hashes_one_by_one);
        assert_eq!(batch, batch_one_by_one);
    }
}

async fn many_keys_get_proof_and_verify_tree_root(seed: &[u8], num_keys: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let _rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    let mut kvs = vec![];
    for i in 0..num_keys {
        let key = format!("key{}", i).into();
        let value = format!("value{}", i).into_bytes();
        kvs.push((key, value));
    }

    let (roots, batch) = tree
        .batch_put_value_sets(vec![kvs.clone()], None, 0 /* version */)
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();

    for (k, v) in kvs {
        let (value, proof) = tree.get_with_proof(k, 0).await.unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[0], k, Some(v)).is_ok());
    }
}

#[tokio::test]
async fn test_1000_keys() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_keys_get_proof_and_verify_tree_root(seed, 1000).await;
}

async fn many_versions_get_proof_and_verify_tree_root(seed: &[u8], num_versions: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let mut rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    let mut kvs = vec![];
    let mut roots = vec![];

    for i in 0..num_versions {
        let key = format!("key{}", i).into();
        let value = format!("value{}", i).into_bytes();
        let new_value = format!("new_value{}", i).into_bytes();
        kvs.push((key, value.clone(), new_value.clone()));
    }

    for (idx, (k, v_old, _v_new)) in kvs.iter().enumerate() {
        let (root, batch) = tree
            .batch_put_value_sets(vec![vec![(*k, v_old.clone())]], None, idx as Version)
            .await
            .unwrap();
        roots.push(root[0]);
        db.write_tree_update_batch(batch).await.unwrap();
    }

    // Update value of all keys
    for (idx, (k, _v_old, v_new)) in kvs.iter().enumerate() {
        let version = (num_versions + idx) as Version;
        let (root, batch) = tree
            .batch_put_value_sets(vec![vec![(*k, v_new.clone())]], None, version)
            .await
            .unwrap();
        roots.push(root[0]);
        db.write_tree_update_batch(batch).await.unwrap();
    }

    for (i, (k, v, _)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i..i + num_versions);
        let (value, proof) = tree
            .get_with_proof(*k, random_version as Version)
            .await
            .unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }

    for (i, (k, _, v)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i + num_versions..2 * num_versions);
        let (value, proof) = tree
            .get_with_proof(*k, random_version as Version)
            .await
            .unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }
}

#[tokio::test]
async fn test_1000_versions() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_versions_get_proof_and_verify_tree_root(seed, 1000).await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]


    #[test]
    fn proptest_get_with_proof((existent_kvs, nonexistent_keys) in arb_existent_kvs_and_nonexistent_keys(1000, 100)) {
        let rt = Runtime::new().unwrap();
        rt.block_on(
            test_get_with_proof((existent_kvs, nonexistent_keys))
        );
    }

    #[test]
    fn proptest_get_with_proof_with_distinct_last_nibble((kv1, kv2) in arb_kv_pair_with_distinct_last_nibble()) {
        let rt = Runtime::new().unwrap();
        rt.block_on(
            test_get_with_proof_with_distinct_last_nibble((kv1, kv2))
        );
    }

    #[test]
    fn proptest_get_range_proof((btree, n) in arb_tree_with_index(1000)) {
        let rt = Runtime::new().unwrap();
        rt.block_on(
            test_get_range_proof((btree, n))
        );
    }

    #[test]
    fn proptest_get_leaf_count(keys in hash_set(any::<KeyHash>(), 1..1000)) {
        let rt = Runtime::new().unwrap();
        rt.block_on(
            test_get_leaf_count(keys)
        );
    }
}
