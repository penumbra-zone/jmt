use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::Sha256;

use crate::{
    mock::MockTreeStore, storage::Node, JellyfishMerkleTree, KeyHash, RootHash, Sha256Jmt, Version,
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

// Simple update proof test to check we can produce and verify merkle proofs for insertion
#[test]
fn test_update_proof() {
    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);
    // ```text
    //                     internal(root)
    //                    /        \
    //                internal      2
    //                   |
    //                internal
    //                /      \
    //               1        3
    // Total: 6 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 15);
    let value2 = vec![2u8];

    let key3 = update_nibble(&key1, 2, 3);
    let value3 = vec![3u8];

    let (mut new_root_hash_and_proofs, batch) = tree
        .put_value_sets_with_proof(
            vec![
                vec![(key1, Some(value1.clone()))],
                vec![(key2, Some(value2.clone()))],
                vec![(key3, Some(value3.clone()))],
            ],
            0, /* version */
        )
        .unwrap();

    // Verify we get the correct values of the tree
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, 0).unwrap().unwrap(), value1);
    assert_eq!(tree.get(key2, 1).unwrap().unwrap(), value2);
    assert_eq!(tree.get(key3, 2).unwrap().unwrap(), value3);

    assert_eq!(db.num_nodes(), 9);

    let (root_hash3, proof3) = new_root_hash_and_proofs.pop().unwrap();
    let (root_hash2, proof2) = new_root_hash_and_proofs.pop().unwrap();
    let (root_hash1, proof1) = new_root_hash_and_proofs.pop().unwrap();

    assert!(proof1
        .verify_update(RootHash(Node::new_null().hash()), root_hash1)
        .is_ok());

    assert!(proof2.verify_update(root_hash1, root_hash2).is_ok());

    assert!(proof3.verify_update(root_hash2, root_hash3).is_ok());
}

#[test]
fn test_prove_multiple_insertions() {
    // ```text
    //                     internal(root)
    //                    /        \
    //                internal      2
    //                /      \
    //               1        3
    // Total: 6 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 2);
    let value2 = vec![2u8];

    let key3 = update_nibble(&key1, 1, 3);
    let value3 = vec![3u8];

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key3, Some(value3))],
    ];
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();

    let to_verify = one_batch.clone();
    let verify_fn = |tree: &JellyfishMerkleTree<MockTreeStore, Sha256>, version: Version| {
        to_verify
            .iter()
            .for_each(|(k, v)| assert_eq!(Some(tree.get(*k, version).unwrap().unwrap()), *v))
    };

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (roots_proofs, batch) = tree
            .put_value_sets_with_proof(batches, 0 /* first_version */)
            .unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 6);

        let mut last_root = RootHash(Node::new_null().hash());
        for (new_root, update_proof) in roots_proofs {
            assert!(update_proof.verify_update(last_root, new_root).is_ok());
            last_root = new_root;
        }
    }

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (last_root, update_proof, batch) = tree
            .put_value_set_with_proof(one_batch, 0 /* version */)
            .unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 0);

        // get # of nodes
        assert_eq!(db.num_nodes(), 5);

        assert!(update_proof
            .verify_update(RootHash(Node::new_null().hash()), last_root)
            .is_ok());
    }
}

#[test]
fn test_prove_complex_insertion() {
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

    let key3 = update_nibble(&key1, 1, 3);
    let value3 = vec![3u8];

    let key4 = update_nibble(&key1, 1, 4);
    let value4 = vec![4u8];

    let key5 = update_nibble(&key1, 5, 5);
    let value5 = vec![5u8];

    let key6 = update_nibble(&key1, 3, 6);
    let value6 = vec![6u8];

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key3, Some(value3))],
        vec![(key4, Some(value4))],
        vec![(key5, Some(value5))],
        vec![(key6, Some(value6))],
    ];
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();

    let to_verify = one_batch.clone();
    let verify_fn = |tree: &JellyfishMerkleTree<MockTreeStore, Sha256>, version: Version| {
        to_verify
            .iter()
            .for_each(|(k, v)| assert_eq!(Some(tree.get(*k, version).unwrap().unwrap()), *v))
    };

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_root, batch) = tree.put_value_set(one_batch, 0 /* version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 0);

        // get # of nodes
        assert_eq!(db.num_nodes(), 12);
    }

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let (_roots, batch) = tree.put_value_sets(batches, 0 /* first_version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();
        verify_fn(&tree, 6);
    }
}

#[test]
// Same as last test, expect we update some nodes
fn test_prove_insertion_separate() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2            <- nibble 0
    //                      /   |   \
    //                     1    3    4                   <- nibble 1
    //
    //
    // Total: 4 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 2);
    let value2 = vec![2u8];

    let key3 = update_nibble(&key1, 1, 3);
    let value3 = vec![3u8];

    let key4 = update_nibble(&key1, 1, 4);
    let value4 = vec![4u8];

    let batches = vec![vec![
        (key1, Some(value1)),
        (key2, Some(value2)),
        (key3, Some(value3)),
    ]];
    let batches2 = vec![vec![(key4, Some(value4))]];

    let one_batch1 = batches.iter().flatten().cloned().collect::<Vec<_>>();
    let one_batch2 = batches2.iter().flatten().cloned().collect::<Vec<_>>();

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

        let (last_root1, update_proof1, batch1) = tree
            .put_value_set_with_proof(one_batch1, 0 /* version */)
            .unwrap();
        db.write_tree_update_batch(batch1).unwrap();

        assert!(update_proof1
            .verify_update(RootHash(Node::new_null().hash()), last_root1)
            .is_ok());

        let (last_root2, update_proof2, batch2) = tree
            .put_value_set_with_proof(one_batch2, 1 /* version */)
            .unwrap();
        db.write_tree_update_batch(batch2).unwrap();

        assert!(update_proof2.verify_update(last_root1, last_root2).is_ok());
    }
}
#[test]
// Same as last test, expect we update some nodes
fn test_prove_update() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2 (then 22)  <- nibble 0
    //                      /   |   \
    //              internal    3    4 (then 20)         <- nibble 1
    //                 |
    //              internal                             <- nibble 2
    //              /      \
    //        internal      6 (then 10)                  <- nibble 3
    //           |
    //        internal                                   <- nibble 4
    //        /      \
    //       1        5 .                                <- nibble 5
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
    let value4_update = vec![20u8];

    let key5 = update_nibble(&key1, 5, 5);
    let value5 = vec![5u8];

    let key6 = update_nibble(&key1, 3, 6);
    let value6 = vec![6u8];
    let value6_update = vec![10u8];

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key3, Some(value3))],
        vec![(key4, Some(value4))],
        vec![(key5, Some(value5))],
        vec![(key4, Some(value4_update))],
        vec![(key6, Some(value6))],
        vec![(key2, Some(value2_update))],
        vec![(key6, Some(value6_update))],
    ];
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();

    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

        let (_root, batch) = tree.put_value_set(one_batch, 0 /* version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();

        // get # of nodes
        assert_eq!(db.num_nodes(), 12);
    }

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

        let (_roots, batch) = tree.put_value_sets(batches, 0 /* first_version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();

        // get # of nodes # higher because of updates
        assert_eq!(db.num_nodes(), 34);
    }
}

#[test]
fn test_gets_then_delete_with_proof() {
    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);

    let key1: KeyHash = KeyHash([1; 32]);

    let value = "".to_string().into_bytes();

    let (mut update_root, batch) = tree
        .put_value_sets_with_proof(
            vec![vec![(key1, Some(value.clone()))], vec![(key1, None)]],
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    let (root2, proof2) = update_root.pop().unwrap();
    let (root1, proof1) = update_root.pop().unwrap();

    assert!(proof1
        .verify_update(RootHash(Node::new_null().hash()), root1)
        .is_ok());
    assert!(proof2.verify_update(root1, root2).is_ok());
}

fn many_keys_update_proof_and_verify_tree_root(seed: &[u8], num_keys: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let _rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);

    let mut kvs = vec![];
    for i in 0..num_keys {
        let key = KeyHash::with::<Sha256>(format!("key{}", i));
        let value = format!("value{}", i).into_bytes();
        kvs.push((key, Some(value)));
    }

    let (roots_and_proofs, batch) = tree
        .put_value_sets_with_proof(vec![kvs.clone()], 0 /* version */)
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    let first_root = roots_and_proofs[0].0;

    let mut curr_root = RootHash(Node::new_null().hash());
    for (root, proof) in roots_and_proofs {
        assert!(proof.verify_update(curr_root, root).is_ok());
        curr_root = root;
    }

    for (k, v) in kvs {
        let (value, proof) = tree.get_with_proof(k, 0).unwrap();
        assert_eq!(value.unwrap(), *v.clone().unwrap());
        assert!(proof.verify(first_root, k, v).is_ok());
    }
}

#[test]
fn test_1000_keys() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_keys_update_proof_and_verify_tree_root(seed, 1000);
}

fn many_versions_update_proof_and_verify_tree_root(seed: &[u8], num_versions: usize) {
    assert!(seed.len() < 32);
    let mut actual_seed = [0u8; 32];
    actual_seed[..seed.len()].copy_from_slice(seed);
    let mut rng: StdRng = StdRng::from_seed(actual_seed);

    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);

    let mut kvs = vec![];
    let mut roots = vec![];

    for i in 0..num_versions {
        let key = KeyHash::with::<Sha256>(format!("key{}", i));
        let value = format!("value{}", i).into_bytes();
        let new_value = format!("new_value{}", i).into_bytes();
        kvs.push((key, value.clone(), new_value.clone()));
    }

    let mut curr_root = RootHash(Node::new_null().hash());
    for (idx, (k, v_old, _v_new)) in kvs.iter().enumerate() {
        let (roots_and_proofs, batch) = tree
            .put_value_sets_with_proof(vec![vec![(*k, Some(v_old.clone()))]], idx as Version)
            .unwrap();
        roots.push(roots_and_proofs[0].0);
        db.write_tree_update_batch(batch).unwrap();

        for (root, proof) in roots_and_proofs {
            assert!(proof.verify_update(curr_root, root).is_ok());
            curr_root = root;
        }
    }

    // Update value of all keys
    for (idx, (k, _v_old, v_new)) in kvs.iter().enumerate() {
        let version = (num_versions + idx) as Version;
        let (roots_and_proofs, batch) = tree
            .put_value_sets_with_proof(vec![vec![(*k, Some(v_new.clone()))]], version)
            .unwrap();
        roots.push(roots_and_proofs[0].0);
        db.write_tree_update_batch(batch).unwrap();

        for (root, proof) in roots_and_proofs {
            assert!(proof.verify_update(curr_root, root).is_ok());
            curr_root = root;
        }
    }

    for (i, (k, v, _)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i..i + num_versions);
        let (value, proof) = tree.get_with_proof(*k, random_version as Version).unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }

    for (i, (k, _, v)) in kvs.iter().enumerate() {
        let random_version = rng.gen_range(i + num_versions..2 * num_versions);
        let (value, proof) = tree.get_with_proof(*k, random_version as Version).unwrap();
        assert_eq!(value.unwrap(), *v);
        assert!(proof.verify(roots[random_version], *k, Some(v)).is_ok());
    }
}

#[test]
fn test_1000_versions() {
    let seed: &[_] = &[1, 2, 3, 4];
    many_versions_update_proof_and_verify_tree_root(seed, 1000);
}
