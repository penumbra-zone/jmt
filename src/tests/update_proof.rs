use proptest::{proptest, strategy::Strategy};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::Sha256;

use crate::{
    mock::MockTreeStore,
    proof,
    storage::Node,
    tests::{
        helper::{arb_interleaved_insertions_and_deletions, arb_partitions},
        helper_update_with_proof::test_clairvoyant_construction_matches_interleaved_construction_proved,
    },
    JellyfishMerkleTree, KeyHash, RootHash, Sha256Jmt, Version,
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

fn insert_and_perform_checks(batches: Vec<Vec<(KeyHash, Option<Vec<u8>>)>>) {
    let one_batch = batches.iter().flatten().cloned().collect::<Vec<_>>();
    // Insert as one batch and update one by one.
    {
        let db = MockTreeStore::default();
        let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

        let (root, proof, batch) = tree
            .put_value_set_with_proof(one_batch, 0 /* version */)
            .unwrap();
        db.write_tree_update_batch(batch).unwrap();

        assert!(proof
            .verify_update(RootHash(Node::new_null().hash()), root)
            .is_ok());
    }

    // Insert in multiple batches.
    {
        let db = MockTreeStore::default();
        let tree: JellyfishMerkleTree<MockTreeStore, Sha256> = JellyfishMerkleTree::new(&db);

        let (_roots, batch) = tree.put_value_sets(batches, 0 /* first_version */).unwrap();
        db.write_tree_update_batch(batch).unwrap();
    }
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

    insert_and_perform_checks(batches);
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

    insert_and_perform_checks(batches);
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

    insert_and_perform_checks(batches);
    insert_and_perform_checks(batches2);
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

    insert_and_perform_checks(batches);
}

#[test]
fn test_delete_simple() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                           1          2 (delete)  <- nibble 0
    //
    // Total: 2 nodes
    // ```
    let key1 = KeyHash([0u8; 32]);
    let value1 = vec![1u8];

    let key2 = update_nibble(&key1, 0, 2);
    let value2 = vec![2u8];

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key2, None)],
    ];

    insert_and_perform_checks(batches);
}

#[test]
fn test_delete_simple2() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2            <- nibble 0
    //                      /   |   \
    //                     1    3    4 (deleted)         <- nibble 1
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

    let batches = vec![
        vec![(key1, Some(value1))],
        vec![(key2, Some(value2))],
        vec![(key3, Some(value3))],
        vec![(key4, Some(value4))],
        vec![(key4, None)],
    ];
    insert_and_perform_checks(batches);
}

#[test]
fn test_delete_complex() {
    // ```text
    //                             internal(root)
    //                            /        \
    //                       internal       2 (deleted)  <- nibble 0
    //                      /   |   \
    //              internal    3    4 (deleted)         <- nibble 1
    //                 |
    //              internal                             <- nibble 2
    //              /      \
    //        internal      6 (deleted)                  <- nibble 3
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
        vec![(key4, None)],
        vec![(key6, Some(value6))],
        vec![(key2, None)],
        vec![(key6, None)],
        vec![(key5, None)],
        vec![(key3, None)],
        vec![(key1, None)],
    ];

    insert_and_perform_checks(batches);
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

proptest!(
// This is a replica of the test below, with the values tuned to the smallest values that were
// useful when isolating bugs. Set `PROPTEST_MAX_SHRINK_ITERS=5000000` to shrink enough to
// isolate bugs down to minimal examples when hunting using this test. Good hunting.
#[test]
fn proptest_clairvoyant_construction_matches_interleaved_construction_small_proved(
    operations_by_version in
        (1usize..4) // possible numbers of versions
            .prop_flat_map(|versions| {
                arb_interleaved_insertions_and_deletions(2, 1, 5, 15) // (distinct keys, distinct values, insertions, deletions)
                    .prop_flat_map(move |ops| arb_partitions(versions, ops))
        })
) {
    test_clairvoyant_construction_matches_interleaved_construction_proved(operations_by_version)
}

// This is a replica of the test above, but with much larger parameters for more exhaustive
// testing. It won't feasibly shrink to a useful counterexample because the generators for these
// tests are not very efficient for shrinking. For some exhaustive fuzzing, try setting
// `PROPTEST_CASES=10000`, which takes about 30 seconds on a fast machine.
#[test]
fn proptest_clairvoyant_construction_matches_interleaved_construction_proved(
    operations_by_version in
        (1usize..500) // possible numbers of versions
            .prop_flat_map(|versions| {
                arb_interleaved_insertions_and_deletions(100, 100, 1000, 1000) // (distinct keys, distinct values, insertions, deletions)
                    .prop_flat_map(move |ops| arb_partitions(versions, ops))
        })
) {
    test_clairvoyant_construction_matches_interleaved_construction_proved(operations_by_version)
}

);
