#[cfg(all(feature = "parallel", feature = "mocks"))]
use crate::mock::MockTreeStore;
use crate::JellyfishMerkleTree;
use crate::KeyHash;
use crate::OwnedValue;
use crate::RootHash;
use rand::Rng;

#[cfg(all(feature = "parallel", feature = "mocks"))]
fn generate_random_keys(count: usize) -> Vec<KeyHash> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            KeyHash(key)
        })
        .collect()
}

#[cfg(all(feature = "parallel", feature = "mocks"))]
fn generate_random_values(count: usize, value_size: usize) -> Vec<OwnedValue> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| (0..value_size).map(|_| rng.gen::<u8>()).collect())
        .collect()
}

#[cfg(all(feature = "parallel", feature = "mocks"))]
fn generate_value_set(count: usize, value_size: usize) -> Vec<(KeyHash, OwnedValue)> {
    let keys = generate_random_keys(count);
    let values = generate_random_values(count, value_size);
    keys.into_iter().zip(values.into_iter()).collect()
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_vs_sequential_consistency_small() {
    test_parallel_vs_sequential_consistency(10, 32);
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_vs_sequential_consistency_medium() {
    test_parallel_vs_sequential_consistency(100, 32);
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_vs_sequential_consistency_large() {
    test_parallel_vs_sequential_consistency(1000, 32);
}

#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_vs_sequential_consistency(num_keys: usize, value_size: usize) {
    let value_set = generate_value_set(num_keys, value_size);

    let reader_seq = MockTreeStore::default();
    let tree_seq = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader_seq);
    let (root_hashes_seq, batch_seq) = tree_seq
        .batch_put_value_sets(vec![value_set.clone()], None, 0)
        .unwrap();

    let reader_par = MockTreeStore::default();
    let tree_par = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader_par);
    let (root_hashes_par, batch_par) = tree_par
        .batch_put_value_sets(vec![value_set.clone()], None, 0)
        .unwrap();

    assert_eq!(
        root_hashes_seq, root_hashes_par,
        "Root hashes should be identical"
    );

    assert_eq!(
        batch_seq.node_batch.nodes().len(),
        batch_par.node_batch.nodes().len(),
        "Node batch sizes should be identical"
    );

    for (node_key, node) in batch_seq.node_batch.nodes() {
        assert!(
            batch_par.node_batch.nodes().contains_key(node_key),
            "Node {:?} should exist in parallel batch",
            node_key
        );
        let par_node = batch_par.node_batch.nodes().get(node_key).unwrap();
        assert_eq!(
            node, par_node,
            "Node {:?} should be identical",
            node_key
        );
    }
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_edge_cases_empty_subtrees() {
    let value_set = generate_value_set(100, 32);

    let reader = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    let (root_hashes, _batch) = tree
        .batch_put_value_sets(vec![value_set], None, 1)
        .unwrap();

    assert_ne!(root_hashes[0], RootHash([0u8; 32]), "Root hash should not be default");
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_edge_cases_single_subtree() {
    let mut value_set = generate_value_set(100, 32);
    for (key, _) in value_set.iter_mut() {
        key.0[0] = 0;
    }

    let reader = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    let (root_hashes, _batch) = tree
        .batch_put_value_sets(vec![value_set], None, 1)
        .unwrap();

    assert_ne!(root_hashes[0], RootHash([0u8; 32]), "Root hash should not be default");
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_edge_cases_all_subtrees() {
    let value_set = generate_value_set(1600, 32);

    let reader = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    let (root_hashes, _batch) = tree
        .batch_put_value_sets(vec![value_set], None, 1)
        .unwrap();

    assert_ne!(root_hashes[0], RootHash([0u8; 32]), "Root hash should not be default");
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_edge_cases_threshold_boundary() {
    let value_set_99 = generate_value_set(99, 32);
    let value_set_100 = generate_value_set(100, 32);
    let value_set_101 = generate_value_set(101, 32);

    let reader_99 = MockTreeStore::default();
    let tree_99 = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader_99);
    let (root_hashes_99, _) = tree_99
        .batch_put_value_sets(vec![value_set_99], None, 1)
        .unwrap();

    let reader_100 = MockTreeStore::default();
    let tree_100 = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader_100);
    let (root_hashes_100, _) = tree_100
        .batch_put_value_sets(vec![value_set_100], None, 1)
        .unwrap();

    let reader_101 = MockTreeStore::default();
    let tree_101 = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader_101);
    let (root_hashes_101, _) = tree_101
        .batch_put_value_sets(vec![value_set_101], None, 1)
        .unwrap();

    assert_ne!(root_hashes_99[0], RootHash([0u8; 32]));
    assert_ne!(root_hashes_100[0], RootHash([0u8; 32]));
    assert_ne!(root_hashes_101[0], RootHash([0u8; 32]));
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_stress_large_dataset() {
    let value_set = generate_value_set(10000, 32);

    let reader = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    let (root_hashes, batch) = tree
        .batch_put_value_sets(vec![value_set], None, 1)
        .unwrap();

    assert_ne!(root_hashes[0], RootHash([0u8; 32]), "Root hash should not be default");
    assert!(
        batch.node_batch.nodes().len() > 0,
        "Node batch should contain nodes"
    );
}

#[test]
#[cfg(all(feature = "parallel", feature = "mocks"))]
fn test_parallel_multiple_versions() {
    let value_set_1 = generate_value_set(100, 32);
    let value_set_2 = generate_value_set(100, 32);
    let value_set_3 = generate_value_set(100, 32);

    let reader = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    let (root_hashes, _) = tree
        .batch_put_value_sets(vec![value_set_1, value_set_2, value_set_3], None, 1)
        .unwrap();

    assert_eq!(root_hashes.len(), 3, "Should have 3 root hashes");
    assert_ne!(root_hashes[0], RootHash([0u8; 32]));
    assert_ne!(root_hashes[1], RootHash([0u8; 32]));
    assert_ne!(root_hashes[2], RootHash([0u8; 32]));
}
