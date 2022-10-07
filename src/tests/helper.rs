// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    ops::Bound,
};

use proptest::{
    collection::{btree_map, hash_map, hash_set, vec},
    prelude::*,
    sample,
};

use crate::{
    mock::MockTreeStore,
    node_type::LeafNode,
    storage::Node,
    types::{
        proof::{SparseMerkleInternalNode, SparseMerkleRangeProof},
        Version, PRE_GENESIS_VERSION,
    },
    Bytes32Ext, JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, SPARSE_MERKLE_PLACEHOLDER_HASH,
};

/// Computes the key immediately after `key`.
pub fn plus_one(key: KeyHash) -> KeyHash {
    assert_ne!(key, KeyHash([0xff; 32]));

    let mut buf = key.0;
    for i in (0..32).rev() {
        if buf[i] == 255 {
            buf[i] = 0;
        } else {
            buf[i] += 1;
            break;
        }
    }
    KeyHash(buf)
}

/// Initializes a DB with a set of key-value pairs by inserting one key at each version.
pub fn init_mock_db(kvs: &HashMap<KeyHash, OwnedValue>) -> (MockTreeStore, Version) {
    assert!(!kvs.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    for (i, (key, value)) in kvs.clone().into_iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(vec![(key, Some(value))], i as Version)
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }

    (db, (kvs.len() - 1) as Version)
}

/// Initializes a DB with a set of key-value pairs by inserting one key at each version, then
/// deleting the specified keys afterwards.
pub fn init_mock_db_with_deletions_afterwards(
    kvs: &HashMap<KeyHash, OwnedValue>,
    deletions: Vec<KeyHash>,
) -> (MockTreeStore, Version) {
    assert!(!kvs.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    for (i, (key, value)) in kvs.clone().into_iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(vec![(key, Some(value))], i as Version)
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }

    let after_insertions_version = kvs.len();

    for (i, key) in deletions.iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(
                vec![(*key, None)],
                (after_insertions_version + i) as Version,
            )
            .unwrap();
        db.write_tree_update_batch(write_batch).unwrap();
    }
    (db, (kvs.len() + deletions.len() - 1) as Version)
}

fn init_mock_db_versioned(
    operations_by_version: Vec<Vec<(KeyHash, Vec<u8>)>>,
) -> (MockTreeStore, Version) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            if operations.is_empty() {
                // skip empty write sets to avoid a panic
                continue;
            }

            let (_root_hash, write_batch) = tree
                .put_value_set(
                    // Convert un-option-wrapped values to option-wrapped values to be compatible with
                    // deletion-enabled put_value_set:
                    operations
                        .into_iter()
                        .map(|(key, value)| (key, Some(value)))
                        .collect(),
                    next_version as Version,
                )
                .unwrap();

            db.write_tree_update_batch(write_batch).unwrap();

            next_version += 1;
        }

        (db, next_version - 1 as Version)
    } else {
        (db, PRE_GENESIS_VERSION)
    }
}

fn init_mock_db_versioned_with_deletions(
    operations_by_version: Vec<Vec<(KeyHash, Option<Vec<u8>>)>>,
) -> (MockTreeStore, Version) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            if operations.is_empty() {
                // skip empty write sets to avoid a panic
                continue;
            }

            let (_root_hash, write_batch) = tree
                .put_value_set(operations, next_version as Version)
                .unwrap();
            db.write_tree_update_batch(write_batch).unwrap();

            next_version += 1;
        }

        (db, next_version - 1 as Version)
    } else {
        (db, PRE_GENESIS_VERSION)
    }
}

pub fn arb_existent_kvs_and_nonexistent_keys(
    num_kvs: usize,
    num_non_existing_keys: usize,
) -> impl Strategy<Value = (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>)> {
    hash_map(any::<KeyHash>(), any::<OwnedValue>(), 1..num_kvs).prop_flat_map(move |kvs| {
        let kvs_clone = kvs.clone();
        (
            Just(kvs),
            vec(
                any::<KeyHash>().prop_filter(
                    "Make sure these keys do not exist in the tree.",
                    move |key| !kvs_clone.contains_key(key),
                ),
                num_non_existing_keys,
            ),
        )
    })
}

pub fn arb_existent_kvs_and_deletions_and_nonexistent_keys(
    num_kvs: usize,
    num_non_existing_keys: usize,
) -> impl Strategy<Value = (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>, Vec<KeyHash>)> {
    hash_map(any::<KeyHash>(), any::<OwnedValue>(), 1..num_kvs).prop_flat_map(move |kvs| {
        let kvs_clone = kvs.clone();
        let keys: Vec<_> = kvs.keys().cloned().collect();
        let keys_count = keys.len();
        (
            Just(kvs),
            sample::subsequence(keys, 0..keys_count),
            vec(
                any::<KeyHash>().prop_filter(
                    "Make sure these keys do not exist in the tree.",
                    move |key| !kvs_clone.contains_key(key),
                ),
                num_non_existing_keys,
            ),
        )
    })
}

pub fn arb_interleaved_insertions_and_deletions(
    num_keys: usize,
    num_values: usize,
    num_insertions: usize,
    num_deletions: usize,
) -> impl Strategy<Value = Vec<(KeyHash, Option<OwnedValue>)>> {
    // Make a hash set of all the keys and a vector of all the values we'll use in this test
    (
        hash_set(any::<KeyHash>(), 1..=num_keys),
        // Values are sequential little-endian byte sequences starting from 0, with trailing zeroes
        // trimmed -- it doesn't really matter what they are for these tests, so we just use the
        // smallest distinct sequences we can
        (1..=num_values).prop_map(|end| {
            (0..end)
                .map(|i| {
                    let mut value = i.to_le_bytes().to_vec();
                    while let Some(byte) = value.last() {
                        if *byte != 0 {
                            break;
                        }
                        value.pop();
                    }
                    value
                })
                .collect::<Vec<_>>()
        }),
    )
        .prop_flat_map(move |(keys, values)| {
            // Create a random sequence of insertions using only the keys and values in the sets
            // (this permits keys to be inserted more than once, and with different values)
            let keys = keys.into_iter().collect::<Vec<_>>();
            vec(
                (sample::select(keys), sample::select(values).prop_map(Some)),
                1..num_insertions,
            )
            .prop_flat_map(move |insertions| {
                // Create a random sequence of deletions using only the keys that were actually inserted
                // (this permits keys to be deleted more than once, but not more times than they will
                // ever be inserted, though they may be deleted before they are inserted, in the end)
                let deletions = sample::subsequence(
                    insertions
                        .iter()
                        .map(|(key, _)| (*key, None))
                        .collect::<Vec<_>>(),
                    0..num_deletions.min(insertions.len()),
                );
                (Just(insertions), deletions)
            })
            .prop_flat_map(move |(insertions, deletions)| {
                // Shuffle together the insertions and the deletions into a single sequence
                let mut insertions_and_deletions = insertions;
                insertions_and_deletions.extend(deletions);
                Just(insertions_and_deletions).prop_shuffle()
            })
        })
}

pub fn arb_partitions<T>(
    num_partitions: usize,
    values: Vec<T>,
) -> impl Strategy<Value = Vec<Vec<T>>>
where
    T: Debug + Clone,
{
    assert_ne!(
        num_partitions, 0,
        "cannot partition a vector into 0 partitions"
    );

    let indices = sample::subsequence(
        (0..values.len()).collect::<Vec<_>>(),
        num_partitions.min(values.len()) - 1,
    );

    indices.prop_map(move |indices| {
        let mut partitions = Vec::with_capacity(num_partitions);
        let mut start = 0;
        for end in indices {
            if end - start > 0 {
                partitions.push(values[start..end].to_vec());
            } else {
                partitions.push(vec![]);
            }
            start = end;
        }
        partitions.push(values[start..].to_vec());
        partitions
    })
}

pub fn test_get_with_proof(
    (existent_kvs, nonexistent_keys): (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>),
) {
    let (db, version) = init_mock_db(&existent_kvs);
    let tree = JellyfishMerkleTree::new(&db);

    test_existent_keys_impl(&tree, version, &existent_kvs);
    test_nonexistent_keys_impl(&tree, version, &nonexistent_keys);
}

pub fn test_get_with_proof_with_deletions(
    (mut existent_kvs, deletions, mut nonexistent_keys): (
        HashMap<KeyHash, OwnedValue>,
        Vec<KeyHash>,
        Vec<KeyHash>,
    ),
) {
    let (db, version) = init_mock_db_with_deletions_afterwards(&existent_kvs, deletions.clone());
    let tree = JellyfishMerkleTree::new(&db);

    for key in deletions {
        // We shouldn't test deleted keys as existent; they should be tested as nonexistent:
        existent_kvs.remove(&key);
        nonexistent_keys.push(key);
    }

    test_existent_keys_impl(&tree, version, &existent_kvs);
    test_nonexistent_keys_impl(&tree, version, &nonexistent_keys);
}

pub fn test_clairvoyant_construction_matches_interleaved_construction(
    operations_by_version: Vec<Vec<(KeyHash, Option<OwnedValue>)>>,
) {
    // Create the expected list of key-value pairs as a hashmap by following the list of operations
    // in order, keeping track of only the latest value
    let mut expected_final_versions = HashMap::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        for (key, value) in operations {
            if value.is_some() {
                expected_final_versions.insert(*key, version);
            } else {
                expected_final_versions.remove(key);
            }
        }
    }

    // Reconstruct the list of operations "as if updates and deletions didn't happen", by filtering
    // for updates that don't match the final state we computed above
    let mut clairvoyant_operations_by_version = Vec::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        let mut clairvoyant_operations = Vec::new();
        for (key, value) in operations {
            // This operation must correspond to some existing key-value pair in the final state
            if let Some(&expected_version) = expected_final_versions.get(key) {
                // This operation must match the final version
                if expected_version == version {
                    // This operation must not be a deletion
                    if let Some(value) = value {
                        clairvoyant_operations.push((*key, value.clone()));
                    }
                }
            }
        }
        clairvoyant_operations_by_version.push(clairvoyant_operations);
    }

    let (db_without_deletions, version_without_deletions) =
        init_mock_db_versioned(clairvoyant_operations_by_version);
    let tree_without_deletions = JellyfishMerkleTree::new(&db_without_deletions);

    let root_hash_without_deletions =
        tree_without_deletions.get_root_hash(version_without_deletions);

    let (db_with_deletions, version_with_deletions) =
        init_mock_db_versioned_with_deletions(operations_by_version);
    let tree_with_deletions = JellyfishMerkleTree::new(&db_with_deletions);

    let root_hash_with_deletions = tree_with_deletions.get_root_hash(version_with_deletions);

    match (root_hash_without_deletions, root_hash_with_deletions) {
        (Ok(root_hash_without_deletions), Ok(root_hash_with_deletions)) => {
            assert_eq!(
                root_hash_without_deletions, root_hash_with_deletions,
                "root hashes mismatch"
            );
        }
        (Err(_), Err(_)) => {
            // Both trees failed to construct, so we can't compare root hashes, so instead we ensure
            // that both trees failed to return a root hash **precisely because they have no root node**:
            assert!(tree_without_deletions
                .get_root_node_option(version_without_deletions)
                .unwrap()
                .is_none());
            assert!(tree_with_deletions
                .get_root_node_option(version_with_deletions)
                .unwrap()
                .is_none());
        }
        (Ok(_), Err(_)) => {
            // If one tree failed to construct but the other didn't, then ensure that the root
            // node of the one that succeeded is the null node and the other is missing its root
            assert_eq!(
                tree_without_deletions
                    .get_root_node_option(version_without_deletions)
                    .unwrap(),
                Some(Node::Null)
            );
            assert!(tree_with_deletions
                .get_root_node_option(version_with_deletions)
                .unwrap()
                .is_none());
        }
        (Err(_), Ok(_)) => {
            // If one tree failed to construct but the other didn't, then ensure that the root
            // node of the one that succeeded is the null node and the other is missing its root
            assert!(tree_without_deletions
                .get_root_node_option(version_without_deletions)
                .unwrap()
                .is_none());
            assert_eq!(
                tree_with_deletions
                    .get_root_node_option(version_with_deletions)
                    .unwrap(),
                Some(Node::Null)
            );
        }
    }
}

pub fn arb_kv_pair_with_distinct_last_nibble(
) -> impl Strategy<Value = ((KeyHash, OwnedValue), (KeyHash, OwnedValue))> {
    (
        any::<KeyHash>().prop_filter("Can't be 0xffffff...", |key| *key != KeyHash([0xff; 32])),
        vec(any::<OwnedValue>(), 2),
    )
        .prop_map(|(key1, accounts)| {
            let key2 = plus_one(key1);
            ((key1, accounts[0].clone()), (key2, accounts[1].clone()))
        })
}

pub fn test_get_with_proof_with_distinct_last_nibble(
    (kv1, kv2): ((KeyHash, OwnedValue), (KeyHash, OwnedValue)),
) {
    let mut kvs = HashMap::new();
    kvs.insert(kv1.0, kv1.1);
    kvs.insert(kv2.0, kv2.1);

    let (db, version) = init_mock_db(&kvs);
    let tree = JellyfishMerkleTree::new(&db);

    test_existent_keys_impl(&tree, version, &kvs);
}

pub fn arb_tree_with_index(
    tree_size: usize,
) -> impl Strategy<Value = (BTreeMap<KeyHash, OwnedValue>, usize)> {
    btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..tree_size).prop_flat_map(|btree| {
        let len = btree.len();
        (Just(btree), 0..len)
    })
}

pub fn test_get_range_proof((btree, n): (BTreeMap<KeyHash, OwnedValue>, usize)) {
    let (db, version) = init_mock_db(&btree.clone().into_iter().collect());
    let tree = JellyfishMerkleTree::new(&db);

    let nth_key = btree.keys().nth(n).unwrap();

    let proof = tree.get_range_proof(*nth_key, version).unwrap();
    verify_range_proof(
        tree.get_root_hash(version).unwrap(),
        btree.into_iter().take(n + 1).collect(),
        proof,
    );
}

fn test_existent_keys_impl<'a>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore>,
    version: Version,
    existent_kvs: &HashMap<KeyHash, OwnedValue>,
) {
    let root_hash = tree.get_root_hash(version).unwrap();

    for (key, value) in existent_kvs {
        let (account, proof) = tree.get_with_proof(*key, version).unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert_eq!(account.unwrap(), *value);
    }
}

fn test_nonexistent_keys_impl<'a>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore>,
    version: Version,
    nonexistent_keys: &[KeyHash],
) {
    let root_hash = tree.get_root_hash(version).unwrap();

    for key in nonexistent_keys {
        let (account, proof) = tree.get_with_proof(*key, version).unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert_eq!(account, None);
    }
}

/// Checks if we can construct the expected root hash using the entries in the btree and the proof.
fn verify_range_proof(
    expected_root_hash: RootHash,
    btree: BTreeMap<KeyHash, OwnedValue>,
    proof: SparseMerkleRangeProof,
) {
    // For example, given the following sparse Merkle tree:
    //
    //                   root
    //                  /     \
    //                 /       \
    //                /         \
    //               o           o
    //              / \         / \
    //             a   o       o   h
    //                / \     / \
    //               o   d   e   X
    //              / \         / \
    //             b   c       f   g
    //
    // we transform the keys as follows:
    //   a => 00,
    //   b => 0100,
    //   c => 0101,
    //   d => 011,
    //   e => 100,
    //   X => 101
    //   h => 11
    //
    // Basically, the suffixes that doesn't affect the common prefix of adjacent leaves are
    // discarded. In this example, we assume `btree` has the keys `a` to `e` and the proof has `X`
    // and `h` in the siblings.

    // Now we want to construct a set of key-value pairs that covers the entire set of leaves. For
    // `a` to `e` this is simple -- we just insert them directly into this set. For the rest of the
    // leaves, they are represented by the siblings, so we just make up some keys that make sense.
    // For example, for `X` we just use 101000... (more zeros omitted), because that is one key
    // that would cause `X` to end up in the above position.
    let mut btree1 = BTreeMap::new();
    for (key, value) in &btree {
        let leaf = LeafNode::new(*key, value.clone());
        btree1.insert(*key, leaf.hash());
    }
    // Using the above example, `last_proven_key` is `e`. We look at the path from root to `e`.
    // For each 0-bit, there should be a sibling in the proof. And we use the path from root to
    // this position, plus a `1` as the key.
    let last_proven_key = *btree
        .keys()
        .last()
        .expect("We are proving at least one key.");
    for (i, sibling) in last_proven_key
        .0
        .iter_bits()
        .enumerate()
        .filter_map(|(i, bit)| if !bit { Some(i) } else { None })
        .zip(proof.right_siblings().iter().rev())
    {
        // This means the `i`-th bit is zero. We take `i` bits from `last_proven_key` and append a
        // one to make up the key for this sibling.
        let mut buf: Vec<_> = last_proven_key.0.iter_bits().take(i).collect();
        buf.push(true);
        // The rest doesn't matter, because they don't affect the position of the node. We just
        // add zeros.
        buf.resize(256, false);
        let key = KeyHash(<[u8; 32]>::from_bit_iter(buf.into_iter()).unwrap());
        btree1.insert(key, *sibling);
    }

    // Now we do the transformation (removing the suffixes) described above.
    let mut kvs = vec![];
    for (key, value) in &btree1 {
        // The length of the common prefix of the previous key and the current key.
        let prev_common_prefix_len =
            prev_key(&btree1, key).map(|pkey| pkey.0.common_prefix_bits_len(&key.0));
        // The length of the common prefix of the next key and the current key.
        let next_common_prefix_len =
            next_key(&btree1, key).map(|nkey| nkey.0.common_prefix_bits_len(&key.0));

        // We take the longest common prefix of the current key and its neighbors. That's how much
        // we need to keep.
        let len = match (prev_common_prefix_len, next_common_prefix_len) {
            (Some(plen), Some(nlen)) => std::cmp::max(plen, nlen),
            (Some(plen), None) => plen,
            (None, Some(nlen)) => nlen,
            (None, None) => 0,
        };
        let transformed_key: Vec<_> = key.0.iter_bits().take(len + 1).collect();
        kvs.push((transformed_key, *value));
    }

    assert_eq!(compute_root_hash(kvs), expected_root_hash);
}

/// Reduces the problem by removing the first bit of every key.
fn reduce<'a>(kvs: &'a [(&[bool], [u8; 32])]) -> Vec<(&'a [bool], [u8; 32])> {
    kvs.iter().map(|(key, value)| (&key[1..], *value)).collect()
}

/// Returns the key immediately before `key` in `btree`.
fn prev_key<K, V>(btree: &BTreeMap<K, V>, key: &K) -> Option<K>
where
    K: Clone + Ord,
{
    btree
        .range((Bound::Unbounded, Bound::Excluded(key)))
        .next_back()
        .map(|(k, _v)| k.clone())
}

fn next_key<K, V>(btree: &BTreeMap<K, V>, key: &K) -> Option<K>
where
    K: Clone + Ord,
{
    btree
        .range((Bound::Excluded(key), Bound::Unbounded))
        .next()
        .map(|(k, _v)| k.clone())
}

/// Computes the root hash of a sparse Merkle tree. `kvs` consists of the entire set of key-value
/// pairs stored in the tree.
fn compute_root_hash(kvs: Vec<(Vec<bool>, [u8; 32])>) -> RootHash {
    let mut kv_ref = vec![];
    for (key, value) in &kvs {
        kv_ref.push((&key[..], *value));
    }
    RootHash(compute_root_hash_impl(kv_ref))
}

fn compute_root_hash_impl(kvs: Vec<(&[bool], [u8; 32])>) -> [u8; 32] {
    assert!(!kvs.is_empty());

    // If there is only one entry, it is the root.
    if kvs.len() == 1 {
        return kvs[0].1;
    }

    // Otherwise the tree has more than one leaves, which means we can find which ones are in the
    // left subtree and which ones are in the right subtree. So we find the first key that starts
    // with a 1-bit.
    let left_hash;
    let right_hash;
    match kvs.iter().position(|(key, _value)| key[0]) {
        Some(0) => {
            // Every key starts with a 1-bit, i.e., they are all in the right subtree.
            left_hash = SPARSE_MERKLE_PLACEHOLDER_HASH;
            right_hash = compute_root_hash_impl(reduce(&kvs));
        }
        Some(index) => {
            // Both left subtree and right subtree have some keys.
            left_hash = compute_root_hash_impl(reduce(&kvs[..index]));
            right_hash = compute_root_hash_impl(reduce(&kvs[index..]));
        }
        None => {
            // Every key starts with a 0-bit, i.e., they are all in the left subtree.
            left_hash = compute_root_hash_impl(reduce(&kvs));
            right_hash = SPARSE_MERKLE_PLACEHOLDER_HASH;
        }
    }

    SparseMerkleInternalNode::new(left_hash, right_hash).hash()
}

pub fn test_get_leaf_count(keys: HashSet<KeyHash>) {
    let kvs = keys.into_iter().map(|k| (k, vec![])).collect();
    let (db, version) = init_mock_db(&kvs);
    let tree = JellyfishMerkleTree::new(&db);
    assert_eq!(tree.get_leaf_count(version).unwrap().unwrap(), kvs.len())
}
