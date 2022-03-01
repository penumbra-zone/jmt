// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Bound,
};

use proptest::{
    collection::{btree_map, hash_map, vec},
    prelude::*,
};

use crate::{
    mock::MockTreeStore,
    node_type::LeafNode,
    types::{
        proof::{SparseMerkleInternalNode, SparseMerkleRangeProof},
        Version,
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
pub async fn init_mock_db(kvs: &HashMap<KeyHash, OwnedValue>) -> (MockTreeStore, Version) {
    assert!(!kvs.is_empty());

    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    for (i, (key, value)) in kvs.clone().into_iter().enumerate() {
        let (_root_hash, write_batch) = tree
            .put_value_set(vec![(key, value)], i as Version)
            .await
            .unwrap();
        db.write_tree_update_batch(write_batch).await.unwrap();
    }

    (db, (kvs.len() - 1) as Version)
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

pub async fn test_get_with_proof(
    (existent_kvs, nonexistent_keys): (HashMap<KeyHash, OwnedValue>, Vec<KeyHash>),
) {
    let (db, version) = init_mock_db(&existent_kvs).await;
    let tree = JellyfishMerkleTree::new(&db);

    test_existent_keys_impl(&tree, version, &existent_kvs);
    test_nonexistent_keys_impl(&tree, version, &nonexistent_keys);
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

pub async fn test_get_with_proof_with_distinct_last_nibble(
    (kv1, kv2): ((KeyHash, OwnedValue), (KeyHash, OwnedValue)),
) {
    let mut kvs = HashMap::new();
    kvs.insert(kv1.0, kv1.1);
    kvs.insert(kv2.0, kv2.1);

    let (db, version) = init_mock_db(&kvs).await;
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

pub async fn test_get_range_proof((btree, n): (BTreeMap<KeyHash, OwnedValue>, usize)) {
    let (db, version) = init_mock_db(&btree.clone().into_iter().collect()).await;
    let tree = JellyfishMerkleTree::new(&db);

    let nth_key = btree.keys().nth(n).unwrap();

    let proof = tree.get_range_proof(*nth_key, version).await.unwrap();
    verify_range_proof(
        tree.get_root_hash(version).await.unwrap(),
        btree.into_iter().take(n + 1).collect(),
        proof,
    );
}

async fn test_existent_keys_impl<'a>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore>,
    version: Version,
    existent_kvs: &HashMap<KeyHash, OwnedValue>,
) {
    let root_hash = tree.get_root_hash(version).await.unwrap();

    for (key, value) in existent_kvs {
        let (account, proof) = tree.get_with_proof(*key, version).await.unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert_eq!(account.unwrap(), *value);
    }
}

async fn test_nonexistent_keys_impl<'a>(
    tree: &JellyfishMerkleTree<'a, MockTreeStore>,
    version: Version,
    nonexistent_keys: &[KeyHash],
) {
    let root_hash = tree.get_root_hash(version).await.unwrap();

    for key in nonexistent_keys {
        let (account, proof) = tree.get_with_proof(*key, version).await.unwrap();
        assert!(proof.verify(root_hash, *key, account.as_ref()).is_ok());
        assert!(account.is_none());
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

pub async fn test_get_leaf_count(keys: HashSet<KeyHash>) {
    let kvs = keys.into_iter().map(|k| (k, vec![])).collect();
    let (db, version) = init_mock_db(&kvs).await;
    let tree = JellyfishMerkleTree::new(&db);
    assert_eq!(
        tree.get_leaf_count(version).await.unwrap().unwrap(),
        kvs.len()
    )
}
