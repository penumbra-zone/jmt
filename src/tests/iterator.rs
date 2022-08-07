// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use futures::StreamExt;
use rand::{rngs::StdRng, Rng, SeedableRng};

use super::helper::plus_one;
use crate::{
    iterator::JellyfishMerkleStream, mock::MockTreeStore, types::Version, JellyfishMerkleTree,
    KeyHash, OwnedValue,
};

#[tokio::test]
async fn test_iterator_same_version() {
    for i in (1..100).step_by(11) {
        test_n_leaves_same_version(i).await;
    }
}

#[tokio::test]
async fn test_iterator_multiple_versions() {
    test_n_leaves_multiple_versions(50).await;
}

#[tokio::test]
async fn test_long_path() {
    test_n_consecutive_addresses(50).await;
}

async fn test_n_leaves_same_version(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = JellyfishMerkleTree::new(&*db);

    let mut rng = StdRng::from_seed([1; 32]);

    let mut btree = BTreeMap::new();
    for i in 0..n {
        let key = KeyHash(rng.gen());
        let value = Some(i.to_be_bytes().to_vec());
        assert_eq!(btree.insert(key, value), None);
    }

    let (_root_hash, batch) = tree
        .put_value_set(btree.clone().into_iter().collect(), 0 /* version */)
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();

    let btree = btree
        .into_iter()
        .collect::<BTreeMap<KeyHash, Option<OwnedValue>>>();

    run_tests(db, &btree, 0 /* version */).await;
}

async fn test_n_leaves_multiple_versions(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = JellyfishMerkleTree::new(&*db);

    let mut btree = BTreeMap::new();
    for i in 0..n {
        let key = format!("key{}", i).into();
        let value = Some(i.to_be_bytes().to_vec());
        assert_eq!(btree.insert(key, value.clone()), None);
        let (_root_hash, batch) = tree
            .put_value_set(vec![(key, value)], i as Version)
            .await
            .unwrap();
        db.write_tree_update_batch(batch).await.unwrap();
        run_tests(Arc::clone(&db), &btree, i as Version).await;
    }
}

async fn test_n_consecutive_addresses(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = JellyfishMerkleTree::new(&*db);

    let btree: BTreeMap<_, _> = (0..n)
        .map(|i| {
            let mut buf = [0u8; 32];
            buf[24..].copy_from_slice(&(i as u64).to_be_bytes());
            (KeyHash(buf), Some(i.to_be_bytes().to_vec()))
        })
        .collect();

    let (_root_hash, batch) = tree
        .put_value_set(btree.clone().into_iter().collect(), 0 /* version */)
        .await
        .unwrap();
    db.write_tree_update_batch(batch).await.unwrap();

    run_tests(db, &btree, 0 /* version */).await;
}

async fn run_tests(
    db: Arc<MockTreeStore>,
    btree: &BTreeMap<KeyHash, Option<OwnedValue>>,
    version: Version,
) {
    {
        let iter = JellyfishMerkleStream::new(Arc::clone(&db), version, KeyHash([0u8; 32]))
            .await
            .unwrap();
        assert_eq!(
            iter.collect::<Vec<Result<_>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            btree
                .clone()
                .into_iter()
                // Remove all k-v pairs whose value is `None`, because they have been logically deleted
                .filter_map(|(k, v)| v.map(move |v| (k, v)))
                .collect::<Vec<_>>(),
        );
    }

    for i in 0..btree.len() {
        {
            let iter = JellyfishMerkleStream::new_by_index(Arc::clone(&db), version, i)
                .await
                .unwrap();
            assert_eq!(
                iter.collect::<Vec<Result<_>>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()
                    .unwrap(),
                btree
                    .clone()
                    .into_iter() // Remove all k-v pairs whose value is `None`, because they have been logically deleted
                    .filter_map(|(k, v)| v.map(move |v| (k, v)))
                    .skip(i)
                    .collect::<Vec<_>>(),
            );
        }

        let ith_key = *btree.keys().nth(i).unwrap();

        {
            let iter = JellyfishMerkleStream::new(Arc::clone(&db), version, ith_key)
                .await
                .unwrap();
            assert_eq!(
                iter.collect::<Vec<Result<_>>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()
                    .unwrap(),
                btree
                    .clone()
                    .into_iter() // Remove all k-v pairs whose value is `None`, because they have been logically deleted
                    .filter_map(|(k, v)| v.map(move |v| (k, v)))
                    .skip(i)
                    .collect::<Vec<_>>(),
            );
        }

        {
            let ith_key_plus_one = plus_one(ith_key);
            let iter = JellyfishMerkleStream::new(Arc::clone(&db), version, ith_key_plus_one)
                .await
                .unwrap();
            assert_eq!(
                iter.collect::<Vec<Result<_>>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()
                    .unwrap(),
                btree
                    .clone()
                    .into_iter()
                    // Remove all k-v pairs whose value is `None`, because they have been logically deleted
                    .filter_map(|(k, v)| v.map(move |v| (k, v)))
                    .skip(i + 1)
                    .map(|(x, y)| (x, y))
                    .collect::<Vec<_>>(),
            );
        }
    }

    {
        let iter = JellyfishMerkleStream::new_by_index(Arc::clone(&db), version, btree.len())
            .await
            .unwrap();
        assert_eq!(
            iter.collect::<Vec<Result<_>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            vec![]
        );
    }

    {
        let iter = JellyfishMerkleStream::new(Arc::clone(&db), version, KeyHash([0xFF; 32]))
            .await
            .unwrap();
        assert_eq!(
            iter.collect::<Vec<Result<_>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            vec![]
        );
    }
}
