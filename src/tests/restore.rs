// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use proptest::{collection::btree_map, prelude::*};
use tokio::sync::RwLock;

use crate::{
    mock::MockTreeStore,
    restore::{JellyfishMerkleRestore, StateSnapshotReceiver},
    storage::TreeReader,
    tests::helper::init_mock_db,
    JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, Version,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_restore_without_interruption(
        btree in btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..1000),
        target_version in 0u64..2000,
    ) {
        let restore_db = Arc::new(RwLock::new(MockTreeStore::default()));
        // For this test, restore everything without interruption.
        restore_without_interruption(&btree, target_version, &restore_db, true);
    }

    #[test]
    fn test_restore_with_interruption(
        (all, batch1_size) in btree_map(any::<KeyHash>(), any::<OwnedValue>(), 2..1000)
            .prop_flat_map(|btree| {
                let len = btree.len();
                (Just(btree), 1..len)
            })
    ) {


        use tokio::runtime::Runtime;

        let runtime = Runtime::new().unwrap();

        runtime.block_on(async move {

        let (db, version) = init_mock_db(
            &all.clone()
                .into_iter()
                .collect()
        ).await;
        let tree = JellyfishMerkleTree::new(&db);
        let expected_root_hash = tree.get_root_hash(version).await.unwrap();
        let batch1: Vec<_> = all.clone().into_iter().take(batch1_size).collect();

        let restore_db = Arc::new(RwLock::new(MockTreeStore::default()));
        {
            let mut restore = JellyfishMerkleRestore::new(
                Arc::clone(&restore_db), version, expected_root_hash, true /* leaf_count_migraion */
            ).await.unwrap();
            let proof = tree
                .get_range_proof(batch1.last().map(|(key, _value)| *key).unwrap(), version)
                .await.unwrap();
            restore.add_chunk(
                batch1.into_iter()
                    .collect(),
                proof
            ).await.unwrap();
            // Do not call `finish`.
        }

        {
            let rightmost_key = match restore_db.read().await.get_rightmost_leaf().await.unwrap() {
                None => {
                    // Sometimes the batch is too small so nothing is written to DB.
                    return;
                }
                Some((_, node)) => node.key_hash(),
            };
            let remaining_accounts: Vec<_> = all
                .clone()
                .into_iter()
                .filter(|(k, _v)| *k > rightmost_key)
                .collect();

            let mut restore = JellyfishMerkleRestore::new(
                 Arc::clone(&restore_db), version, expected_root_hash, true /* leaf_count_migration */
            ).await.unwrap();
            let proof = tree
                .get_range_proof(
                    remaining_accounts.last().map(|(key, _value)| *key).unwrap(),
                    version,
                )
                .await.unwrap();
            restore.add_chunk(
                remaining_accounts.into_iter()
                    .collect(),
                proof
            ).await.unwrap();
            restore.finish().await.unwrap();
        }

        assert_success(&*restore_db.read().await, expected_root_hash, &all, version).await;

        });
    }

    #[test]
    fn test_overwrite(
        btree1 in btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..1000),
        btree2 in btree_map(any::<KeyHash>(), any::<OwnedValue>(), 1..1000),
        target_version in 0u64..2000,
    ) {
        let restore_db = Arc::new(RwLock::new(MockTreeStore::new(true /* allow_overwrite */)));
        restore_without_interruption(&btree1, target_version, &restore_db, true);
        // overwrite, an entirely different tree
        restore_without_interruption(&btree2, target_version, &restore_db, false);
    }
}

async fn assert_success(
    db: &MockTreeStore,
    expected_root_hash: RootHash,
    btree: &BTreeMap<KeyHash, OwnedValue>,
    version: Version,
) {
    let tree = JellyfishMerkleTree::new(db);
    for (key, value) in btree {
        assert_eq!(tree.get(*key, version).await.unwrap(), Some(value.clone()));
    }

    let actual_root_hash = tree.get_root_hash(version).await.unwrap();
    assert_eq!(actual_root_hash, expected_root_hash);
}

async fn restore_without_interruption(
    btree: &BTreeMap<KeyHash, OwnedValue>,
    target_version: Version,
    target_db: &Arc<RwLock<MockTreeStore>>,
    try_resume: bool,
) {
    let (db, source_version) = init_mock_db(&btree.clone().into_iter().collect()).await;
    let tree = JellyfishMerkleTree::new(&db);
    let expected_root_hash = tree.get_root_hash(source_version).await.unwrap();

    let mut restore = if try_resume {
        JellyfishMerkleRestore::new(
            Arc::clone(target_db),
            target_version,
            expected_root_hash,
            true, /* account_count_migration */
        )
        .await
        .unwrap()
    } else {
        JellyfishMerkleRestore::new_overwrite(
            Arc::clone(target_db),
            target_version,
            expected_root_hash,
            true, /* account_count_migration */
        )
        .unwrap()
    };
    for (key, value) in btree {
        let proof = tree.get_range_proof(*key, source_version).await.unwrap();
        restore
            .add_chunk(vec![(*key, value.clone())], proof)
            .await
            .unwrap();
    }
    Box::new(restore).finish().await.unwrap();

    assert_success(
        &*target_db.read().await,
        expected_root_hash,
        btree,
        target_version,
    );
}
