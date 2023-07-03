/// This file reproduces most of the tests within the helper folder but
/// adds update proof verification in the test helpers.
use std::collections::HashMap;

use alloc::sync::Arc;
use sha2::{
    digest::{
        core_api::{CoreWrapper, CtVariableCoreWrapper},
        typenum::{UInt, UTerm, B0, B1},
    },
    OidSha256, Sha256VarCore,
};

use crate::{
    mock::MockTreeStore, proof::definition::UpdateMerkleProof, storage::Node,
    types::PRE_GENESIS_VERSION, JellyfishMerkleIterator, KeyHash, OwnedValue, RootHash, Sha256Jmt,
    Version,
};

type MockUpdateMerkleProof = UpdateMerkleProof<
    CoreWrapper<
        CtVariableCoreWrapper<
            Sha256VarCore,
            UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
            OidSha256,
        >,
    >,
    std::vec::Vec<u8>,
>;

fn init_mock_db_versioned_proved(
    operations_by_version: Vec<Vec<(KeyHash, Vec<u8>)>>,
) -> (
    Vec<(RootHash, MockUpdateMerkleProof)>,
    MockTreeStore,
    Version,
) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);
    let mut roots_proofs: Vec<(RootHash, MockUpdateMerkleProof)> = Vec::new();

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            let (root_hash, proof, write_batch) = tree
                .put_value_set_with_proof(
                    // Convert un-option-wrapped values to option-wrapped values to be compatible with
                    // deletion-enabled put_value_set:
                    operations
                        .into_iter()
                        .map(|(key, value)| (key, Some(value))),
                    next_version as Version,
                )
                .unwrap();

            db.write_tree_update_batch(write_batch).unwrap();

            roots_proofs.push((root_hash, proof));

            next_version += 1;
        }

        (roots_proofs, db, next_version - 1 as Version)
    } else {
        (roots_proofs, db, PRE_GENESIS_VERSION)
    }
}

fn init_mock_db_versioned_with_deletions_proved(
    operations_by_version: Vec<Vec<(KeyHash, Option<Vec<u8>>)>>,
) -> (
    Vec<(RootHash, MockUpdateMerkleProof)>,
    MockTreeStore,
    Version,
) {
    assert!(!operations_by_version.is_empty());

    let db = MockTreeStore::default();
    let tree = Sha256Jmt::new(&db);
    let mut roots_proofs: Vec<(RootHash, MockUpdateMerkleProof)> = Vec::new();

    if operations_by_version
        .iter()
        .any(|operations| !operations.is_empty())
    {
        let mut next_version = 0;

        for operations in operations_by_version.into_iter() {
            let (root_hash, proof, write_batch) = tree
                .put_value_set_with_proof(operations, next_version as Version)
                .unwrap();
            db.write_tree_update_batch(write_batch).unwrap();

            roots_proofs.push((root_hash, proof));

            next_version += 1;
        }

        (roots_proofs, db, next_version - 1 as Version)
    } else {
        (roots_proofs, db, PRE_GENESIS_VERSION)
    }
}

/// A very general test that demonstrates that given a sequence of insertions and deletions, batched
/// by version, the end result of having performed those operations is identical to having *already
/// known* what the end result would be, and only performing the insertions necessary to get there,
/// with no insertions that would have been overwritten, and no deletions at all.
/// This test differs from [`test_clairvoyant_construction_matches_interleaved_construction`] by
/// constructing (and verifying) update proofs.
pub fn test_clairvoyant_construction_matches_interleaved_construction_proved(
    operations_by_version: Vec<Vec<(KeyHash, Option<OwnedValue>)>>,
) {
    // Create the expected list of key-value pairs as a hashmap by following the list of operations
    // in order, keeping track of only the latest value
    let mut expected_final = HashMap::new();
    for (version, operations) in operations_by_version.iter().enumerate() {
        for (key, value) in operations {
            if let Some(value) = value {
                expected_final.insert(*key, (version, value.clone()));
            } else {
                expected_final.remove(key);
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
            if let Some((expected_version, _)) = expected_final.get(key) {
                // This operation must not be a deletion
                if let Some(value) = value {
                    // The version must be the final version that will end up in the result
                    if version == *expected_version {
                        clairvoyant_operations.push((*key, value.clone()));
                    }
                }
            }
        }
        clairvoyant_operations_by_version.push(clairvoyant_operations);
    }

    // Compute the root hash of the version without deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (roots_proofs_without_deletions, db_without_deletions, version_without_deletions) =
        init_mock_db_versioned_proved(clairvoyant_operations_by_version);
    let tree_without_deletions = Sha256Jmt::new(&db_without_deletions);

    let root_hash_without_deletions =
        tree_without_deletions.get_root_hash(version_without_deletions);

    // Compute the root hash of the version with deletions (note that the computed root hash is a
    // `Result` which we haven't unwrapped yet)
    let (roots_proofs_with_deletions, db_with_deletions, version_with_deletions) =
        init_mock_db_versioned_with_deletions_proved(operations_by_version);
    let tree_with_deletions = Sha256Jmt::new(&db_with_deletions);

    let root_hash_with_deletions = tree_with_deletions.get_root_hash(version_with_deletions);

    // If either of the resultant trees are in a pre-genesis state (because no operations were
    // performed), then we can't compare their root hashes, because they won't have any root
    match (
        version_without_deletions == PRE_GENESIS_VERSION,
        version_with_deletions == PRE_GENESIS_VERSION,
    ) {
        (false, false) => {
            // If neither was uninitialized by the sequence of operations, their root hashes should
            // match each other, and should both exist
            assert_eq!(
                root_hash_without_deletions.unwrap(),
                root_hash_with_deletions.unwrap(),
                "root hashes mismatch"
            );
        }
        (true, true) => {
            // If both were uninitialized by the sequence of operations, both attempts to get their
            // root hashes should be met with failure, because they have no root node, so ensure
            // that both actually are errors
            assert!(root_hash_without_deletions.is_err());
            assert!(root_hash_with_deletions.is_err());
        }
        (true, false) => {
            // If only the one without deletions was uninitialized by the sequence of operations,
            // then the attempt to get its root hash should be met with failure, because it has no
            // root node
            assert!(root_hash_without_deletions.is_err());
            // And the one that was initialized should have a root hash equivalent to the hash of
            // the null node, since it should contain nothing
            assert_eq!(
                root_hash_with_deletions.unwrap(),
                RootHash(Node::Null.hash())
            );
        }
        (false, true) => {
            // If only the one with deletions was uninitialized by the sequence of operations,
            // then the attempt to get its root hash should be met with failure, because it has no
            // root node
            assert!(root_hash_with_deletions.is_err());
            // And the one that was initialized should have a root hash equivalent to the hash of
            // the null node, since it should contain nothing
            assert_eq!(
                root_hash_without_deletions.unwrap(),
                RootHash(Node::Null.hash())
            );
        }
    }

    // We know need to check that the updates from the tree have been performed correctly.
    // We need to loop over the vectors of proofs and verify each one
    if version_without_deletions != PRE_GENESIS_VERSION {
        let mut old_root = RootHash(Node::new_null().hash());
        for (new_root, proof) in roots_proofs_without_deletions {
            assert!(proof.verify_update(old_root, new_root).is_ok());
            old_root = new_root;
        }
    }

    // We know need to check that the updates from the tree have been performed correctly.
    // We need to loop over the vectors of proofs and verify each one
    if version_with_deletions != PRE_GENESIS_VERSION {
        let mut old_root = RootHash(Node::new_null().hash());
        for (new_root, proof) in roots_proofs_with_deletions {
            assert!(proof.verify_update(old_root, new_root).is_ok());
            old_root = new_root;
        }
    }

    // After having checked that the root hashes match, it's time to check that the actual values
    // contained in the trees match. We use the JellyfishMerkleIterator to extract a sorted list of
    // key-value pairs from each, and compare to the expected mapping:

    // Get all the key-value pairs in the version without deletions
    let iter_without_deletions = if version_without_deletions != PRE_GENESIS_VERSION {
        JellyfishMerkleIterator::new(
            Arc::new(db_without_deletions),
            version_without_deletions,
            KeyHash([0u8; 32]),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    } else {
        vec![]
    };

    // Get all the key-value pairs in the version with deletions
    let iter_with_deletions = if version_with_deletions != PRE_GENESIS_VERSION {
        JellyfishMerkleIterator::new(
            Arc::new(db_with_deletions),
            version_with_deletions,
            KeyHash([0u8; 32]),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    } else {
        vec![]
    };

    // Get the expected key-value pairs
    let mut iter_expected = expected_final
        .into_iter()
        .map(|(k, (_, v))| (k, v))
        .collect::<Vec<_>>();
    iter_expected.sort();

    // Assert that both with and without deletions, both are equal to the expected final contents
    assert_eq!(
        iter_expected, iter_without_deletions,
        "clairvoyant construction mismatches expectation"
    );
    assert_eq!(
        iter_expected, iter_with_deletions,
        "construction interleaved with deletions mismatches expectation"
    );
}
