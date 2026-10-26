//! Tests for the stale node index and pruning.
//!
//! All tests are built around a single oracle: after pruning up to `least_readable_version`, the
//! store must hold *exactly* the nodes reachable from the roots of the retained versions
//! `least_readable_version..=latest_version`.
//!   - A reachable node that is missing means pruning removed a live node (over-pruning).
//!   - A node that is not reachable means it was never indexed as stale (leak).
//!
//! The per-version form of the same invariant is checked on every write: the stale index entries
//! with `stale_since_version == v` must be exactly `reachable(v - 1) \ reachable(v)`.
//!
//! Reachability is computed against an "archive" store that receives the same batches as the
//! pruned store but is never pruned.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use proptest::prelude::*;
use sha2::Sha256;

use crate::{
    mock::MockTreeStore,
    node_type::{Node, NodeKey},
    storage::{TreeReader, TreeUpdateBatch},
    types::Version,
    JellyfishMerkleTree, KeyHash, OwnedValue,
};

type ValueSet = Vec<(KeyHash, Option<OwnedValue>)>;

/// Returns the keys of all nodes reachable from the root of `version`.
fn reachable_nodes<R: TreeReader>(reader: &R, version: Version) -> BTreeSet<NodeKey> {
    let mut reachable = BTreeSet::new();
    let mut stack = vec![NodeKey::new_empty_path(version)];
    while let Some(node_key) = stack.pop() {
        let node = reader
            .get_node(&node_key)
            .unwrap_or_else(|e| panic!("version {version}: node {node_key:?} is missing: {e}"));
        if let Node::Internal(internal) = &node {
            for (nibble, child) in internal.children_unsorted() {
                stack.push(node_key.gen_child_node_key(child.version, nibble));
            }
        }
        reachable.insert(node_key);
    }
    reachable
}

/// Drives a pruned store and an archive store in lockstep and checks the pruning invariants
/// after every write and every prune.
struct PruningHarness {
    /// Receives every batch and is never pruned. Used as the reference for reachability.
    archive: MockTreeStore,
    /// Receives every batch and is pruned. New versions are computed against this store, like
    /// a production node would.
    pruned: MockTreeStore,
    /// Expected key-value state at each committed version.
    states: Vec<BTreeMap<KeyHash, OwnedValue>>,
    /// Every key ever written; used to probe reads at retained versions.
    keys: BTreeSet<KeyHash>,
    least_readable_version: Version,
}

impl PruningHarness {
    fn new() -> Self {
        Self {
            archive: MockTreeStore::default(),
            pruned: MockTreeStore::default(),
            states: Vec::new(),
            keys: BTreeSet::new(),
            least_readable_version: 0,
        }
    }

    fn next_version(&self) -> Version {
        self.states.len() as Version
    }

    fn latest_version(&self) -> Version {
        self.next_version() - 1
    }

    /// Commits `value_sets` as consecutive versions in a single `put_value_sets` call.
    fn commit(&mut self, value_sets: Vec<ValueSet>) {
        let first_version = self.next_version();
        let (_, batch) = JellyfishMerkleTree::<_, Sha256>::new(&self.pruned)
            .put_value_sets(value_sets.clone(), first_version)
            .unwrap_or_else(|e| panic!("failed to compute version {first_version}: {e:?}"));
        self.apply(batch, value_sets);
    }

    /// Commits `value_sets`, which must contain only inserts, as consecutive versions in a single
    /// `batch_put_value_sets` call.
    fn commit_with_batch_api(&mut self, value_sets: Vec<ValueSet>) {
        let first_version = self.next_version();
        let inserts = value_sets
            .iter()
            .map(|value_set| {
                value_set
                    .iter()
                    .map(|(key, value)| (*key, value.clone().expect("only inserts are supported")))
                    .collect()
            })
            .collect();
        let (_, batch) = JellyfishMerkleTree::<_, Sha256>::new(&self.pruned)
            .batch_put_value_sets(inserts, None, first_version)
            .unwrap_or_else(|e| panic!("failed to compute version {first_version}: {e:?}"));
        self.apply(batch, value_sets);
    }

    fn apply(&mut self, batch: TreeUpdateBatch, value_sets: Vec<ValueSet>) {
        let first_version = self.next_version();
        self.write(batch.clone());

        for value_set in value_sets {
            let mut state = self.states.last().cloned().unwrap_or_default();
            for (key, value) in value_set {
                self.keys.insert(key);
                match value {
                    Some(value) => state.insert(key, value),
                    None => state.remove(&key),
                };
            }
            self.states.push(state);
        }

        self.assert_stale_index_is_exact(&batch, first_version..=self.latest_version());
    }

    fn write(&self, batch: TreeUpdateBatch) {
        self.archive.write_tree_update_batch(batch.clone()).unwrap();
        self.pruned.write_tree_update_batch(batch).unwrap();
    }

    /// Checks that the nodes indexed as stale at version `v` are exactly the nodes that are
    /// reachable from the root of `v - 1` but not from the root of `v`.
    fn assert_stale_index_is_exact(
        &self,
        batch: &TreeUpdateBatch,
        versions: core::ops::RangeInclusive<Version>,
    ) {
        for index in &batch.stale_node_index_batch {
            assert!(
                versions.contains(&index.stale_since_version),
                "stale index {index:?} is outside of the committed versions {versions:?}",
            );
        }
        for version in versions {
            let indexed: BTreeSet<NodeKey> = batch
                .stale_node_index_batch
                .iter()
                .filter(|index| index.stale_since_version == version)
                .map(|index| index.node_key.clone())
                .collect();
            let previous = if version == 0 {
                BTreeSet::new()
            } else {
                reachable_nodes(&self.archive, version - 1)
            };
            let current = reachable_nodes(&self.archive, version);
            let expected: BTreeSet<NodeKey> = previous.difference(&current).cloned().collect();

            let not_indexed: Vec<_> = expected.difference(&indexed).collect();
            let wrongly_indexed: Vec<_> = indexed.difference(&expected).collect();
            assert!(
                not_indexed.is_empty() && wrongly_indexed.is_empty(),
                "version {version}: stale index is wrong\n  \
                 replaced but not indexed (will leak): {not_indexed:?}\n  \
                 indexed but still live (will be over-pruned): {wrongly_indexed:?}",
            );
        }
    }

    /// Prunes the pruned store so that `least_readable_version` is the oldest readable version
    /// and checks that it holds exactly the nodes of the retained versions, all of them readable.
    fn prune(&mut self, least_readable_version: Version) {
        assert!(least_readable_version <= self.latest_version());
        self.pruned
            .purge_stale_nodes(least_readable_version)
            .unwrap_or_else(|e| panic!("purge_stale_nodes({least_readable_version}): {e:?}"));
        self.least_readable_version = self.least_readable_version.max(least_readable_version);
        self.assert_store_holds_exactly_retained_versions();
        self.assert_retained_versions_are_readable();
    }

    fn assert_store_holds_exactly_retained_versions(&self) {
        let retained = self.least_readable_version..=self.latest_version();
        let mut expected = BTreeSet::new();
        for version in retained.clone() {
            expected.extend(reachable_nodes(&self.archive, version));
        }
        let actual = self.pruned.node_keys();

        let over_pruned: Vec<_> = expected.difference(&actual).collect();
        let leaked: Vec<_> = actual.difference(&expected).collect();
        assert!(
            over_pruned.is_empty() && leaked.is_empty(),
            "after pruning, retained versions {retained:?}:\n  \
             live nodes that were pruned: {over_pruned:?}\n  \
             unreachable nodes that were never pruned: {leaked:?}",
        );
    }

    fn assert_retained_versions_are_readable(&self) {
        let pruned = JellyfishMerkleTree::<_, Sha256>::new(&self.pruned);
        let archive = JellyfishMerkleTree::<_, Sha256>::new(&self.archive);
        for version in self.least_readable_version..=self.latest_version() {
            let root = archive.get_root_hash(version).unwrap();
            assert_eq!(
                pruned.get_root_hash(version).unwrap(),
                root,
                "version {version}: root hash differs after pruning",
            );
            for key in &self.keys {
                let expected = self.states[version as usize].get(key).cloned();
                let (value, proof) = pruned
                    .get_with_proof(*key, version)
                    .unwrap_or_else(|e| panic!("version {version}: reading {key:?}: {e:?}"));
                assert_eq!(
                    value, expected,
                    "version {version}: wrong value for {key:?}"
                );
                proof.verify(root, *key, value).unwrap();
            }
        }
    }
}

/// Builds a key that is all zeroes except for the given nibbles.
fn key_with_nibbles(nibbles: &[(usize, u8)]) -> KeyHash {
    let mut key = [0u8; 32];
    for &(index, nibble) in nibbles {
        assert!(nibble < 16);
        key[index / 2] |= if index % 2 == 0 { nibble << 4 } else { nibble };
    }
    KeyHash(key)
}

fn put(key: KeyHash, value: u8) -> (KeyHash, Option<OwnedValue>) {
    (key, Some(vec![value]))
}

fn delete(key: KeyHash) -> (KeyHash, Option<OwnedValue>) {
    (key, None)
}

/// Sanity check of the harness on a workload without deletions.
#[test]
fn inserts_and_updates_prune_exactly() {
    let a = key_with_nibbles(&[(0, 1)]);
    let b = key_with_nibbles(&[(0, 2)]);
    let c = key_with_nibbles(&[(0, 1), (40, 3)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1), put(b, 1)]]);
    harness.commit(vec![vec![put(c, 1)], vec![put(a, 2)]]);
    harness.commit(vec![vec![put(b, 2)]]);
    for version in 0..=harness.latest_version() {
        harness.prune(version);
    }
}

/// A version whose writes have no effect (deleting an absent key) copies the previous root to the
/// new version in `TreeCache::freeze`, but never indexes the previous root as stale.
#[test]
fn noop_version_indexes_previous_root_as_stale() {
    let a = key_with_nibbles(&[(0, 1)]);
    let b = key_with_nibbles(&[(0, 2)]);
    let absent = key_with_nibbles(&[(0, 3)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1), put(b, 1)]]);
    harness.commit(vec![vec![delete(absent)]]);
    harness.commit(vec![vec![put(a, 2)]]);
    harness.prune(2);
}

/// Same as above, but the no-op version is an empty value set.
#[test]
fn empty_version_indexes_previous_root_as_stale() {
    let a = key_with_nibbles(&[(0, 1)]);
    let b = key_with_nibbles(&[(0, 2)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1), put(b, 1)]]);
    harness.commit(vec![vec![]]);
    harness.commit(vec![vec![put(a, 2)]]);
    harness.prune(2);
}

/// When the tree becomes empty a `Null` root is written for that version. Inserting into the
/// empty tree at a later version never indexes that `Null` root as stale.
#[test]
fn null_root_is_indexed_as_stale_when_tree_is_refilled() {
    let a = key_with_nibbles(&[(0, 1)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1)]]);
    harness.commit(vec![vec![delete(a)]]);
    harness.commit(vec![vec![put(a, 2)]]);
    harness.prune(2);
}

/// Same as above, but the tree is refilled with `batch_put_value_sets`.
#[test]
fn null_root_is_indexed_as_stale_when_tree_is_refilled_with_batch_api() {
    let a = key_with_nibbles(&[(0, 1)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1)]]);
    harness.commit(vec![vec![delete(a)]]);
    harness.commit_with_batch_api(vec![vec![put(a, 2)]]);
    harness.prune(2);
}

/// Deleting a key collapses a chain of single-child internal nodes and moves the sibling leaf up.
/// Every node of the chain and the old sibling leaf must become stale, and nothing else.
#[test]
fn deletion_collapsing_internal_chain_prunes_exactly() {
    // `a` and `b` share 40 nibbles, so they hang below a chain of 40 internal nodes.
    let a = key_with_nibbles(&[(40, 1)]);
    let b = key_with_nibbles(&[(40, 2)]);
    let c = key_with_nibbles(&[(0, 1)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(a, 1), put(b, 1), put(c, 1)]]);
    harness.commit(vec![vec![delete(a)]]);
    harness.commit(vec![vec![delete(c)]]);
    harness.commit(vec![vec![put(a, 2)]]);
    for version in 0..=harness.latest_version() {
        harness.prune(version);
    }
}

/// Same as above with all operations inside a single version, in both orders, so that nodes
/// created and deleted within the version go through the in-memory cache only.
#[test]
fn insert_and_delete_in_same_version_prunes_exactly() {
    let a = key_with_nibbles(&[(40, 1)]);
    let b = key_with_nibbles(&[(40, 2)]);
    let c = key_with_nibbles(&[(0, 1)]);

    let mut harness = PruningHarness::new();
    harness.commit(vec![vec![put(c, 1)]]);
    harness.commit(vec![vec![put(a, 1), put(b, 1), delete(a)]]);
    harness.commit(vec![vec![delete(b), put(a, 2), put(b, 2), delete(c)]]);
    harness.commit(vec![vec![put(c, 2)], vec![delete(a)], vec![delete(b)]]);
    for version in 0..=harness.latest_version() {
        harness.prune(version);
    }
}

/// `append_value_set` rewrites nodes in place at the latest version. Their old node keys are the
/// same as the new ones, so indexing them as stale makes pruning delete the live tree.
#[cfg(feature = "migration")]
#[test]
fn append_value_set_does_not_prune_live_nodes() {
    let a = key_with_nibbles(&[(0, 1)]);
    let b = key_with_nibbles(&[(0, 2)]);
    let c = key_with_nibbles(&[(0, 3)]);

    let db = MockTreeStore::new(true /* allow_overwrite */);
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);
    let (_, batch) = tree.put_value_set(vec![put(a, 1), put(b, 1)], 0).unwrap();
    db.write_tree_update_batch(batch).unwrap();

    let (root, batch) = tree.append_value_set(vec![put(c, 1)], 0).unwrap();
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get_root_hash(0).unwrap(), root);

    // Version 0 is still the latest version, so it must stay readable.
    db.purge_stale_nodes(0).unwrap();
    assert_eq!(
        tree.get_root_hash(0).unwrap(),
        root,
        "root of version 0 was pruned"
    );
    for key in [a, b, c] {
        assert_eq!(tree.get(key, 0).unwrap(), Some(vec![1]));
    }
}

/// Appends that delete and re-insert a key remove nodes of the latest version and later recreate
/// nodes under the same keys. Stale index entries written by an earlier append must not make
/// pruning delete nodes recreated by a later append.
#[cfg(feature = "migration")]
#[test]
fn append_value_set_with_deletions_does_not_prune_live_nodes() {
    // `a` and `b` share the internal node at nibble path `1`.
    let a = key_with_nibbles(&[(0, 1), (1, 1)]);
    let b = key_with_nibbles(&[(0, 1), (1, 2)]);
    let c = key_with_nibbles(&[(0, 2)]);

    let db = MockTreeStore::new(true /* allow_overwrite */);
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);
    let (_, batch) = tree
        .put_value_set(vec![put(a, 1), put(b, 1), put(c, 1)], 0)
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    // Collapses the internal node at path `1` into the leaf of `a`...
    let (_, batch) = tree.append_value_set(vec![delete(b)], 0).unwrap();
    db.write_tree_update_batch(batch).unwrap();
    // ...and splits it again, recreating the nodes removed by the previous append.
    let (root, batch) = tree.append_value_set(vec![put(b, 2)], 0).unwrap();
    db.write_tree_update_batch(batch).unwrap();

    db.purge_stale_nodes(0).unwrap();
    let missing: Vec<_> = reachable_nodes_option(&db, 0)
        .into_iter()
        .filter(|(_, exists)| !exists)
        .collect();
    assert!(missing.is_empty(), "live nodes were pruned: {missing:?}");
    assert_eq!(tree.get_root_hash(0).unwrap(), root);
    assert_eq!(tree.get(a, 0).unwrap(), Some(vec![1]));
    assert_eq!(tree.get(b, 0).unwrap(), Some(vec![2]));
    assert_eq!(tree.get(c, 0).unwrap(), Some(vec![1]));

    // Regular versions on top of the appended version keep pruning correctly.
    let (_, batch) = tree.put_value_set(vec![put(a, 3)], 1).unwrap();
    db.write_tree_update_batch(batch).unwrap();
    db.purge_stale_nodes(1).unwrap();
    assert_eq!(tree.get(a, 1).unwrap(), Some(vec![3]));
    assert_eq!(tree.get(b, 1).unwrap(), Some(vec![2]));
    assert_eq!(tree.get(c, 1).unwrap(), Some(vec![1]));
}

/// Like `reachable_nodes`, but reports missing nodes instead of panicking.
#[cfg(feature = "migration")]
fn reachable_nodes_option<R: TreeReader>(reader: &R, version: Version) -> Vec<(NodeKey, bool)> {
    let mut reachable = Vec::new();
    let mut stack = vec![NodeKey::new_empty_path(version)];
    while let Some(node_key) = stack.pop() {
        let node = reader.get_node_option(&node_key).unwrap();
        if let Some(Node::Internal(internal)) = &node {
            for (nibble, child) in internal.children_unsorted() {
                stack.push(node_key.gen_child_node_key(child.version, nibble));
            }
        }
        reachable.push((node_key, node.is_some()));
    }
    reachable
}

/// A small key universe with long shared prefixes, so that random workloads hit splits of leaves
/// into internal-node chains, collapses on deletion, deletes of absent keys and empty trees.
fn arb_key() -> impl Strategy<Value = KeyHash> {
    (0u8..3, 0u8..3, 0u8..3).prop_map(|(n0, n3, n9)| key_with_nibbles(&[(0, n0), (3, n3), (9, n9)]))
}

fn arb_value_set(allow_noop: bool) -> impl Strategy<Value = ValueSet> {
    let op = (arb_key(), proptest::option::weighted(0.6, 0u8..4))
        .prop_map(|(key, value)| (key, value.map(|v| vec![v])));
    proptest::collection::vec(op, if allow_noop { 0..6 } else { 1..6 })
}

/// One call to the tree, committing one or more versions.
#[derive(Clone, Debug)]
struct Commit {
    value_sets: Vec<ValueSet>,
    /// How many versions before the latest one to keep readable after this commit.
    keep: u64,
    /// Use `batch_put_value_sets` instead of `put_value_sets` if the commit only inserts.
    use_batch_api: bool,
}

impl Commit {
    fn is_insert_only(&self) -> bool {
        self.value_sets.iter().all(|value_set| {
            !value_set.is_empty() && value_set.iter().all(|(_, value)| value.is_some())
        })
    }
}

fn arb_workload(allow_noop: bool) -> impl Strategy<Value = Vec<Commit>> {
    let commit = (
        proptest::collection::vec(arb_value_set(allow_noop), 1..4),
        0u64..4,
        any::<bool>(),
    )
        .prop_map(|(value_sets, keep, use_batch_api)| Commit {
            value_sets,
            keep,
            use_batch_api,
        });
    proptest::collection::vec(commit, 1..25)
}

fn run_workload(workload: Vec<Commit>) {
    let mut harness = PruningHarness::new();
    for commit in workload {
        let keep = commit.keep;
        if commit.use_batch_api && commit.is_insert_only() {
            harness.commit_with_batch_api(commit.value_sets);
        } else {
            harness.commit(commit.value_sets);
        }
        let least_readable_version = harness.latest_version().saturating_sub(keep);
        harness.prune(least_readable_version.max(harness.least_readable_version));
    }
}

/// Filters a workload down to versions that rewrite at least one leaf and leave the tree
/// non-empty, to look for pruning bugs other than the no-op version and `Null` root leaks.
fn without_noop_versions(workload: Vec<Commit>) -> Vec<Commit> {
    let mut state = BTreeMap::new();
    let mut filtered = Vec::new();
    for commit in workload {
        let mut kept_sets = Vec::new();
        for value_set in commit.value_sets {
            let mut next = state.clone();
            for (key, value) in &value_set {
                match value {
                    Some(value) => next.insert(*key, value.clone()),
                    None => next.remove(key),
                };
            }
            let has_insert = value_set.iter().any(|(_, value)| value.is_some());
            if has_insert && !next.is_empty() {
                state = next;
                kept_sets.push(value_set);
            }
        }
        if !kept_sets.is_empty() {
            filtered.push(Commit {
                value_sets: kept_sets,
                ..commit
            });
        }
    }
    filtered
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random inserts, updates and deletes, committed in single- and multi-version batches and
    /// pruned with a random lag.
    #[test]
    fn proptest_pruning_keeps_exactly_retained_versions(workload in arb_workload(true)) {
        run_workload(workload);
    }

    /// Same as above, but without versions that leave the tree unchanged.
    #[test]
    fn proptest_pruning_keeps_exactly_retained_versions_without_noops(
        workload in arb_workload(false).prop_map(without_noop_versions)
    ) {
        prop_assume!(!workload.is_empty());
        run_workload(workload);
    }
}
