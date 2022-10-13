// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! A mock, in-memory tree store useful for testing.

use std::{
    collections::{hash_map::Entry, BTreeSet, HashMap},
    sync::atomic::{AtomicU32, Ordering},
};

use anyhow::{bail, ensure, Result};

use crate::{
    node_type::{LeafNode, Node, NodeKey},
    storage::{NodeBatch, StaleNodeIndex, TreeReader, TreeUpdateBatch, TreeWriter},
    types::Version,
};

mod rwlock;
use rwlock::RwLock;

/// A mock, in-memory tree store useful for testing.
///
/// The tree store is internally represented with a `HashMap`.  This structure
/// is exposed for use only by downstream crates' tests, and it should obviously
/// not be used in production.
pub struct MockTreeStore {
    data: RwLock<(HashMap<NodeKey, Node>, BTreeSet<StaleNodeIndex>)>,
    allow_overwrite: bool,
    writes: AtomicU32,
    reads: AtomicU32,
}

impl Default for MockTreeStore {
    fn default() -> Self {
        Self {
            data: RwLock::new((HashMap::new(), BTreeSet::new())),
            allow_overwrite: false,
            writes: AtomicU32::new(0),
            reads: AtomicU32::new(0),
        }
    }
}

impl TreeReader for MockTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.data.read().0.get(node_key).cloned())
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let locked = self.data.read();
        let mut node_key_and_node: Option<(NodeKey, LeafNode)> = None;

        for (key, value) in locked.0.iter() {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if let Node::Leaf(leaf_node) = value {
                if node_key_and_node.is_none()
                    || leaf_node.key_hash() > node_key_and_node.as_ref().unwrap().1.key_hash()
                {
                    node_key_and_node.replace((key.clone(), leaf_node.clone()));
                }
            }
        }

        Ok(node_key_and_node)
    }
}

impl TreeWriter for MockTreeStore {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut locked = self.data.write();
        for (node_key, node) in node_batch.clone() {
            let replaced = locked.0.insert(node_key, node);
            if !self.allow_overwrite {
                assert_eq!(replaced, None);
            }
        }
        Ok(())
    }
}

impl MockTreeStore {
    pub fn new(allow_overwrite: bool) -> Self {
        Self {
            allow_overwrite,
            ..Default::default()
        }
    }

    pub fn reads(&self) -> u32 {
        self.reads.load(Ordering::SeqCst)
    }

    pub fn writes(&self) -> u32 {
        self.writes.load(Ordering::SeqCst)
    }

    pub fn put_node(&self, node_key: NodeKey, node: Node) -> Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        match self.data.write().0.entry(node_key) {
            Entry::Occupied(o) => bail!("Key {:?} exists.", o.key()),
            Entry::Vacant(v) => {
                v.insert(node);
            }
        }
        Ok(())
    }

    fn put_stale_node_index(&self, index: StaleNodeIndex) -> Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let is_new_entry = self.data.write().1.insert(index);
        ensure!(is_new_entry, "Duplicated retire log.");
        Ok(())
    }

    pub fn write_tree_update_batch(&self, batch: TreeUpdateBatch) -> Result<()> {
        batch
            .node_batch
            .into_iter()
            .map(|(k, v)| self.put_node(k, v))
            .collect::<Result<Vec<_>>>()?;
        batch
            .stale_node_index_batch
            .into_iter()
            .map(|i| self.put_stale_node_index(i))
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    pub fn purge_stale_nodes(&self, least_readable_version: Version) -> Result<()> {
        let mut wlocked = self.data.write();

        // Only records retired before or at `least_readable_version` can be purged in order
        // to keep that version still readable.
        let to_prune = wlocked
            .1
            .iter()
            .take_while(|log| log.stale_since_version <= least_readable_version)
            .cloned()
            .collect::<Vec<_>>();

        for log in to_prune {
            let removed = wlocked.0.remove(&log.node_key).is_some();
            ensure!(removed, "Stale node index refers to non-existent node.");
            wlocked.1.remove(&log);
        }

        Ok(())
    }

    pub fn num_nodes(&self) -> usize {
        self.data.read().0.len()
    }
}
