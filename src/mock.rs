// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! A mock, in-memory tree store useful for testing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{ensure, Result};

use crate::{
    node_type::{AugmentedNode, LeafNode, Node, NodeKey},
    storage::{
        HasPreimage, StaleNodeIndex, TreeChangeBatch, TreeReader, TreeUpdateBatch, TreeWriter,
    },
    types::Version,
    KeyHash,
};

mod rwlock;
use rwlock::RwLock;

/// A mock, in-memory tree store useful for testing.
///
/// The tree store is internally represented with a `HashMap`.  This structure
/// is exposed for use only by downstream crates' tests, and it should obviously
/// not be used in production.
#[derive(Debug)]
pub struct MockTreeStore {
    data: RwLock<MockTreeStoreInner>,
    allow_overwrite: bool,
}

#[derive(Default, Debug)]
pub(crate) struct MockTreeStoreInner {
    pub nodes: HashMap<NodeKey, Node>,
    pub values: BTreeMap<Version, HashMap<KeyHash, Option<Vec<u8>>>>,
    pub stale_nodes: BTreeSet<StaleNodeIndex>,
    pub preimages: HashMap<KeyHash, Vec<u8>>,
}

impl Default for MockTreeStore {
    fn default() -> Self {
        Self {
            data: RwLock::new(Default::default()),
            allow_overwrite: false,
        }
    }
}

impl TreeReader for MockTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.data.read().nodes.get(node_key).cloned())
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let locked = self.data.read();
        let mut node_key_and_node: Option<(NodeKey, LeafNode)> = None;

        for (key, value) in locked.nodes.iter() {
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

    fn get_value_option(
        &self,
        value_id: &crate::types::value_identifier::ValueIdentifier,
    ) -> Result<Option<crate::OwnedValue>> {
        for (_, values) in self.data.read().values.range(0..=value_id.version()).rev() {
            if let Some(v) = values.get(&value_id.key_hash()) {
                return Ok(v.clone());
            }
        }
        Ok(None)
    }
}

impl HasPreimage for MockTreeStore {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self.data.read().preimages.get(&key_hash).cloned())
    }
}

impl TreeWriter for MockTreeStore {
    fn write_node_batch(&self, node_batch: &TreeChangeBatch) -> Result<()> {
        let mut locked = self.data.write();
        for (node_key, node) in node_batch.nodes().clone() {
            let node_to_insert = if let AugmentedNode::Leaf(augmented_leaf) = node {
                let (leaf, value) = augmented_leaf.split();
                put_value(
                    &mut locked.values,
                    node_key.version(),
                    leaf.key_hash(),
                    Some(value),
                );
                Node::Leaf(leaf)
            } else {
                node.into()
            };

            let replaced = locked.nodes.insert(node_key, node_to_insert);
            if !self.allow_overwrite {
                assert_eq!(replaced, None);
            }
        }
        for idx in node_batch.deleted_values() {
            put_value(&mut locked.values, idx.version(), idx.key_hash(), None)
        }
        Ok(())
    }
}
pub fn put_value(
    values: &mut BTreeMap<Version, HashMap<KeyHash, Option<Vec<u8>>>>,
    version: u64,
    key_hash: KeyHash,
    value: Option<Vec<u8>>,
) {
    match values.entry(version) {
        std::collections::btree_map::Entry::Vacant(v) => {
            v.insert([(key_hash, value)].into_iter().collect());
        }
        std::collections::btree_map::Entry::Occupied(mut o) => {
            o.get_mut().insert(key_hash, value);
        }
    }
}

impl MockTreeStore {
    pub fn new(allow_overwrite: bool) -> Self {
        Self {
            allow_overwrite,
            ..Default::default()
        }
    }

    pub fn put_node(&self, node_key: NodeKey, node: AugmentedNode) -> Result<()> {
        self.write_node_batch(&TreeChangeBatch {
            insertions: vec![(node_key, node)].into_iter().collect(),
            deleted_values: vec![],
        })
    }

    pub fn put_key_preimage(&self, preimage: &Vec<u8>) {
        let key_hash: KeyHash = preimage.into();
        self.data
            .write()
            .preimages
            .insert(key_hash, preimage.clone());
    }

    fn put_stale_node_index(&self, index: StaleNodeIndex) -> Result<()> {
        let is_new_entry = self.data.write().stale_nodes.insert(index);
        ensure!(is_new_entry, "Duplicated retire log.");
        Ok(())
    }

    pub fn write_tree_update_batch(&self, batch: TreeUpdateBatch) -> Result<()> {
        self.write_node_batch(&batch.node_batch)?;

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
            .stale_nodes
            .iter()
            .take_while(|log| log.stale_since_version <= least_readable_version)
            .cloned()
            .collect::<Vec<_>>();

        for log in to_prune {
            let removed_node = wlocked.nodes.remove(&log.node_key);
            ensure!(
                removed_node.is_some(),
                "Stale node index refers to non-existent node."
            );
            wlocked.stale_nodes.remove(&log);
        }

        Ok(())
    }

    pub fn num_nodes(&self) -> usize {
        self.data.read().nodes.len()
    }
}
