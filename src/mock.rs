// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! A mock, in-memory tree store useful for testing.

use std::collections::{hash_map::Entry, BTreeSet, HashMap};

use anyhow::{bail, ensure, Result};
use futures::{future::BoxFuture, stream, StreamExt};

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
    #[allow(clippy::type_complexity)]
    data: RwLock<(HashMap<NodeKey, Node>, BTreeSet<StaleNodeIndex>)>,
    allow_overwrite: bool,
}

impl Default for MockTreeStore {
    fn default() -> Self {
        Self {
            data: RwLock::new((HashMap::new(), BTreeSet::new())),
            allow_overwrite: false,
        }
    }
}

impl TreeReader for MockTreeStore {
    fn get_node_option<'future, 'a: 'future, 'n: 'future>(
        &'a self,
        node_key: &'n NodeKey,
    ) -> BoxFuture<'future, Result<Option<Node>>> {
        Box::pin(async move { Ok(self.data.read().0.get(node_key).cloned()) })
    }

    #[allow(clippy::type_complexity)]
    fn get_rightmost_leaf<'future, 'a: 'future>(
        &'a self,
    ) -> BoxFuture<'future, Result<Option<(NodeKey, LeafNode)>>> {
        Box::pin(async move {
            let locked = self.data.read();
            let mut node_key_and_node: Option<(NodeKey, LeafNode)> = None;

            for (key, value) in locked.0.iter() {
                if let Node::Leaf(leaf_node) = value {
                    if node_key_and_node.is_none()
                        || leaf_node.key_hash() > node_key_and_node.as_ref().unwrap().1.key_hash()
                    {
                        node_key_and_node.replace((key.clone(), leaf_node.clone()));
                    }
                }
            }

            Ok(node_key_and_node)
        })
    }
}

impl TreeWriter for MockTreeStore {
    fn write_node_batch<'future, 'a: 'future, 'n: 'future>(
        &'a mut self,
        node_batch: &'n NodeBatch,
    ) -> BoxFuture<'future, Result<()>> {
        Box::pin(async move {
            let mut locked = self.data.write();
            for (node_key, node) in node_batch.clone() {
                let replaced = locked.0.insert(node_key, node);
                if !self.allow_overwrite {
                    assert_eq!(replaced, None);
                }
            }
            Ok(())
        })
    }
}

impl MockTreeStore {
    pub fn new(allow_overwrite: bool) -> Self {
        Self {
            allow_overwrite,
            ..Default::default()
        }
    }

    pub async fn put_node(&self, node_key: NodeKey, node: Node) -> Result<()> {
        match self.data.write().0.entry(node_key) {
            Entry::Occupied(o) => bail!("Key {:?} exists.", o.key()),
            Entry::Vacant(v) => {
                v.insert(node);
            }
        }
        Ok(())
    }

    async fn put_stale_node_index(&self, index: StaleNodeIndex) -> Result<()> {
        let is_new_entry = self.data.write().1.insert(index);
        ensure!(is_new_entry, "Duplicated retire log.");
        Ok(())
    }

    pub async fn write_tree_update_batch(&self, batch: TreeUpdateBatch) -> Result<()> {
        stream::iter(batch.node_batch.into_iter())
            .then(|(k, v)| self.put_node(k, v))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<_>>()?;
        stream::iter(batch.stale_node_index_batch.into_iter())
            .then(|i| self.put_stale_node_index(i))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<_>>()?;
        Ok(())
    }

    pub async fn purge_stale_nodes(&self, least_readable_version: Version) -> Result<()> {
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

    pub async fn num_nodes(&self) -> usize {
        self.data.read().0.len()
    }
}
