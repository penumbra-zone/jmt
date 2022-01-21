// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::types::Version;
use crate::{
    node_type::{LeafNode, Node, NodeKey},
    NodeBatch, StaleNodeIndex, TreeReaderAsync, TreeUpdateBatch, TreeWriterAsync,
};
use anyhow::{bail, ensure, Result};
use futures::future::BoxFuture;
use futures::{stream, StreamExt};
use std::collections::{hash_map::Entry, BTreeSet, HashMap};

#[cfg(test)]
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct MockTreeStore<V> {
    #[allow(clippy::type_complexity)]
    data: RwLock<(HashMap<NodeKey, Node<V>>, BTreeSet<StaleNodeIndex>)>,
    allow_overwrite: bool,
}

impl<V> Default for MockTreeStore<V> {
    fn default() -> Self {
        Self {
            data: RwLock::new((HashMap::new(), BTreeSet::new())),
            allow_overwrite: false,
        }
    }
}

impl<V> TreeReaderAsync<V> for MockTreeStore<V>
where
    V: crate::TestValue + Send + Sync,
{
    fn get_node_option<'future, 'a: 'future, 'n: 'future>(
        &'a self,
        node_key: &'n NodeKey,
    ) -> BoxFuture<'future, Result<Option<Node<V>>>> {
        Box::pin(async move {
            let node_value = self.data.read().await.0.get(node_key).cloned();
            dbg!(&node_value);
            Ok(node_value)
        })
    }

    #[allow(clippy::type_complexity)]
    fn get_rightmost_leaf<'future, 'a: 'future>(
        &'a self,
    ) -> BoxFuture<'future, Result<Option<(NodeKey, LeafNode<V>)>>> {
        Box::pin(async move {
            let locked = self.data.read().await;
            let mut node_key_and_node: Option<(NodeKey, LeafNode<V>)> = None;

            for (key, value) in locked.0.iter() {
                if let Node::Leaf(leaf_node) = value {
                    if node_key_and_node.is_none()
                        || leaf_node.account_key()
                            > node_key_and_node.as_ref().unwrap().1.account_key()
                    {
                        node_key_and_node.replace((key.clone(), leaf_node.clone()));
                    }
                }
            }

            dbg!(&node_key_and_node);

            Ok(node_key_and_node)
        })
    }
}

impl<V> TreeWriterAsync<V> for MockTreeStore<V>
where
    V: crate::TestValue + Send + Sync,
{
    fn write_node_batch<'future, 'a: 'future, 'n: 'future>(
        &'a mut self,
        node_batch: &'n NodeBatch<V>,
    ) -> BoxFuture<'future, Result<()>> {
        Box::pin(async move {
            let mut locked = self.data.write().await;
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

impl<V> MockTreeStore<V>
where
    V: crate::TestValue,
{
    pub fn new(allow_overwrite: bool) -> Self {
        Self {
            allow_overwrite,
            ..Default::default()
        }
    }

    pub async fn put_node(&self, node_key: NodeKey, node: Node<V>) -> Result<()> {
        dbg!(&node_key, &node);
        match self.data.write().await.0.entry(node_key) {
            Entry::Occupied(o) => bail!("Key {:?} exists.", o.key()),
            Entry::Vacant(v) => {
                v.insert(node);
            }
        }
        Ok(())
    }

    async fn put_stale_node_index(&self, index: StaleNodeIndex) -> Result<()> {
        let is_new_entry = self.data.write().await.1.insert(index);
        ensure!(is_new_entry, "Duplicated retire log.");
        Ok(())
    }

    pub async fn write_tree_update_batch(&self, batch: TreeUpdateBatch<V>) -> Result<()> {
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
        let mut wlocked = self.data.write().await;

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
        self.data.read().await.0.len()
    }
}
