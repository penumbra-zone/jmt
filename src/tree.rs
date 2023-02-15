use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    convert::TryInto,
};

use anyhow::{bail, ensure, format_err, Context, Result};

use crate::{
    node_type::{Child, Children, InternalNode, LeafNode, Node, NodeKey, NodeType},
    storage::{TreeReader, TreeUpdateBatch},
    tree_cache::TreeCache,
    types::{
        nibble::{
            nibble_path::{skip_common_prefix, NibbleIterator, NibblePath},
            Nibble, NibbleRangeIterator, ROOT_NIBBLE_HEIGHT,
        },
        proof::{SparseMerkleProof, SparseMerkleRangeProof},
        Version,
    },
    Bytes32Ext, KeyHash, MissingRootError, OwnedValue, RootHash,
};

#[cfg(feature = "ics23")]
pub mod ics23_impl;

/// The Jellyfish Merkle tree data structure. See [`crate`] for description.
pub struct JellyfishMerkleTree<'a, R> {
    reader: &'a R,
    leaf_count_migration: bool,
}

impl<'a, R> JellyfishMerkleTree<'a, R>
where
    R: 'a + TreeReader,
{
    /// Creates a `JellyfishMerkleTree` backed by the given [`TreeReader`](trait.TreeReader.html).
    pub fn new(reader: &'a R) -> Self {
        Self {
            reader,
            leaf_count_migration: true,
        }
    }

    pub fn new_migration(reader: &'a R, leaf_count_migration: bool) -> Self {
        Self {
            reader,
            leaf_count_migration,
        }
    }

    /// Get the node hash from the cache if exists, otherwise compute it.
    fn get_hash(
        node_key: &NodeKey,
        node: &Node,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
    ) -> [u8; 32] {
        if let Some(cache) = hash_cache {
            match cache.get(node_key.nibble_path()) {
                Some(hash) => *hash,
                None => unreachable!("{:?} can not be found in hash cache", node_key),
            }
        } else {
            node.hash()
        }
    }

    /// The batch version of `put_value_sets`.
    pub fn batch_put_value_sets(
        &self,
        value_sets: Vec<Vec<(KeyHash, OwnedValue)>>,
        node_hashes: Option<Vec<&HashMap<NibblePath, [u8; 32]>>>,
        first_version: Version,
    ) -> Result<(Vec<RootHash>, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new(self.reader, first_version)?;
        let hash_sets: Vec<_> = match node_hashes {
            Some(hashes) => hashes.into_iter().map(Some).collect(),
            None => (0..value_sets.len()).map(|_| None).collect(),
        };

        for (idx, (value_set, hash_set)) in
            itertools::zip_eq(value_sets.into_iter(), hash_sets.into_iter()).enumerate()
        {
            assert!(
                !value_set.is_empty(),
                "Transactions that output empty write set should not be included.",
            );
            let version = first_version + idx as u64;
            let deduped_and_sorted_kvs = value_set
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Vec<_>>();
            let root_node_key = tree_cache.get_root_node_key().clone();
            let (new_root_node_key, _) = self.batch_insert_at(
                root_node_key,
                version,
                deduped_and_sorted_kvs.as_slice(),
                0,
                &hash_set,
                &mut tree_cache,
            )?;
            tree_cache.set_root_node_key(new_root_node_key);

            // Freezes the current cache to make all contents in the current cache immutable.
            tree_cache.freeze()?;
        }

        Ok(tree_cache.into())
    }

    fn batch_insert_at(
        &self,
        mut node_key: NodeKey,
        version: Version,
        kvs: &[(KeyHash, OwnedValue)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        assert!(!kvs.is_empty());

        let node = tree_cache.get_node(&node_key)?;
        Ok(match node {
            Node::Internal(internal_node) => {
                // We always delete the existing internal node here because it will not be referenced anyway
                // since this version.
                tree_cache.delete_node(&node_key, false /* is_leaf */);

                // Reuse the current `InternalNode` in memory to create a new internal node.
                let mut children: Children = internal_node.clone().into();

                // Traverse all the path touched by `kvs` from this internal node.
                for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                    // Traverse downwards from this internal node recursively by splitting the updates into
                    // each child index
                    let child_index = kvs[left].0 .0.get_nibble(depth);

                    let (new_child_node_key, new_child_node) =
                        match internal_node.child(child_index) {
                            Some(child) => {
                                let child_node_key =
                                    node_key.gen_child_node_key(child.version, child_index);
                                self.batch_insert_at(
                                    child_node_key,
                                    version,
                                    &kvs[left..=right],
                                    depth + 1,
                                    hash_cache,
                                    tree_cache,
                                )?
                            }
                            None => {
                                let new_child_node_key =
                                    node_key.gen_child_node_key(version, child_index);
                                self.batch_create_subtree(
                                    new_child_node_key,
                                    version,
                                    &kvs[left..=right],
                                    depth + 1,
                                    hash_cache,
                                    tree_cache,
                                )?
                            }
                        };

                    children.insert(
                        child_index,
                        Child::new(
                            Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                            version,
                            new_child_node.node_type(),
                        ),
                    );
                }
                let new_internal_node =
                    InternalNode::new_migration(children, self.leaf_count_migration);

                node_key.set_version(version);

                // Cache this new internal node.
                tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
                (node_key, new_internal_node.into())
            }
            Node::Leaf(leaf_node) => {
                // We are on a leaf node but trying to insert another node, so we may diverge.
                // We always delete the existing leaf node here because it will not be referenced anyway
                // since this version.
                tree_cache.delete_node(&node_key, true /* is_leaf */);
                node_key.set_version(version);
                self.batch_create_subtree_with_existing_leaf(
                    node_key, version, leaf_node, kvs, depth, hash_cache, tree_cache,
                )?
            }
            Node::Null => {
                if !node_key.nibble_path().is_empty() {
                    bail!(
                        "Null node exists for non-root node with node_key {:?}",
                        node_key
                    );
                }

                if node_key.version() == version {
                    tree_cache.delete_node(&node_key, false /* is_leaf */);
                }
                self.batch_create_subtree(
                    NodeKey::new_empty_path(version),
                    version,
                    kvs,
                    depth,
                    hash_cache,
                    tree_cache,
                )?
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn batch_create_subtree_with_existing_leaf(
        &self,
        node_key: NodeKey,
        version: Version,
        existing_leaf_node: LeafNode,
        kvs: &[(KeyHash, OwnedValue)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        let existing_leaf_key = existing_leaf_node.key_hash();

        if kvs.len() == 1 && kvs[0].0 == existing_leaf_key {
            let new_leaf_node = Node::new_leaf(existing_leaf_key, kvs[0].1.clone());
            tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
            Ok((node_key, new_leaf_node))
        } else {
            let existing_leaf_bucket = existing_leaf_key.0.get_nibble(depth);
            let mut isolated_existing_leaf = true;
            let mut children = Children::new();
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0 .0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                let (new_child_node_key, new_child_node) = if existing_leaf_bucket == child_index {
                    isolated_existing_leaf = false;
                    self.batch_create_subtree_with_existing_leaf(
                        child_node_key,
                        version,
                        existing_leaf_node.clone(),
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        tree_cache,
                    )?
                } else {
                    self.batch_create_subtree(
                        child_node_key,
                        version,
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        tree_cache,
                    )?
                };
                children.insert(
                    child_index,
                    Child::new(
                        Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                        version,
                        new_child_node.node_type(),
                    ),
                );
            }
            if isolated_existing_leaf {
                let existing_leaf_node_key =
                    node_key.gen_child_node_key(version, existing_leaf_bucket);
                children.insert(
                    existing_leaf_bucket,
                    Child::new(existing_leaf_node.hash(), version, NodeType::Leaf),
                );

                tree_cache.put_node(existing_leaf_node_key, existing_leaf_node.into())?;
            }

            let new_internal_node =
                InternalNode::new_migration(children, self.leaf_count_migration);

            tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
            Ok((node_key, new_internal_node.into()))
        }
    }

    fn batch_create_subtree(
        &self,
        node_key: NodeKey,
        version: Version,
        kvs: &[(KeyHash, OwnedValue)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        if kvs.len() == 1 {
            let new_leaf_node = Node::new_leaf(kvs[0].0, kvs[0].1.clone());
            tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
            Ok((node_key, new_leaf_node))
        } else {
            let mut children = Children::new();
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0 .0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                let (new_child_node_key, new_child_node) = self.batch_create_subtree(
                    child_node_key,
                    version,
                    &kvs[left..=right],
                    depth + 1,
                    hash_cache,
                    tree_cache,
                )?;
                children.insert(
                    child_index,
                    Child::new(
                        Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                        version,
                        new_child_node.node_type(),
                    ),
                );
            }
            let new_internal_node =
                InternalNode::new_migration(children, self.leaf_count_migration);

            tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
            Ok((node_key, new_internal_node.into()))
        }
    }

    /// This is a convenient function that calls
    /// [`put_value_sets`](struct.JellyfishMerkleTree.html#method.put_value_sets) with a single
    /// `keyed_value_set`.
    pub fn put_value_set(
        &self,
        value_set: impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>,
        version: Version,
    ) -> Result<(RootHash, TreeUpdateBatch)> {
        let (root_hashes, tree_update_batch) = self.put_value_sets(vec![value_set], version)?;
        assert_eq!(
            root_hashes.len(),
            1,
            "root_hashes must consist of a single value.",
        );
        Ok((root_hashes[0], tree_update_batch))
    }

    /// Returns the new nodes and values in a batch after applying `value_set`. For
    /// example, if after transaction `T_i` the committed state of tree in the persistent storage
    /// looks like the following structure:
    ///
    /// ```text
    ///              S_i
    ///             /   \
    ///            .     .
    ///           .       .
    ///          /         \
    ///         o           x
    ///        / \
    ///       A   B
    ///        storage (disk)
    /// ```
    ///
    /// where `A` and `B` denote the states of two adjacent accounts, and `x` is a sibling subtree
    /// of the path from root to A and B in the tree. Then a `value_set` produced by the next
    /// transaction `T_{i+1}` modifies other accounts `C` and `D` exist in the subtree under `x`, a
    /// new partial tree will be constructed in memory and the structure will be:
    ///
    /// ```text
    ///                 S_i      |      S_{i+1}
    ///                /   \     |     /       \
    ///               .     .    |    .         .
    ///              .       .   |   .           .
    ///             /         \  |  /             \
    ///            /           x | /               x'
    ///           o<-------------+-               / \
    ///          / \             |               C   D
    ///         A   B            |
    ///           storage (disk) |    cache (memory)
    /// ```
    ///
    /// With this design, we are able to query the global state in persistent storage and
    /// generate the proposed tree delta based on a specific root hash and `value_set`. For
    /// example, if we want to execute another transaction `T_{i+1}'`, we can use the tree `S_i` in
    /// storage and apply the `value_set` of transaction `T_{i+1}`. Then if the storage commits
    /// the returned batch, the state `S_{i+1}` is ready to be read from the tree by calling
    /// [`get_with_proof`](struct.JellyfishMerkleTree.html#method.get_with_proof). Anything inside
    /// the batch is not reachable from public interfaces before being committed.
    pub fn put_value_sets(
        &self,
        value_sets: impl IntoIterator<Item = impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>>,
        first_version: Version,
    ) -> Result<(Vec<RootHash>, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new(self.reader, first_version)?;
        for (idx, value_set) in value_sets.into_iter().enumerate() {
            let version = first_version + idx as u64;
            value_set
                .into_iter()
                .enumerate()
                .try_for_each(|(i, (key, value))| {
                    let action = if value.is_some() { "insert" } else { "delete" };
                    self.put(key, value, version, &mut tree_cache)
                        .with_context(|| {
                            format!(
                                "failed to {} key {} for version {}, key = {:?}",
                                action, i, version, key
                            )
                        })
                })?;
            // Freezes the current cache to make all contents in the current cache immutable.
            tree_cache.freeze()?;
        }

        Ok(tree_cache.into())
    }

    fn put(
        &self,
        key: KeyHash,
        value: Option<OwnedValue>,
        version: Version,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<()> {
        // tree_cache.ensure_initialized()?;

        let nibble_path = NibblePath::new(key.0.to_vec());

        // Get the root node. If this is the first operation, it would get the root node from the
        // underlying db. Otherwise it most likely would come from `cache`.
        let root_node_key = tree_cache.get_root_node_key().clone();
        let mut nibble_iter = nibble_path.nibbles();

        // Start insertion from the root node.
        match self.insert_at(root_node_key, version, &mut nibble_iter, value, tree_cache)? {
            PutResult::Updated((new_root_node_key, _)) => {
                tree_cache.set_root_node_key(new_root_node_key);
            }
            PutResult::NotChanged => {
                // Nothing has changed, so do nothing
            }
            PutResult::Removed => {
                // root node becomes empty, insert a null node at root
                let genesis_root_key = NodeKey::new_empty_path(version);
                tree_cache.set_root_node_key(genesis_root_key.clone());
                tree_cache.put_node(genesis_root_key, Node::new_null())?;
            }
        }

        Ok(())
    }

    /// Helper function for recursive insertion into the subtree that starts from the current
    /// [`NodeKey`](node_type/struct.NodeKey.html). Returns the newly inserted node.
    /// It is safe to use recursion here because the max depth is limited by the key length which
    /// for this tree is the length of the hash of account addresses.
    fn insert_at(
        &self,
        node_key: NodeKey,
        version: Version,
        nibble_iter: &mut NibbleIterator,
        value: Option<OwnedValue>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<PutResult<(NodeKey, Node)>> {
        // Because deletions could cause the root node not to exist, we try to get the root node,
        // and if it doesn't exist, we synthesize a `Null` node, noting that it hasn't yet been
        // committed anywhere (we need to track this because the tree cache will panic if we try to
        // delete a node that it doesn't know about).
        let (node, node_already_exists) = tree_cache
            .get_node_option(&node_key)?
            .map(|node| (node, true))
            .unwrap_or((Node::Null, false));
        match node {
            Node::Internal(internal_node) => self.insert_at_internal_node(
                node_key,
                internal_node,
                version,
                nibble_iter,
                value,
                tree_cache,
            ),
            Node::Leaf(leaf_node) => self.insert_at_leaf_node(
                node_key,
                leaf_node,
                version,
                nibble_iter,
                value,
                tree_cache,
            ),
            Node::Null => {
                if !node_key.nibble_path().is_empty() {
                    bail!(
                        "Null node exists for non-root node with node_key {:?}",
                        node_key
                    );
                }
                // Delete the old null node if the at the same version
                if node_key.version() == version && node_already_exists {
                    tree_cache.delete_node(&node_key, false /* is_leaf */);
                }
                if let Some(value) = value {
                    // If we're inserting into the null root node, we should change it to be a leaf node
                    let (new_root_node_key, new_root_node) = Self::create_leaf_node(
                        NodeKey::new_empty_path(version),
                        nibble_iter,
                        value,
                        tree_cache,
                    )?;
                    Ok(PutResult::Updated((new_root_node_key, new_root_node)))
                } else {
                    // If we're deleting from the null root node, nothing needs to change
                    Ok(PutResult::NotChanged)
                }
            }
        }
    }

    /// Helper function for recursive insertion into the subtree that starts from the current
    /// `internal_node`. Returns the newly inserted node with its
    /// [`NodeKey`](node_type/struct.NodeKey.html).
    fn insert_at_internal_node(
        &self,
        mut node_key: NodeKey,
        internal_node: InternalNode,
        version: Version,
        nibble_iter: &mut NibbleIterator,
        value: Option<OwnedValue>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<PutResult<(NodeKey, Node)>> {
        // Find the next node to visit following the next nibble as index.
        let child_index = nibble_iter.next().expect("Ran out of nibbles");

        // Traverse downwards from this internal node recursively to get the `node_key` of the child
        // node at `child_index`.
        let result = match internal_node.child(child_index) {
            Some(child) => {
                let child_node_key = node_key.gen_child_node_key(child.version, child_index);
                self.insert_at(child_node_key, version, nibble_iter, value, tree_cache)?
            }
            None => {
                if let Some(value) = value {
                    // insert
                    let new_child_node_key = node_key.gen_child_node_key(version, child_index);
                    PutResult::Updated(Self::create_leaf_node(
                        new_child_node_key,
                        nibble_iter,
                        value,
                        tree_cache,
                    )?)
                } else {
                    // delete not found
                    PutResult::NotChanged
                }
            }
        };

        // Reuse the current `InternalNode` in memory to create a new internal node.
        let mut children: Children = internal_node.into();
        match result {
            PutResult::NotChanged => {
                return Ok(PutResult::NotChanged);
            }
            PutResult::Updated((_, new_node)) => {
                // update child
                children.insert(
                    child_index,
                    Child::new(new_node.hash(), version, new_node.node_type()),
                );
            }
            PutResult::Removed => {
                // remove child
                children.remove(child_index);
            }
        }

        // We always delete the existing internal node here because it will not be referenced anyway
        // since this version.
        tree_cache.delete_node(&node_key, false /* is_leaf */);

        let mut it = children.iter();
        if let Some((child_nibble, child)) = it.next() {
            if it.next().is_none() && child.is_leaf() {
                // internal node has only one child left and it's leaf node, replace it with the leaf node
                let child_key = node_key.gen_child_node_key(child.version, child_nibble);
                let child_node = tree_cache.get_node(&child_key)?;
                tree_cache.delete_node(&child_key, true /* is_leaf */);

                node_key.set_version(version);
                tree_cache.put_node(node_key.clone(), child_node.clone())?;
                Ok(PutResult::Updated((node_key, child_node)))
            } else {
                drop(it);
                let new_internal_node: InternalNode = InternalNode::new(children);

                node_key.set_version(version);

                // Cache this new internal node.
                tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
                Ok(PutResult::Updated((node_key, new_internal_node.into())))
            }
        } else {
            // internal node becomes empty, remove it
            Ok(PutResult::Removed)
        }
    }

    /// Helper function for recursive insertion into the subtree that starts from the
    /// `existing_leaf_node`. Returns the newly inserted node with its
    /// [`NodeKey`](node_type/struct.NodeKey.html).
    fn insert_at_leaf_node(
        &self,
        mut node_key: NodeKey,
        existing_leaf_node: LeafNode,
        version: Version,
        nibble_iter: &mut NibbleIterator,
        value: Option<OwnedValue>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<PutResult<(NodeKey, Node)>> {
        // 1. Make sure that the existing leaf nibble_path has the same prefix as the already
        // visited part of the nibble iter of the incoming key and advances the existing leaf
        // nibble iterator by the length of that prefix.
        let mut visited_nibble_iter = nibble_iter.visited_nibbles();
        let existing_leaf_nibble_path = NibblePath::new(existing_leaf_node.key_hash().0.to_vec());
        let mut existing_leaf_nibble_iter = existing_leaf_nibble_path.nibbles();
        skip_common_prefix(&mut visited_nibble_iter, &mut existing_leaf_nibble_iter);

        // TODO(lightmark): Change this to corrupted error.
        assert!(
            visited_nibble_iter.is_finished(),
            "Leaf nodes failed to share the same visited nibbles before index {}",
            existing_leaf_nibble_iter.visited_nibbles().num_nibbles()
        );

        // 2. Determine the extra part of the common prefix that extends from the position where
        // step 1 ends between this leaf node and the incoming key.
        let mut existing_leaf_nibble_iter_below_internal =
            existing_leaf_nibble_iter.remaining_nibbles();
        let num_common_nibbles_below_internal =
            skip_common_prefix(nibble_iter, &mut existing_leaf_nibble_iter_below_internal);
        let mut common_nibble_path = nibble_iter.visited_nibbles().collect::<NibblePath>();

        // 2.1. Both are finished. That means the incoming key already exists in the tree and we
        // just need to update its value.
        if nibble_iter.is_finished() {
            assert!(existing_leaf_nibble_iter_below_internal.is_finished());
            tree_cache.delete_node(&node_key, true /* is_leaf */);
            if let Some(value) = value {
                // The new leaf node will have the same nibble_path with a new version as node_key.
                node_key.set_version(version);
                // Create the new leaf node with the same address but new blob content.
                return Ok(PutResult::Updated(Self::create_leaf_node(
                    node_key,
                    nibble_iter,
                    value,
                    tree_cache,
                )?));
            } else {
                // deleted
                return Ok(PutResult::Removed);
            };
        }

        if let Some(value) = value {
            tree_cache.delete_node(&node_key, true /* is_leaf */);

            // 2.2. both are unfinished(They have keys with same length so it's impossible to have one
            // finished and the other not). This means the incoming key forks at some point between the
            // position where step 1 ends and the last nibble, inclusive. Then create a seris of
            // internal nodes the number of which equals to the length of the extra part of the
            // common prefix in step 2, a new leaf node for the incoming key, and update the
            // [`NodeKey`] of existing leaf node. We create new internal nodes in a bottom-up
            // order.
            let existing_leaf_index = existing_leaf_nibble_iter_below_internal
                .next()
                .expect("Ran out of nibbles");
            let new_leaf_index = nibble_iter.next().expect("Ran out of nibbles");
            assert_ne!(existing_leaf_index, new_leaf_index);

            let mut children = Children::new();
            children.insert(
                existing_leaf_index,
                Child::new(existing_leaf_node.hash(), version, NodeType::Leaf),
            );
            node_key = NodeKey::new(version, common_nibble_path.clone());
            tree_cache.put_node(
                node_key.gen_child_node_key(version, existing_leaf_index),
                existing_leaf_node.into(),
            )?;

            let (_, new_leaf_node) = Self::create_leaf_node(
                node_key.gen_child_node_key(version, new_leaf_index),
                nibble_iter,
                value,
                tree_cache,
            )?;
            children.insert(
                new_leaf_index,
                Child::new(new_leaf_node.hash(), version, NodeType::Leaf),
            );

            let internal_node = InternalNode::new_migration(children, self.leaf_count_migration);
            let mut next_internal_node = internal_node.clone();
            tree_cache.put_node(node_key.clone(), internal_node.into())?;

            for _i in 0..num_common_nibbles_below_internal {
                let nibble = common_nibble_path
                    .pop()
                    .expect("Common nibble_path below internal node ran out of nibble");
                node_key = NodeKey::new(version, common_nibble_path.clone());
                let mut children = Children::new();
                children.insert(
                    nibble,
                    Child::new(
                        next_internal_node.hash(),
                        version,
                        next_internal_node.node_type(),
                    ),
                );
                let internal_node = InternalNode::new(children);
                next_internal_node = internal_node.clone();
                tree_cache.put_node(node_key.clone(), internal_node.into())?;
            }

            Ok(PutResult::Updated((node_key, next_internal_node.into())))
        } else {
            // delete not found
            Ok(PutResult::NotChanged)
        }
    }

    /// Helper function for creating leaf nodes. Returns the newly created leaf node.
    fn create_leaf_node(
        node_key: NodeKey,
        nibble_iter: &NibbleIterator,
        value: OwnedValue,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        // Get the underlying bytes of nibble_iter which must be a key, i.e., hashed account address
        // with `HashValue::LENGTH` bytes.
        let new_leaf_node = Node::new_leaf(
            KeyHash(
                nibble_iter
                    .get_nibble_path()
                    .bytes()
                    .try_into()
                    .expect("LeafNode must have full nibble path."),
            ),
            value,
        );

        tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
        Ok((node_key, new_leaf_node))
    }

    /// Returns the value (if applicable) and the corresponding merkle proof.
    pub fn get_with_proof(
        &self,
        key: KeyHash,
        version: Version,
    ) -> Result<(Option<OwnedValue>, SparseMerkleProof)> {
        // Empty tree just returns proof with no sibling hash.
        let mut next_node_key = NodeKey::new_empty_path(version);
        let mut siblings = vec![];
        let nibble_path = NibblePath::new(key.0.to_vec());
        let mut nibble_iter = nibble_path.nibbles();

        // We limit the number of loops here deliberately to avoid potential cyclic graph bugs
        // in the tree structure.
        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self.reader.get_node(&next_node_key).map_err(|err| {
                if nibble_depth == 0 {
                    MissingRootError { version }.into()
                } else {
                    err
                }
            })?;
            match next_node {
                Node::Internal(internal_node) => {
                    let queried_child_index = nibble_iter
                        .next()
                        .ok_or_else(|| format_err!("ran out of nibbles"))?;
                    let (child_node_key, mut siblings_in_internal) =
                        internal_node.get_child_with_siblings(&next_node_key, queried_child_index);
                    siblings.append(&mut siblings_in_internal);
                    next_node_key = match child_node_key {
                        Some(node_key) => node_key,
                        None => {
                            return Ok((
                                None,
                                SparseMerkleProof::new(None, {
                                    siblings.reverse();
                                    siblings
                                }),
                            ))
                        }
                    };
                }
                Node::Leaf(leaf_node) => {
                    return Ok((
                        if leaf_node.key_hash() == key {
                            Some(leaf_node.value().to_vec())
                        } else {
                            None
                        },
                        SparseMerkleProof::new(Some(leaf_node.into()), {
                            siblings.reverse();
                            siblings
                        }),
                    ));
                }
                Node::Null => {
                    if nibble_depth == 0 {
                        return Ok((None, SparseMerkleProof::new(None, vec![])));
                    } else {
                        bail!(
                            "Non-root null node exists with node key {:?}",
                            next_node_key
                        );
                    }
                }
            }
        }
        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn search_closest_extreme_node(
        &self,
        version: Version,
        extreme: Extreme,
        to: NibblePath,
        parents: Vec<InternalNode>,
    ) -> Result<Option<KeyHash>> {
        fn neighbor_nibble(
            node: &InternalNode,
            child_index: Nibble,
            extreme: Extreme,
        ) -> Option<Nibble> {
            match extreme {
                // Rightmost left neighbor
                Extreme::Left => node
                    .children_unsorted()
                    .filter(|(nibble, _)| *nibble < child_index)
                    .max_by_key(|(nibble, _)| *nibble)
                    .map(|p| p.0)
                    .clone(),
                // Leftmost right neighbor
                Extreme::Right => node
                    .children_unsorted()
                    .filter(|(nibble, _)| *nibble > child_index)
                    .min_by_key(|(nibble, _)| *nibble)
                    .map(|p| p.0)
                    .clone(),
            }
        }

        let mut parents = parents;
        let mut neighbor: Option<Nibble> = None;
        let mut path = to;

        while neighbor.is_none() {
            let index = path.pop();
            let next_parent = parents.pop();
            if next_parent.is_none() {
                return Ok(None);
            }
            neighbor = neighbor_nibble(&next_parent.unwrap(), index.unwrap(), extreme);

            if neighbor.is_none() {
                continue;
            }
        }
        path.push(neighbor.unwrap());

        // nibble path will represent the left nibble path. this is currently at
        // the parent of the leaf for `key`
        Ok(Some(self.get_extreme_key_hash(
            version,
            NodeKey::new(version, path.clone()),
            path.num_nibbles(),
            extreme.opposite(),
        )?))
    }

    // given a search_key,
    fn search_for_closest_node(
        &self,
        version: Version,
        search_key: KeyHash,
    ) -> Result<SearchResult> {
        let search_path = NibblePath::new(search_key.0.to_vec());
        let mut search_nibbles = search_path.nibbles();
        let mut next_node_key = NodeKey::new_empty_path(version);
        let mut internal_nodes = vec![];

        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self.reader.get_node(&next_node_key).map_err(|err| {
                if nibble_depth == 0 {
                    MissingRootError { version }.into()
                } else {
                    err
                }
            })?;
            match next_node {
                Node::Internal(node) => {
                    internal_nodes.push(node.clone());
                    let queried_child_index = search_nibbles
                        .next()
                        .ok_or_else(|| format_err!("ran out of nibbles"))?;

                    let child_node_key =
                        node.get_child_without_siblings(&next_node_key, queried_child_index);

                    match child_node_key {
                        Some(node_key) => {
                            next_node_key = node_key;
                        }
                        None => {
                            return Ok(SearchResult::FoundInternal {
                                path_to_internal: search_nibbles
                                    .visited_nibbles()
                                    .get_nibble_path(),
                                parents: internal_nodes,
                            });
                        }
                    }
                }
                Node::Leaf(node) => {
                    let key_hash = node.key_hash();
                    return Ok(SearchResult::FoundLeaf {
                        ordering: key_hash.cmp(&search_key),
                        leaf_hash: key_hash,
                        path_to_leaf: search_nibbles.visited_nibbles().get_nibble_path(),
                        parents: internal_nodes,
                    });
                }
                Node::Null => {
                    if nibble_depth == 0 {
                        bail!(
                            "Cannot manufacture nonexistence proof by exclusion for the empty tree"
                        );
                    } else {
                        bail!(
                            "Non-root null node exists with node key {:?}",
                            next_node_key
                        );
                    }
                }
            }
        }

        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn get_bounding_path(
        &self,
        search_key: KeyHash,
        version: Version,
    ) -> Result<(Option<KeyHash>, Option<KeyHash>)> {
        let search_result = self.search_for_closest_node(version, search_key)?;

        match search_result {
            SearchResult::FoundLeaf {
                ordering,
                leaf_hash,
                path_to_leaf,
                parents,
            } => {
                match ordering {
                    Ordering::Less => {
                        // found the closest leaf to the left of the search key.
                        // find the other bound (the leftmost right keyhash)
                        let leftmost_right_keyhash = self.search_closest_extreme_node(
                            version,
                            Extreme::Right,
                            path_to_leaf,
                            parents,
                        )?;

                        Ok((Some(leaf_hash), leftmost_right_keyhash))
                    }
                    Ordering::Greater => {
                        // found the closest leaf to the right of the search key
                        let rightmost_left_keyhash = self.search_closest_extreme_node(
                            version,
                            Extreme::Left,
                            path_to_leaf,
                            parents,
                        )?;

                        Ok((rightmost_left_keyhash, Some(leaf_hash)))
                    }
                    Ordering::Equal => {
                        bail!("found exact key when searching for bounding path for nonexistence proof")
                    }
                }
            }
            SearchResult::FoundInternal {
                path_to_internal,
                parents,
            } => {
                let leftmost_right_keyhash = self.search_closest_extreme_node(
                    version,
                    Extreme::Right,
                    path_to_internal.clone(),
                    parents.clone(),
                )?;
                let rightmost_left_keyhash = self.search_closest_extreme_node(
                    version,
                    Extreme::Left,
                    path_to_internal,
                    parents,
                )?;

                Ok((rightmost_left_keyhash, leftmost_right_keyhash))
            }
        }
    }

    /// Returns the value (if applicable) and the corresponding merkle proof.
    pub fn get_with_exclusion_proof(
        &self,
        key: KeyHash,
        version: Version,
    ) -> Result<Result<(OwnedValue, SparseMerkleProof), ExclusionProof>> {
        // Optimistically attempt get_with_proof, if that succeeds, we're done.
        if let (Some(value), proof) = self.get_with_proof(key, version)? {
            return Ok(Ok((value, proof)));
        }

        // Otherwise, we know this key doesn't exist, so construct an exclusion proof.

        // first, find out what are its bounding path, i.e. the greatest key that is strictly less
        // than the non-present search key and/or the smallest key that is strictly greater than
        // the search key.
        let (left_bound, right_bound) = self.get_bounding_path(key, version)?;

        match (left_bound, right_bound) {
            (Some(left_bound), Some(right_bound)) => {
                let left_proof = self.get_with_proof(left_bound, version)?.1;
                let right_proof = self.get_with_proof(right_bound, version)?.1;

                Ok(Err(ExclusionProof::Middle {
                    rightmost_left_proof: left_proof,
                    leftmost_right_proof: right_proof,
                }))
            }
            (Some(left_bound), None) => {
                let left_proof = self.get_with_proof(left_bound, version)?.1;
                Ok(Err(ExclusionProof::Rightmost {
                    rightmost_left_proof: left_proof,
                }))
            }
            (None, Some(right_bound)) => {
                let right_proof = self.get_with_proof(right_bound, version)?.1;
                Ok(Err(ExclusionProof::Leftmost {
                    leftmost_right_proof: right_proof,
                }))
            }
            _ => bail!("Invalid exclusion proof"),
        }
    }

    fn get_extreme_key_hash(
        &self,
        version: Version,
        mut node_key: NodeKey,
        nibble_depth: usize,
        extreme: Extreme,
    ) -> Result<KeyHash> {
        // Depending on the extreme specified, get either the least nibble or the most nibble
        let min_or_max = |internal_node: &InternalNode| {
            match extreme {
                Extreme::Left => internal_node.children_unsorted().min_by_key(|c| c.0),
                Extreme::Right => internal_node.children_unsorted().max_by_key(|c| c.0),
            }
            .map(|(nibble, _)| nibble)
        };

        for nibble_depth in nibble_depth..=ROOT_NIBBLE_HEIGHT {
            let node = self.reader.get_node(&node_key).map_err(|err| {
                if nibble_depth == 0 {
                    MissingRootError { version }.into()
                } else {
                    err
                }
            })?;
            match node {
                Node::Internal(internal_node) => {
                    // Find the leftmost nibble in the children
                    let queried_child_index =
                        min_or_max(&internal_node).expect("a child always exists");
                    let child_node_key =
                        internal_node.get_child_without_siblings(&node_key, queried_child_index);
                    // Proceed downwards
                    node_key = match child_node_key {
                        Some(node_key) => node_key,
                        None => {
                            bail!("Internal node has no children");
                        }
                    };
                }
                Node::Leaf(leaf_node) => {
                    return Ok(leaf_node.key_hash());
                }
                Node::Null => bail!("Null node cannot have children"),
            }
        }
        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn get_without_proof(&self, key: KeyHash, version: Version) -> Result<Option<OwnedValue>> {
        // Empty tree just returns proof with no sibling hash.
        let mut next_node_key = NodeKey::new_empty_path(version);
        let nibble_path = NibblePath::new(key.0.to_vec());
        let mut nibble_iter = nibble_path.nibbles();

        // We limit the number of loops here deliberately to avoid potential cyclic graph bugs
        // in the tree structure.
        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self.reader.get_node(&next_node_key).map_err(|err| {
                if nibble_depth == 0 {
                    MissingRootError { version }.into()
                } else {
                    err
                }
            })?;
            match next_node {
                Node::Internal(internal_node) => {
                    let queried_child_index = nibble_iter
                        .next()
                        .ok_or_else(|| format_err!("ran out of nibbles"))?;
                    let child_node_key = internal_node
                        .get_child_without_siblings(&next_node_key, queried_child_index);
                    next_node_key = match child_node_key {
                        Some(node_key) => node_key,
                        None => return Ok(None),
                    };
                }
                Node::Leaf(leaf_node) => {
                    return Ok(if leaf_node.key_hash() == key {
                        Some(leaf_node.value().to_vec())
                    } else {
                        None
                    });
                }
                Node::Null => {
                    if nibble_depth == 0 {
                        return Ok(None);
                    } else {
                        bail!(
                            "Non-root null node exists with node key {:?}",
                            next_node_key
                        );
                    }
                }
            }
        }
        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    /// Gets the proof that shows a list of keys up to `rightmost_key_to_prove` exist at `version`.
    pub fn get_range_proof(
        &self,
        rightmost_key_to_prove: KeyHash,
        version: Version,
    ) -> Result<SparseMerkleRangeProof> {
        let (account, proof) = self.get_with_proof(rightmost_key_to_prove, version)?;
        ensure!(account.is_some(), "rightmost_key_to_prove must exist.");

        let siblings = proof
            .siblings()
            .iter()
            .rev()
            .zip(rightmost_key_to_prove.0.iter_bits())
            .filter_map(|(sibling, bit)| {
                // We only need to keep the siblings on the right.
                if !bit {
                    Some(*sibling)
                } else {
                    None
                }
            })
            .rev()
            .collect();
        Ok(SparseMerkleRangeProof::new(siblings))
    }

    /// Returns the value (if applicable), without any proof.
    ///
    /// Equivalent to [`get_with_proof`](JellyfishMerkleTree::get_with_proof) and dropping the
    /// proof, but more efficient.
    pub fn get(&self, key: KeyHash, version: Version) -> Result<Option<OwnedValue>> {
        self.get_without_proof(key, version)
    }

    fn get_root_node(&self, version: Version) -> Result<Node> {
        self.get_root_node_option(version)?
            .ok_or_else(|| format_err!("Root node not found for version {}.", version))
    }

    pub(crate) fn get_root_node_option(&self, version: Version) -> Result<Option<Node>> {
        let root_node_key = NodeKey::new_empty_path(version);
        self.reader.get_node_option(&root_node_key)
    }

    pub fn get_root_hash(&self, version: Version) -> Result<RootHash> {
        self.get_root_node(version).map(|n| RootHash(n.hash()))
    }

    pub fn get_root_hash_option(&self, version: Version) -> Result<Option<RootHash>> {
        Ok(self
            .get_root_node_option(version)?
            .map(|n| RootHash(n.hash())))
    }

    // TODO: should this be public? seems coupled to tests?
    pub fn get_leaf_count(&self, version: Version) -> Result<Option<usize>> {
        if self.leaf_count_migration {
            self.get_root_node(version).map(|n| n.leaf_count())
        } else {
            // When all children of an internal node are leaves, the leaf count is accessible
            // even if the migration haven't started. In fact, in such a case, there's no difference
            // in the old and new serialization format. Forcing it None here just to make the tests
            // straightforward.
            Ok(None)
        }
    }
}

/// The result of putting a single key-value pair into the tree, or deleting a key.
enum PutResult<T> {
    // Put a key-value pair successfully.
    Updated(T),
    // Deleted a key successfully.
    Removed,
    // Key to delete not found.
    NotChanged,
}

/// A proof of non-existence by exclusion between two adjacent neighbors._
#[derive(Debug)]
pub enum ExclusionProof {
    Leftmost {
        leftmost_right_proof: SparseMerkleProof,
    },
    Middle {
        leftmost_right_proof: SparseMerkleProof,
        rightmost_left_proof: SparseMerkleProof,
    },
    Rightmost {
        rightmost_left_proof: SparseMerkleProof,
    },
}

#[derive(Clone, Copy)]
enum Extreme {
    Left,
    Right,
}

impl Extreme {
    fn opposite(&self) -> Self {
        match self {
            Extreme::Left => Extreme::Right,
            Extreme::Right => Extreme::Left,
        }
    }
}

enum SearchResult {
    FoundLeaf {
        ordering: Ordering,
        leaf_hash: KeyHash,
        path_to_leaf: NibblePath,
        parents: Vec<InternalNode>,
    },
    FoundInternal {
        path_to_internal: NibblePath,
        parents: Vec<InternalNode>,
    },
}
