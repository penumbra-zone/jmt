use std::collections::HashMap;

use anyhow::Result;

use crate::{
    storage::{TreeReader, TreeWriter},
    JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, Version,
};

// There's some similarity between the OverlayTree and the TreeCache, but it's
// not exactly clear how to share code between them (the TreeCache operates at
// the level of the tree internals, not at the level of its external interface),
// so it's easier and better for now to just make a new wrapper.

/// A wrapper around a [`JellyfishMerkleTree`] that buffers pending writes to the
/// tree, and overlays the effect of those writes on the tree state for reading.
pub struct WriteOverlay<R> {
    reader: R,
    overlay: HashMap<KeyHash, OwnedValue>,
    version: Version,
}

impl<R> WriteOverlay<R>
where
    R: TreeReader + Sync,
{
    /// Constructs a new [`WriteOverlay`] with the given `reader` and `version`.
    ///
    /// All reads performed with `get` will use `version` when querying the
    /// underlying backing store.  The buffered writes created with `put` will
    /// be written as `version + 1`, so `version` should probably be the latest
    /// version if `commit` will be called.
    pub fn new(reader: R, version: Version) -> Self {
        Self {
            reader,
            version,
            overlay: Default::default(),
        }
    }

    fn tree(&self) -> JellyfishMerkleTree<'_, R> {
        JellyfishMerkleTree::new(&self.reader)
    }

    /// Gets a value by key.
    ///
    /// This method reflects the results of any pending writes made by `put`.
    pub async fn get(&self, key: KeyHash) -> Result<Option<OwnedValue>> {
        if let Some(value) = self.overlay.get(&key) {
            Ok(Some(value.clone()))
        } else {
            self.tree().get(key, self.version).await
        }
    }

    /// Puts a key/value pair in the overlay.
    ///
    /// Assuming it is not overwritten by a subsequent `put`, the value will be
    /// written to the tree when `commit` is called.
    pub fn put(&mut self, key: KeyHash, value: OwnedValue) {
        *self.overlay.entry(key).or_default() = value;
    }

    /// Clears the overlay, committing all pending writes to the provided
    /// `writer` and returning the new [`RootHash`] and [`Version`].
    ///
    /// The overlay will then point at the newly written state and tree version.
    pub async fn commit<W>(&mut self, mut writer: W) -> Result<(RootHash, Version)>
    where
        W: TreeWriter + Sync,
    {
        let overlay = std::mem::replace(&mut self.overlay, Default::default());
        let new_version = self.version + 1;
        let (root_hash, batch) = self
            .tree()
            .put_value_set(overlay.into_iter().collect(), new_version)
            .await?;

        writer.write_node_batch(&batch.node_batch).await?;

        // Now that we've successfully written the new nodes, update the version.
        self.version = new_version;

        Ok((root_hash, new_version))
    }
}
