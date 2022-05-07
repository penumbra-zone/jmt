use std::collections::HashMap;

use anyhow::Result;
use tracing::instrument;

use crate::{
    storage::{TreeReader, TreeWriter},
    JellyfishMerkleTree, KeyHash, MissingRootError, OwnedValue, RootHash, Version,
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

impl<R> WriteOverlay<R> {
    /// Use this [`Version`] with [`Self::new`] to specify that the writes
    /// should be committed with version `0`.
    pub const PRE_GENESIS_VERSION: Version = u64::MAX;
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
    ///
    /// To initialize an empty tree, use [`Self::PRE_GENESIS_VERSION`] here.
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
    #[instrument(name = "WriteOverlay::get", skip(self, key))]
    pub async fn get(&self, key: KeyHash) -> Result<Option<OwnedValue>> {
        if let Some(value) = self.overlay.get(&key) {
            tracing::trace!(?key, value = ?hex::encode(&value), "read from cache");
            Ok(Some(value.clone()))
        } else {
            match self.tree().get(key, self.version).await {
                Ok(Some(value)) => {
                    tracing::trace!(version = ?self.version, ?key, value = ?hex::encode(&value), "read from tree");
                    Ok(Some(value))
                }
                Ok(None) => {
                    tracing::trace!(version = ?self.version, ?key, "key not found in tree");
                    Ok(None)
                }
                // This allows for using the Overlay on an empty database without errors
                Err(e) if e.downcast_ref::<MissingRootError>().is_some() => {
                    tracing::trace!(version = ?self.version, "no data available at this version");
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
    }

    /// Puts a key/value pair in the overlay.
    ///
    /// Assuming it is not overwritten by a subsequent `put`, the value will be
    /// written to the tree when `commit` is called.
    #[instrument(name = "WriteOverlay::put", skip(self, key, value))]
    pub fn put(&mut self, key: KeyHash, value: OwnedValue) {
        tracing::trace!(?key, value = ?hex::encode(&value));
        *self.overlay.entry(key).or_default() = value;
    }

    /// Deletes a key from the overlay.
    ///
    /// Assuming it is not overwritten by a subsequent `put`, the value will not be
    /// written to the tree when `commit` is called, and any previous value will be
    /// erased.
    #[instrument(name = "WriteOverlay::del", skip(self, key))]
    pub fn del(&mut self, key: KeyHash) {
        tracing::trace!(?key);
        self.overlay.remove(&key);
    }

    /// Clears the overlay, committing all pending writes to the provided
    /// `writer` and returning the new [`RootHash`] and [`Version`].
    ///
    /// The overlay will then point at the newly written state and tree version.
    #[instrument(name = "WriteOverlay::commit", skip(self, writer))]
    pub async fn commit<W>(&mut self, mut writer: W) -> Result<(RootHash, Version)>
    where
        W: TreeWriter + Sync,
    {
        let overlay = std::mem::replace(&mut self.overlay, Default::default());
        // We use wrapping_add here so that we can write `new_version = 0` by
        // overflowing `PRE_GENESIS_VERSION`.
        let new_version = self.version.wrapping_add(1);
        tracing::trace!(old_version = ?self.version, new_version, ?overlay);
        let (root_hash, batch) = self
            .tree()
            .put_value_set(overlay.into_iter().collect(), new_version)
            .await?;

        // TODO: determine deletions and modify JMT appropriately?

        writer.write_node_batch(&batch.node_batch).await?;
        tracing::trace!(?root_hash, "wrote node batch to backing store");

        // Now that we've successfully written the new nodes, update the version.
        self.version = new_version;

        Ok((root_hash, new_version))
    }
}
