use anyhow::Result;

use crate::node_type::{LeafNode, Node, NodeKey};
use crate::sharded_storage::ShardedTreeReader;
use crate::storage::TreeReader;
use crate::{KeyHash, OwnedValue, Version};

/// An adapter that allows a [`ShardedTreeReader`] to be used as a [`TreeReader`].
pub struct ShardedTreeReaderAdapter<R: ShardedTreeReader>(pub R);

impl<R: ShardedTreeReader> ShardedTreeReaderAdapter<R> {
    /// Creates a new adapter from a sharded tree reader.
    pub fn new(reader: R) -> Self {
        Self(reader)
    }

    /// Gets a reference to the underlying sharded tree reader.
    pub fn inner(&self) -> &R {
        &self.0
    }

    /// Gets a mutable reference to the underlying sharded tree reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.0
    }

    /// Consumes the adapter and returns the underlying sharded tree reader.
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R: ShardedTreeReader + 'static> TreeReader for ShardedTreeReaderAdapter<R> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.0.get_node_option(node_key)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<OwnedValue>> {
        self.0.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.0.get_rightmost_leaf()
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// An adapter that allows a [`ShardedTreeWriter`] to be used as a [`crate::storage::TreeWriter`].
pub struct ShardedTreeWriterAdapter<W: crate::sharded_storage::ShardedTreeWriter>(pub W);

impl<W: crate::sharded_storage::ShardedTreeWriter> ShardedTreeWriterAdapter<W> {
    /// Creates a new adapter from a sharded tree writer.
    pub fn new(writer: W) -> Self {
        Self(writer)
    }

    /// Gets a reference to the underlying sharded tree writer.
    pub fn inner(&self) -> &W {
        &self.0
    }

    /// Gets a mutable reference to the underlying sharded tree writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.0
    }

    /// Consumes the adapter and returns the underlying sharded tree writer.
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: crate::sharded_storage::ShardedTreeWriter + Sync> crate::storage::TreeWriter for ShardedTreeWriterAdapter<W> {
    fn write_node_batch(&self, node_batch: &crate::storage::NodeBatch) -> Result<()> {
        self.0.write_node_batch(node_batch)
    }
}

/// An adapter that allows a reference to a [`ShardedTreeReader`] to be used as a [`TreeReader`].
pub struct ShardedTreeReaderAdapterRef<'a, R: ShardedTreeReader>(&'a R);

impl<'a, R: ShardedTreeReader> ShardedTreeReaderAdapterRef<'a, R> {
    /// Creates a new adapter from a sharded tree reader reference.
    pub fn new(reader: &'a R) -> Self {
        Self(reader)
    }

    /// Gets a reference to the underlying sharded tree reader.
    pub fn inner(&self) -> &'a R {
        &self.0
    }
}

impl<'a, R: ShardedTreeReader + 'static> TreeReader for ShardedTreeReaderAdapterRef<'a, R> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.0.get_node_option(node_key)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<OwnedValue>> {
        self.0.get_value_option(max_version, key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.0.get_rightmost_leaf()
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self.0.as_any()
    }
}

/// An adapter that allows a reference to a [`ShardedTreeWriter`] to be used as a [`crate::storage::TreeWriter`].
pub struct ShardedTreeWriterAdapterRef<'a, W: crate::sharded_storage::ShardedTreeWriter>(&'a W);

impl<'a, W: crate::sharded_storage::ShardedTreeWriter> ShardedTreeWriterAdapterRef<'a, W> {
    /// Creates a new adapter from a sharded tree writer reference.
    pub fn new(writer: &'a W) -> Self {
        Self(writer)
    }

    /// Gets a reference to the underlying sharded tree writer.
    pub fn inner(&self) -> &'a W {
        &self.0
    }
}

impl<'a, W: crate::sharded_storage::ShardedTreeWriter + Sync> crate::storage::TreeWriter for ShardedTreeWriterAdapterRef<'a, W> {
    fn write_node_batch(&self, node_batch: &crate::storage::NodeBatch) -> Result<()> {
        self.0.write_node_batch(node_batch)
    }
}
