use anyhow::{format_err, Result};
use futures::future::BoxFuture;

use crate::node_type::{LeafNode, Node, NodeKey};

/// Defines the interface between a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// and underlying storage holding nodes.
pub trait TreeReader {
    /// Gets node given a node key. Returns `None` if the node does not exist.
    fn get_node_option<'future, 'a: 'future, 'n: 'future>(
        &'a self,
        node_key: &'n NodeKey,
    ) -> BoxFuture<'future, Result<Option<Node>>>;

    /// Gets the rightmost leaf. Note that this assumes we are in the process of restoring the tree
    /// and all nodes are at the same version.
    #[allow(clippy::type_complexity)]
    fn get_rightmost_leaf<'future, 'a: 'future>(
        &'a self,
    ) -> BoxFuture<'future, Result<Option<(NodeKey, LeafNode)>>>;
}

/// Internal helper: Gets node given a node key. Returns error if the node does not exist.
async fn get_node_async<R: TreeReader>(reader: &R, node_key: &NodeKey) -> Result<Node> {
    reader
        .get_node_option(node_key)
        .await?
        .ok_or_else(|| format_err!("Missing node at {:?}.", node_key))
}
