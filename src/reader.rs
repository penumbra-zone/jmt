use anyhow::{format_err, Result};

use crate::node_type::{AugmentedLeafNode, AugmentedNode, LeafNode, Node, NodeKey};
use crate::types::value_identifier::ValueIdentifier;
use crate::{KeyHash, OwnedValue};

/// Defines the interface between a
/// [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
/// and underlying storage holding nodes.
pub trait TreeReader {
    /// Gets node given a node key. Returns error if the node does not exist.
    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        self.get_node_option(node_key)?
            .ok_or_else(|| format_err!("Missing node at {:?}.", node_key))
    }

    /// Gets node given a node key. Returns `None` if the node does not exist.
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>>;

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version. Returns an error if the value does not exist.
    fn get_value(&self, value_id: &ValueIdentifier) -> Result<OwnedValue> {
        self.get_value_option(value_id)?
            .ok_or_else(|| format_err!("Missing value with id {value_id:?}."))
    }

    /// Gets a value by identifier, returning the newest value whose version is *less than or
    /// equal to* the specified version.  Returns None if the value does not exist.
    fn get_value_option(&self, value_id: &ValueIdentifier) -> Result<Option<OwnedValue>>;

    /// Gets the latest version of a value given the key hash. Returns an error if the value does not exist.
    fn get_latest_value(&self, key_hash: KeyHash) -> Result<OwnedValue> {
        self.get_latest_value_option(key_hash)?
            .ok_or_else(|| format_err!("Missing value with key_hash {key_hash:?}."))
    }

    /// Gets the latest version of a value given the key hash. Returns None if the value does not exist.
    fn get_latest_value_option(&self, key_hash: KeyHash) -> Result<Option<OwnedValue>> {
        self.get_value_option(&ValueIdentifier::new(u64::MAX, key_hash))
    }

    /// Gets an [`AugmentedNode`] given a [`NodeKey`]. Returns an error if the node does not exist
    fn get_augmented_node(&self, node_key: &NodeKey) -> Result<AugmentedNode> {
        self.get_augmented_node_option(node_key)?
            .ok_or_else(|| format_err!("Missing augmented node with key {:?}.", node_key))
    }

    /// Gets an [`AugmentedNode`] given a [`NodeKey`]. Returns `None` if the node does not exist.
    fn get_augmented_node_option(&self, node_key: &NodeKey) -> Result<Option<AugmentedNode>> {
        if let Some(node) = self.get_node_option(node_key)? {
            return match node {
                Node::Null => Ok(Some(AugmentedNode::Null)),
                Node::Internal(internal) => Ok(Some(internal.into())),
                Node::Leaf(leaf) => {
                    let value =
                        self.get_value(&ValueIdentifier::new(node_key.version(), leaf.key_hash()))?;
                    Ok(Some(AugmentedNode::Leaf(AugmentedLeafNode::from_parts(
                        leaf, value,
                    ))))
                }
            };
        };
        Ok(None)
    }

    /// Gets the rightmost leaf. Note that this assumes we are in the process of restoring the tree
    /// and all nodes are at the same version.
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>>;
}

/// Defines the ability for a tree to look up the preimage of its key hashes.
pub trait HasPreimage {
    /// Gets the preimage of a key hash, if it is present in the tree.
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>>;
}
