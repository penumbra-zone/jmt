use serde::{Deserialize, Serialize};

use crate::{KeyHash, Version};

/// Uniquely identifies a value stored in the [`JellyfishMerkleTree`](crate::JellyfishMerkleTree).
/// Enables efficient lookups on values without traversing the tree.
// TODO: REmove ordering
#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValueIdentifier {
    version: Version,
    key_hash: KeyHash,
}

impl ValueIdentifier {
    pub fn new(version: u64, key_hash: KeyHash) -> Self {
        Self { version, key_hash }
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn key_hash(&self) -> KeyHash {
        self.key_hash
    }
}
