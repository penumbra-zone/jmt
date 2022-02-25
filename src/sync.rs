//! A synchronous version of the API for use with blocking I/O.
//!
//! This is a stub module, to be filled in later with sync-wrapped version
//! of the async versions of the code.

use crate::*;

pub mod storage {
    pub use node_type::{Node, NodeDecodeError, NodeKey};
    pub use writer::{NodeBatch, NodeStats, StaleNodeIndex, StaleNodeIndexBatch, TreeUpdateBatch};

    pub trait TreeWriter {}
    pub trait TreeReader {}

    use super::*;
}
pub mod restore {
    // todo : fill in
    pub struct JellyfishMerkleRestore {}
    pub trait StateSnapshotReceiver {}
}

pub mod mock {
    pub struct MockTreeStore {}
}

pub struct JellyFishMerkleTree {}
pub struct JellyfishMerkleIterator {}
