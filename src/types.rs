// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod nibble;
pub mod proof;
pub mod value_identifier;

/// Specifies a particular version of the [`JellyfishMerkleTree`](crate::JellyfishMerkleTree) state.
pub type Version = u64; // Height - also used for MVCC in StateDB

// In StateDB, things readable by the genesis transaction are under this version.
pub const PRE_GENESIS_VERSION: Version = u64::max_value();
