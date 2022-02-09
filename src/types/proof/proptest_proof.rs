// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! All proofs generated in this module are not valid proofs. They are only for the purpose of
//! testing conversion between Rust and Protobuf.

use proptest::{collection::vec, prelude::*};

use crate::{
    hash::{HashValue, SPARSE_MERKLE_PLACEHOLDER_HASH},
    types::proof::{SparseMerkleLeafNode, SparseMerkleProof, SparseMerkleRangeProof},
};

fn arb_non_placeholder_sparse_merkle_sibling() -> impl Strategy<Value = HashValue> {
    any::<HashValue>().prop_filter("Filter out placeholder sibling.", |x| {
        *x != *SPARSE_MERKLE_PLACEHOLDER_HASH
    })
}

fn arb_sparse_merkle_sibling() -> impl Strategy<Value = HashValue> {
    prop_oneof![
        arb_non_placeholder_sparse_merkle_sibling(),
        Just(*SPARSE_MERKLE_PLACEHOLDER_HASH),
    ]
}

impl Arbitrary for SparseMerkleProof {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<Option<SparseMerkleLeafNode>>(),
            (0..=256usize).prop_flat_map(|len| {
                if len == 0 {
                    Just(vec![]).boxed()
                } else {
                    (
                        arb_non_placeholder_sparse_merkle_sibling(),
                        vec(arb_sparse_merkle_sibling(), len),
                    )
                        .prop_map(|(first_sibling, mut siblings)| {
                            siblings[0] = first_sibling;
                            siblings
                        })
                        .boxed()
                }
            }),
        )
            .prop_map(|(leaf, siblings)| SparseMerkleProof::new(leaf, siblings))
            .boxed()
    }
}

impl Arbitrary for SparseMerkleRangeProof {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        vec(arb_sparse_merkle_sibling(), 0..=256)
            .prop_map(Self::new)
            .boxed()
    }
}
