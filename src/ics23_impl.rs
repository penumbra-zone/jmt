use anyhow::{anyhow, Result};

use crate::{storage::TreeReader, JellyfishMerkleTree, Version};

impl<'a, R> JellyfishMerkleTree<'a, R>
where
    R: 'a + TreeReader,
{
    /// Returns the value and an [`ics23::ExistenceProof`].
    pub fn get_with_ics23_proof(
        &self,
        key: Vec<u8>,
        version: Version,
    ) -> Result<ics23::ExistenceProof> {
        let key_hash = key.as_slice().into();
        let (value, proof) = self.get_with_proof(key_hash, version)?;
        let value = value.ok_or_else(|| {
            anyhow!(
                "Requested proof of inclusion for non-existent key {:?}",
                key
            )
        })?;

        let mut path = Vec::new();
        let mut skip = 256 - proof.siblings().len();
        let mut sibling_idx = 0;

        for byte_idx in (0..32).rev() {
            // The JMT proofs iterate over the bits in MSB order
            for bit_idx in 0..8 {
                if skip > 0 {
                    skip -= 1;
                    continue;
                } else {
                    let bit = (key_hash.0[byte_idx] >> bit_idx) & 0x1;
                    // ICS23 InnerOp computes
                    //    hash( prefix || current || suffix )
                    // so we want to construct (prefix, suffix) so that this is
                    // the correct hash-of-internal-node
                    let (prefix, suffix) = if bit == 1 {
                        // We want hash( domsep || sibling || current )
                        // so prefix = domsep || sibling
                        //    suffix = (empty)
                        let mut prefix = Vec::with_capacity(16 + 32);
                        prefix.extend_from_slice(b"JMT::IntrnalNode");
                        prefix.extend_from_slice(&proof.siblings()[sibling_idx]);
                        (prefix, Vec::new())
                    } else {
                        // We want hash( domsep || current || sibling )
                        // so prefix = domsep
                        //    suffix = sibling
                        let prefix = b"JMT::IntrnalNode".to_vec();
                        let suffix = proof.siblings()[sibling_idx].to_vec();
                        (prefix, suffix)
                    };
                    path.push(ics23::InnerOp {
                        hash: ics23::HashOp::Sha256.into(),
                        prefix,
                        suffix,
                    });
                    sibling_idx += 1;
                }
            }
        }

        Ok(ics23::ExistenceProof {
            key,
            value,
            path,
            leaf: Some(ics23::LeafOp {
                hash: ics23::HashOp::Sha256.into(),
                prehash_key: ics23::HashOp::Sha256.into(),
                prehash_value: ics23::HashOp::Sha256.into(),
                length: ics23::LengthOp::NoPrefix.into(),
                prefix: b"JMT::LeafNode".to_vec(),
            }),
        })
    }
}

pub fn ics23_spec() -> ics23::ProofSpec {
    ics23::ProofSpec {
        leaf_spec: Some(ics23::LeafOp {
            hash: ics23::HashOp::Sha256.into(),
            prehash_key: ics23::HashOp::Sha256.into(),
            prehash_value: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prefix: b"JMT::LeafNode".to_vec(),
        }),
        inner_spec: Some(ics23::InnerSpec {
            // This is the only field we're sure about
            hash: ics23::HashOp::Sha256.into(),
            // These fields are apparently used for neighbor tests in range proofs,
            // and could be wrong:
            child_order: vec![0, 1], //where exactly does this need to be true?
            min_prefix_length: 16,   //what is this?
            max_prefix_length: 48,   //and this?
            child_size: 32,
            empty_child: vec![], //check JMT repo to determine if special value used here
        }),
        // TODO: check this
        min_depth: 0,
        // TODO:
        max_depth: 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mock::MockTreeStore, KeyHash};

    #[test]
    fn test_jmt_ics23_existence() {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        let key = b"key";
        let key_hash = KeyHash::from(&key);

        // For testing, insert multiple values into the tree
        let mut kvs = Vec::new();
        kvs.push((key_hash, Some(b"value".to_vec())));
        // make sure we have some sibling nodes, through carefully constructed k/v entries that will have overlapping paths
        for i in 1..4 {
            let mut overlap_key = KeyHash([0; 32]);
            overlap_key.0[0..i].copy_from_slice(&key_hash.0[0..i]);
            kvs.push((overlap_key, Some(b"bogus value".to_vec())));
        }

        let (new_root_hash, batch) = tree.put_value_set(kvs, 0).unwrap();
        db.write_tree_update_batch(batch).unwrap();

        let existence_proof = tree.get_with_ics23_proof(b"key".to_vec(), 0).unwrap();

        let commitment_proof = ics23::CommitmentProof {
            proof: Some(ics23::commitment_proof::Proof::Exist(existence_proof)),
        };

        assert!(ics23::verify_membership(
            &commitment_proof,
            &ics23_spec(),
            &new_root_hash.0.to_vec(),
            b"key",
            b"value",
        ));
    }

    #[test]
    fn test_jmt_ics23_existence_random_keys() {
        let db = MockTreeStore::default();
        let tree = JellyfishMerkleTree::new(&db);

        const MAX_VERSION: u64 = 1 << 14;

        for version in 0..=MAX_VERSION {
            let key = format!("key{}", version).into_bytes();
            let value = format!("value{}", version).into_bytes();
            let (_root, batch) = tree
                .put_value_set(vec![(key.as_slice().into(), Some(value))], version)
                .unwrap();
            db.write_tree_update_batch(batch).unwrap();
        }

        let existence_proof = tree
            .get_with_ics23_proof(format!("key{}", MAX_VERSION).into_bytes(), MAX_VERSION)
            .unwrap();

        let commitment_proof = ics23::CommitmentProof {
            proof: Some(ics23::commitment_proof::Proof::Exist(existence_proof)),
        };

        let root_hash = tree.get_root_hash(MAX_VERSION).unwrap().0.to_vec();

        assert!(ics23::verify_membership(
            &commitment_proof,
            &ics23_spec(),
            &root_hash,
            format!("key{}", MAX_VERSION).as_bytes(),
            format!("value{}", MAX_VERSION).as_bytes(),
        ));
    }
}
