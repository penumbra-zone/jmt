use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{mock::MockTreeStore, KeyHash, Sha256Jmt};

#[derive(Serialize, Deserialize)]
struct TestVectorWrapper {
    pub vectors: Vec<TestVector>,
}

#[derive(Serialize, Deserialize)]
struct TestVector {
    #[serde(with = "hex::serde")]
    pub expected_root: [u8; 32],
    pub data: Vec<KeyValuePair>,
}

#[derive(Serialize, Deserialize)]
struct KeyValuePair {
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub value: Vec<u8>,
}

#[test]
fn test_with_vectors() {
    let reader = std::fs::File::open("src/tests/sha2_256_vectors.json").unwrap();

    let test_file: TestVectorWrapper =
        serde_json::from_reader(reader).expect("test vectors must be valid json");

    let store = &MockTreeStore::default();

    let jmt = Sha256Jmt::new(store);
    for vector in test_file.vectors {
        let mut key_value_pairs = vec![];
        for pair in vector.data {
            let key_hash = KeyHash::with::<Sha256>(&pair.key);
            key_value_pairs.push((key_hash, Some(pair.value)));
        }

        let root = jmt
            .put_value_set(key_value_pairs, 0)
            .expect("tree update must not fail")
            .0;
        assert_eq!(root.0, vector.expected_root);
    }
}
