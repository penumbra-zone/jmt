extern crate alloc;

use jmt::mock::MockTreeStore;
use jmt::JellyfishMerkleTree;
use jmt::KeyHash;
use jmt::OwnedValue;
use rand::Rng;

pub fn generate_random_keys(count: usize) -> Vec<KeyHash> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            KeyHash(key)
        })
        .collect()
}

pub fn generate_random_values(count: usize, value_size: usize) -> Vec<OwnedValue> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            (0..value_size).map(|_| rng.gen::<u8>()).collect()
        })
        .collect()
}

pub fn generate_value_set(count: usize, value_size: usize) -> Vec<(KeyHash, OwnedValue)> {
    let keys = generate_random_keys(count);
    let values = generate_random_values(count, value_size);
    keys.into_iter().zip(values.into_iter()).collect()
}

pub fn generate_value_set_with_distribution(
    count: usize,
    value_size: usize,
    distribution: KeyDistribution,
) -> Vec<(KeyHash, OwnedValue)> {
    match distribution {
        KeyDistribution::Random => generate_value_set(count, value_size),
        KeyDistribution::Concentrated => generate_concentrated_keys(count, value_size, 2),
        KeyDistribution::Sparse => generate_sparse_keys(count, value_size),
    }
}

pub fn generate_concentrated_keys(
    count: usize,
    value_size: usize,
    num_subtrees: usize,
) -> Vec<(KeyHash, OwnedValue)> {
    let mut rng = rand::thread_rng();
    let subtree_indices: Vec<u8> = (0..num_subtrees)
        .map(|_| rng.gen_range(0..16))
        .collect();
    
    (0..count)
        .map(|_| {
            let mut key = [0u8; 32];
            (0..32).for_each(|i| key[i] = rng.gen());
            key[0] = subtree_indices[rng.gen_range(0..num_subtrees)];
            let value: OwnedValue = (0..value_size).map(|_| rng.gen()).collect();
            (KeyHash(key), value)
        })
        .collect()
}

pub fn generate_sparse_keys(count: usize, value_size: usize) -> Vec<(KeyHash, OwnedValue)> {
    let mut rng = rand::thread_rng();
    let mut used_subtrees = Vec::new();
    
    (0..count)
        .map(|_| {
            let mut key = [0u8; 32];
            if used_subtrees.is_empty() || rng.gen_bool(0.3) {
                let subtree = rng.gen_range(0..16);
                if !used_subtrees.contains(&subtree) {
                    used_subtrees.push(subtree);
                }
            }
            (0..32).for_each(|i| key[i] = rng.gen());
            if !used_subtrees.is_empty() {
                key[0] = used_subtrees[rng.gen_range(0..used_subtrees.len())];
            }
            let value: OwnedValue = (0..value_size).map(|_| rng.gen()).collect();
            (KeyHash(key), value)
        })
        .collect()
}

pub enum KeyDistribution {
    Random,
    Concentrated,
    Sparse,
}

pub fn compute_key_distribution(value_set: &[(KeyHash, OwnedValue)]) -> [usize; 16] {
    let mut distribution = [0usize; 16];
    for (key, _) in value_set {
        let subtree_index = key.0[0] as usize % 16;
        distribution[subtree_index] += 1;
    }
    distribution
}
