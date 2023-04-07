// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub use metrics::*;

#[cfg(feature = "metrics")]
mod metrics {
    use once_cell::sync::Lazy;
    use prometheus::{register_int_counter, IntCounter};

    pub static DIEM_JELLYFISH_LEAF_ENCODED_BYTES: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "diem_jellyfish_leaf_encoded_bytes",
            "Diem jellyfish leaf encoded bytes in total"
        )
        .unwrap()
    });

    pub static DIEM_JELLYFISH_INTERNAL_ENCODED_BYTES: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "diem_jellyfish_internal_encoded_bytes",
            "Diem jellyfish total internal nodes encoded in bytes"
        )
        .unwrap()
    });

    pub static DIEM_JELLYFISH_STORAGE_READS: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "diem_jellyfish_storage_reads",
            "Diem jellyfish reads from storage"
        )
        .unwrap()
    });

    pub fn inc_leaf_encoded_bytes_metric_if_enabled(amount: u64) {
        DIEM_JELLYFISH_LEAF_ENCODED_BYTES.inc_by(amount);
    }

    pub fn inc_internal_encoded_bytes_metric_if_enabled(amount: u64) {
        DIEM_JELLYFISH_INTERNAL_ENCODED_BYTES.inc_by(amount);
    }

    pub fn inc_storage_reads_metric_if_enabled(amount: u64) {
        DIEM_JELLYFISH_STORAGE_READS.inc_by(amount);
    }
}

#[cfg(not(feature = "metrics"))]
mod metrics {
    pub fn inc_storage_reads_metric_if_enabled(_amount: u64) {}
}
