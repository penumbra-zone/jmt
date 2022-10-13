#[macro_use]
extern crate anyhow;

use std::{
    fmt::Debug,
    fs::File,
    ops::{Add, Div, Range},
    path::PathBuf,
    thread,
};

use clap::Parser;
use crossbeam::channel::Sender;
use indicatif::ProgressBar;
use jmt::{mock::MockTreeStore, JellyfishMerkleTree, KeyHash};
use rand::Rng;
use rayon::prelude::*;

#[derive(Debug, Parser)]
struct Opts {
    /// Output the experiment results to this CSV file.
    #[clap(long)]
    file: PathBuf,
    /// For each experiment, iterate it this number of times and average the results.
    #[clap(long, default_value = "1")]
    iterations: usize,
    /// Try the experiment with distinct keys in this range.
    #[clap(long, value_parser = parse_range)]
    distinct_keys: Range<usize>,
    /// Only sample with distinct key counts divisible by this number.
    #[clap(long, default_value = "1")]
    key_resolution: usize,
    /// Run the experiment up to this number of versions of the tree.
    #[clap(long)]
    versions: u64,
    /// Only sample with version counts divisible by this number.
    #[clap(long, default_value = "1")]
    version_resolution: u64,
    /// Try the experiment with write set sizes in this range.
    #[clap(long, value_parser = parse_range)]
    write_set_sizes: Range<usize>,
    /// Only sample with write set sizes divisible by this number.
    #[clap(long, default_value = "1")]
    write_set_size_resolution: usize,
}

fn parse_range(s: &str) -> anyhow::Result<Range<usize>> {
    let mut parts = s.splitn(2, "..");
    let start = parts
        .next()
        .ok_or_else(|| anyhow!("invalid range: missing start"))?;
    let end = parts
        .next()
        .ok_or_else(|| anyhow!("invalid range: missing end"))?;
    match (start, end) {
        ("", "") => Ok(0..usize::MAX),
        ("", end) => Ok(0..end.parse()?),
        (start, "") => Ok(start.parse()?..usize::MAX),
        (start, end) => Ok(start.parse()?..end.parse()?),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Stats<T = u32> {
    batch_reads: T,
    batch_writes: T,
    non_batch_reads: T,
    non_batch_writes: T,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
struct Row {
    iteration: usize,
    version: u64,
    distinct_keys: usize,
    write_set_size: usize,
    batch_reads: u32,
    batch_writes: u32,
    non_batch_reads: u32,
    non_batch_writes: u32,
    difference: bool,
}

impl Add for Stats {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            batch_reads: self.batch_reads + rhs.batch_reads,
            batch_writes: self.batch_writes + rhs.batch_writes,
            non_batch_reads: self.non_batch_reads + rhs.non_batch_reads,
            non_batch_writes: self.non_batch_writes + rhs.non_batch_writes,
        }
    }
}

impl Div<usize> for Stats {
    type Output = Stats<f64>;

    fn div(self, rhs: usize) -> Self::Output {
        Self::Output {
            batch_reads: f64::from(self.batch_reads) / rhs as f64,
            batch_writes: f64::from(self.batch_writes) / rhs as f64,
            non_batch_reads: f64::from(self.non_batch_reads) as f64 / rhs as f64,
            non_batch_writes: f64::from(self.non_batch_writes) as f64 / rhs as f64,
        }
    }
}

fn sample<R: Rng>(
    rng: &mut R,
    submit: Sender<Row>,
    iteration: usize,
    versions: u64,
    version_resolution: u64,
    distinct_keys: usize,
    write_set_size: usize,
) {
    let batch_storage = MockTreeStore::default();
    let batch_tree = JellyfishMerkleTree::new(&batch_storage);

    let non_batch_storage = MockTreeStore::default();
    let non_batch_tree = JellyfishMerkleTree::new(&non_batch_storage);

    // This way each run starts with a different random preimage of keys, rather than the lowest `distinct_keys` ones
    let key_preimage_offset = rng.gen::<u64>();

    for version in 0..versions {
        if distinct_keys == 0 {
            continue;
        }

        let mut write_set = Vec::with_capacity(write_set_size);
        for _ in 0..write_set_size {
            write_set.push((
                KeyHash::from(
                    (rng.gen::<u64>() % distinct_keys as u64 + key_preimage_offset).to_be_bytes(),
                ),
                vec![],
            ))
        }

        if write_set.is_empty() {
            continue;
        }

        // The differing batch vs. non-batch interface means we have to clone here
        let value_set_with_deletions = write_set
            .iter()
            .map(|(k, v)| (*k, Some(v.clone())))
            .collect();

        let (_, batch_update) = batch_tree
            .batch_put_value_sets(vec![write_set], None, version)
            .unwrap();
        batch_storage.write_tree_update_batch(batch_update).unwrap();

        let (_, non_batch_update) = non_batch_tree
            .put_value_set(value_set_with_deletions, version)
            .unwrap();
        non_batch_storage
            .write_tree_update_batch(non_batch_update)
            .unwrap();

        if version % version_resolution == 0
            && submit
                .send({
                    // Construct the CSV row to write
                    let mut row = Row {
                        iteration,
                        version,
                        distinct_keys,
                        write_set_size,
                        batch_reads: batch_storage.reads(),
                        batch_writes: batch_storage.writes(),
                        non_batch_reads: non_batch_storage.reads(),
                        non_batch_writes: non_batch_storage.writes(),
                        difference: false,
                    };
                    if row.batch_reads != row.non_batch_reads
                        || row.batch_writes != row.non_batch_writes
                    {
                        row.difference = true;
                    }
                    row
                })
                .is_err()
        {
            return;
        }
    }
}

pub fn main() -> anyhow::Result<()> {
    let Opts {
        file,
        iterations,
        distinct_keys,
        key_resolution,
        versions,
        version_resolution,
        write_set_sizes,
        write_set_size_resolution,
    } = Opts::parse();

    let (submit, receive) = crossbeam::channel::bounded(10_000);

    // Calculate expected number of trials
    let trials = iterations
        * distinct_keys.clone().step_by(key_resolution).count()
        * (0..versions).step_by(version_resolution as usize).count()
        * write_set_sizes
            .clone()
            .step_by(write_set_size_resolution)
            .count();

    let writer = thread::spawn(move || {
        let progress = ProgressBar::new(trials as u64);
        let mut writer = csv::Writer::from_writer(File::create(file)?);
        for row in receive {
            writer.serialize(row).unwrap();
            progress.inc(1);
        }
        Ok::<_, anyhow::Error>(())
    });

    distinct_keys
        .into_par_iter()
        .step_by(key_resolution)
        .for_each(|distinct_keys| {
            write_set_sizes
                .clone()
                .into_par_iter()
                .step_by(write_set_size_resolution)
                .for_each(|write_set_size| {
                    (0..iterations).into_par_iter().for_each(|iteration| {
                        sample(
                            &mut rand::thread_rng(),
                            submit.clone(),
                            iteration,
                            versions,
                            version_resolution,
                            distinct_keys,
                            write_set_size,
                        );
                    })
                })
        });

    drop(submit); // This allows the writer thread to finish, because there are no more senders
    writer.join().unwrap()?; // Wait for the writer thread to finish

    Ok(())
}
