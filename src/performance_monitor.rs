// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Performance metrics for sharded storage operations.
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    /// Number of read operations
    pub read_ops: u64,
    /// Number of write operations
    pub write_ops: u64,
    /// Total time spent on read operations
    pub total_read_time: Duration,
    /// Total time spent on write operations
    pub total_write_time: Duration,
    /// Number of nodes read
    pub nodes_read: u64,
    /// Number of nodes written
    pub nodes_written: u64,
    /// Number of parallel operations
    pub parallel_ops: u64,
    /// Total time spent on parallel operations
    pub total_parallel_time: Duration,
}

impl PerformanceMetrics {
    /// Creates new performance metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets all metrics to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Calculates average read operation time.
    pub fn avg_read_time(&self) -> Duration {
        if self.read_ops == 0 {
            return Duration::ZERO;
        }
        self.total_read_time / self.read_ops as u32
    }

    /// Calculates average write operation time.
    pub fn avg_write_time(&self) -> Duration {
        if self.write_ops == 0 {
            return Duration::ZERO;
        }
        self.total_write_time / self.write_ops as u32
    }

    /// Calculates average parallel operation time.
    pub fn avg_parallel_time(&self) -> Duration {
        if self.parallel_ops == 0 {
            return Duration::ZERO;
        }
        self.total_parallel_time / self.parallel_ops as u32
    }

    /// Calculates read throughput (nodes per second).
    pub fn read_throughput(&self) -> f64 {
        let total_time = self.total_read_time.as_secs_f64();
        if total_time == 0.0 {
            return 0.0;
        }
        self.nodes_read as f64 / total_time
    }

    /// Calculates write throughput (nodes per second).
    pub fn write_throughput(&self) -> f64 {
        let total_time = self.total_write_time.as_secs_f64();
        if total_time == 0.0 {
            return 0.0;
        }
        self.nodes_written as f64 / total_time
    }

    /// Merges another set of metrics into this one.
    pub fn merge(&mut self, other: &PerformanceMetrics) {
        self.read_ops += other.read_ops;
        self.write_ops += other.write_ops;
        self.total_read_time += other.total_read_time;
        self.total_write_time += other.total_write_time;
        self.nodes_read += other.nodes_read;
        self.nodes_written += other.nodes_written;
        self.parallel_ops += other.parallel_ops;
        self.total_parallel_time += other.total_parallel_time;
    }
}

/// Performance monitor for tracking and reporting metrics.
pub struct PerformanceMonitor {
    metrics: Arc<Mutex<PerformanceMetrics>>,
    shard_metrics: Arc<Mutex<HashMap<usize, PerformanceMetrics>>>,
}

impl PerformanceMonitor {
    /// Creates a new performance monitor.
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(PerformanceMetrics::new())),
            shard_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Records a read operation.
    pub fn record_read(&self, duration: Duration, nodes: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.read_ops += 1;
        metrics.total_read_time += duration;
        metrics.nodes_read += nodes;
    }

    /// Records a write operation.
    pub fn record_write(&self, duration: Duration, nodes: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.write_ops += 1;
        metrics.total_write_time += duration;
        metrics.nodes_written += nodes;
    }

    /// Records a parallel operation.
    pub fn record_parallel(&self, duration: Duration) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.parallel_ops += 1;
        metrics.total_parallel_time += duration;
    }

    /// Records a read operation for a specific shard.
    pub fn record_shard_read(&self, shard_idx: usize, duration: Duration, nodes: u64) {
        let mut shard_metrics = self.shard_metrics.lock().unwrap();
        let metrics = shard_metrics.entry(shard_idx).or_insert_with(PerformanceMetrics::new);
        metrics.read_ops += 1;
        metrics.total_read_time += duration;
        metrics.nodes_read += nodes;
    }

    /// Records a write operation for a specific shard.
    pub fn record_shard_write(&self, shard_idx: usize, duration: Duration, nodes: u64) {
        let mut shard_metrics = self.shard_metrics.lock().unwrap();
        let metrics = shard_metrics.entry(shard_idx).or_insert_with(PerformanceMetrics::new);
        metrics.write_ops += 1;
        metrics.total_write_time += duration;
        metrics.nodes_written += nodes;
    }

    /// Gets the current metrics.
    pub fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Gets metrics for a specific shard.
    pub fn get_shard_metrics(&self, shard_idx: usize) -> Option<PerformanceMetrics> {
        self.shard_metrics.lock().unwrap().get(&shard_idx).cloned()
    }

    /// Gets metrics for all shards.
    pub fn get_all_shard_metrics(&self) -> HashMap<usize, PerformanceMetrics> {
        self.shard_metrics.lock().unwrap().clone()
    }

    /// Resets all metrics.
    pub fn reset(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.reset();
        let mut shard_metrics = self.shard_metrics.lock().unwrap();
        shard_metrics.clear();
    }

    /// Generates a performance report.
    pub fn generate_report(&self) -> PerformanceReport {
        let metrics = self.get_metrics();
        let shard_metrics = self.get_all_shard_metrics();
        PerformanceReport {
            overall: metrics,
            shard_metrics,
        }
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance report containing metrics for analysis.
#[derive(Debug, Clone)]
pub struct PerformanceReport {
    /// Overall performance metrics
    pub overall: PerformanceMetrics,
    /// Per-shard performance metrics
    pub shard_metrics: HashMap<usize, PerformanceMetrics>,
}

impl PerformanceReport {
    /// Formats the report as a string.
    pub fn format(&self) -> String {
        let mut output = String::new();
        
        output.push_str("=== Performance Report ===\n\n");
        output.push_str("Overall Metrics:\n");
        output.push_str(&format!("  Read Operations: {}\n", self.overall.read_ops));
        output.push_str(&format!("  Write Operations: {}\n", self.overall.write_ops));
        output.push_str(&format!("  Nodes Read: {}\n", self.overall.nodes_read));
        output.push_str(&format!("  Nodes Written: {}\n", self.overall.nodes_written));
        output.push_str(&format!("  Parallel Operations: {}\n", self.overall.parallel_ops));
        output.push_str(&format!("  Avg Read Time: {:?}\n", self.overall.avg_read_time()));
        output.push_str(&format!("  Avg Write Time: {:?}\n", self.overall.avg_write_time()));
        output.push_str(&format!("  Avg Parallel Time: {:?}\n", self.overall.avg_parallel_time()));
        output.push_str(&format!("  Read Throughput: {:.2} nodes/sec\n", self.overall.read_throughput()));
        output.push_str(&format!("  Write Throughput: {:.2} nodes/sec\n", self.overall.write_throughput()));
        
        if !self.shard_metrics.is_empty() {
            output.push_str("\nPer-Shard Metrics:\n");
            let mut shard_indices: Vec<_> = self.shard_metrics.keys().collect();
            shard_indices.sort();
            
            for shard_idx in shard_indices {
                if let Some(metrics) = self.shard_metrics.get(&shard_idx) {
                    output.push_str(&format!("  Shard {}:\n", shard_idx));
                    output.push_str(&format!("    Read Operations: {}\n", metrics.read_ops));
                    output.push_str(&format!("    Write Operations: {}\n", metrics.write_ops));
                    output.push_str(&format!("    Nodes Read: {}\n", metrics.nodes_read));
                    output.push_str(&format!("    Nodes Written: {}\n", metrics.nodes_written));
                    output.push_str(&format!("    Avg Read Time: {:?}\n", metrics.avg_read_time()));
                    output.push_str(&format!("    Avg Write Time: {:?}\n", metrics.avg_write_time()));
                    output.push_str(&format!("    Read Throughput: {:.2} nodes/sec\n", metrics.read_throughput()));
                    output.push_str(&format!("    Write Throughput: {:.2} nodes/sec\n", metrics.write_throughput()));
                }
            }
        }
        
        output.push_str("========================\n");
        output
    }
}

/// Timer for measuring operation duration.
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Starts a new timer.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Stops the timer and returns the elapsed duration.
    pub fn stop(&self) -> Duration {
        self.start.elapsed()
    }

    /// Times an operation and returns the result along with duration.
    pub fn time<F, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> T,
    {
        let timer = Self::start();
        let result = f();
        let duration = timer.stop();
        (result, duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::new();
        
        metrics.read_ops = 100;
        metrics.total_read_time = Duration::from_secs(1);
        metrics.nodes_read = 1000;
        
        assert_eq!(metrics.avg_read_time(), Duration::from_millis(10));
        assert_eq!(metrics.read_throughput(), 1000.0);
    }

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();
        
        monitor.record_read(Duration::from_millis(100), 10);
        monitor.record_write(Duration::from_millis(200), 20);
        
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.read_ops, 1);
        assert_eq!(metrics.write_ops, 1);
        assert_eq!(metrics.nodes_read, 10);
        assert_eq!(metrics.nodes_written, 20);
    }

    #[test]
    fn test_performance_report() {
        let monitor = PerformanceMonitor::new();
        
        monitor.record_read(Duration::from_millis(100), 10);
        monitor.record_shard_read(0, Duration::from_millis(50), 5);
        monitor.record_shard_read(1, Duration::from_millis(50), 5);
        
        let report = monitor.generate_report();
        assert_eq!(report.overall.read_ops, 1);
        assert_eq!(report.shard_metrics.len(), 2);
        
        let formatted = report.format();
        assert!(formatted.contains("Performance Report"));
        assert!(formatted.contains("Overall Metrics"));
        assert!(formatted.contains("Per-Shard Metrics"));
    }

    #[test]
    fn test_timer() {
        let timer = Timer::start();
        std::thread::sleep(Duration::from_millis(10));
        let duration = timer.stop();
        
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_timer_closure() {
        let (result, duration) = Timer::time(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
        assert!(duration >= Duration::from_millis(10));
    }
}
