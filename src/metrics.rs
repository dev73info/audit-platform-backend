//! 进程内指标注册表：计数器、仪表、直方图。
//!
//! 与 `doc/设计文档.md` 4.14.1 的指标定义一一对应，`/metrics` 输出 Prometheus 文本格式。

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

/// 指标标签。
pub type Labels = Vec<(String, String)>;

/// 指标键：名称 + 标签。
type MetricKey = (String, Labels);

/// 直方图：按桶统计 + 累计和与计数。
#[derive(Debug, Default, Clone, Serialize)]
pub struct Histogram {
    pub buckets: Vec<f64>,
    pub counts: Vec<u64>,
    pub sum: f64,
    pub count: u64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let counts = vec![0; buckets.len()];
        Self {
            buckets,
            counts,
            sum: 0.0,
            count: 0,
        }
    }

    pub fn observe(&mut self, value: f64) {
        for (index, upper) in self.buckets.iter().enumerate() {
            if value <= *upper {
                self.counts[index] += 1;
            }
        }
        self.sum += value;
        self.count += 1;
    }
}

#[derive(Debug, Default)]
struct Inner {
    counters: HashMap<MetricKey, f64>,
    gauges: HashMap<MetricKey, f64>,
    histograms: HashMap<MetricKey, Histogram>,
}

/// 指标注册表。
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    inner: Mutex<Inner>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// 计数器加一。
    pub fn inc(&self, name: &str, labels: Labels) {
        self.add(name, labels, 1.0);
    }

    /// 计数器累加。
    pub fn add(&self, name: &str, labels: Labels, value: f64) {
        let mut inner = self.lock();
        *inner
            .counters
            .entry((name.to_string(), labels))
            .or_insert(0.0) += value;
    }

    /// 仪表赋值。
    pub fn set_gauge(&self, name: &str, labels: Labels, value: f64) {
        let mut inner = self.lock();
        inner.gauges.insert((name.to_string(), labels), value);
    }

    /// 直方图观测。
    pub fn observe(&self, name: &str, labels: Labels, value: f64, buckets: Vec<f64>) {
        let mut inner = self.lock();
        let entry = inner
            .histograms
            .entry((name.to_string(), labels))
            .or_insert_with(|| Histogram::new(buckets));
        entry.observe(value);
    }

    /// 读取计数器的值。
    pub fn counter(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let inner = self.lock();
        let key = (
            name.to_string(),
            labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>(),
        );
        inner.counters.get(&key).copied().unwrap_or(0.0)
    }

    /// 读取全部计数器快照。
    pub fn counter_snapshot(&self) -> Vec<(String, Labels, f64)> {
        let inner = self.lock();
        let mut items: Vec<(String, Labels, f64)> = inner
            .counters
            .iter()
            .map(|((name, labels), value)| (name.clone(), labels.clone(), *value))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    /// 读取全部仪表快照。
    pub fn gauge_snapshot(&self) -> Vec<(String, Labels, f64)> {
        let inner = self.lock();
        let mut items: Vec<(String, Labels, f64)> = inner
            .gauges
            .iter()
            .map(|((name, labels), value)| (name.clone(), labels.clone(), *value))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    /// 读取全部直方图快照。
    pub fn histogram_snapshot(&self) -> Vec<(String, Labels, Histogram)> {
        let inner = self.lock();
        let mut items: Vec<(String, Labels, Histogram)> = inner
            .histograms
            .iter()
            .map(|((name, labels), value)| (name.clone(), labels.clone(), value.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    /// 输出 Prometheus 文本格式。
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        for (name, labels, value) in self.counter_snapshot() {
            out.push_str(&format!("# TYPE {} counter\n", name));
            out.push_str(&format!("{}{} {}\n", name, render_labels(&labels), value));
        }
        for (name, labels, value) in self.gauge_snapshot() {
            out.push_str(&format!("# TYPE {} gauge\n", name));
            out.push_str(&format!("{}{} {}\n", name, render_labels(&labels), value));
        }
        for (name, labels, histogram) in self.histogram_snapshot() {
            out.push_str(&format!("# TYPE {} histogram\n", name));
            for (upper, count) in histogram.buckets.iter().zip(histogram.counts.iter()) {
                out.push_str(&format!(
                    "{}_bucket{} {}\n",
                    name,
                    render_labels_with(&labels, "le", &format!("{upper}")),
                    count
                ));
            }
            out.push_str(&format!(
                "{}_bucket{} {}\n",
                name,
                render_labels_with(&labels, "le", "+Inf"),
                histogram.count
            ));
            out.push_str(&format!(
                "{}_sum{} {}\n",
                name,
                render_labels(&labels),
                histogram.sum
            ));
            out.push_str(&format!(
                "{}_count{} {}\n",
                name,
                render_labels(&labels),
                histogram.count
            ));
        }
        out
    }
}

fn build_labels(labels: &[&str]) -> Labels {
    labels
        .iter()
        .enumerate()
        .map(|(index, value)| (format!("label{index}"), value.to_string()))
        .collect()
}

fn render_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape(value)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn render_labels_with(labels: &Labels, key: &str, value: &str) -> String {
    let mut items = labels.clone();
    items.push((key.to_string(), value.to_string()));
    render_labels(&items)
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let registry = MetricsRegistry::new();
        registry.inc(
            "audit_task_received_total",
            vec![("project".into(), "1".into())],
        );
        registry.inc(
            "audit_task_received_total",
            vec![("project".into(), "1".into())],
        );
        assert_eq!(
            registry.counter("audit_task_received_total", &[("project", "1")]),
            2.0
        );
    }

    #[test]
    fn prometheus_output_contains_labels() {
        let registry = MetricsRegistry::new();
        registry.set_gauge(
            "audit_queue_backlog",
            vec![("project".into(), "7".into())],
            12.0,
        );
        let text = registry.render_prometheus();
        assert!(text.contains("audit_queue_backlog{project=\"7\"} 12"));
    }
}
