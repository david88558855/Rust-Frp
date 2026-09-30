//! In-memory server metrics, exposed through the dashboard and Prometheus.
//!
//! Upstream frps keeps seven days of samples for the dashboard charts. Rust-Frp
//! keeps the same counters but only the current snapshot plus a bounded history
//! of traffic samples, which is what the dashboard charts actually render.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum number of traffic samples kept (one per minute, i.e. ~24h).
const MAX_TRAFFIC_SAMPLES: usize = 24 * 60;
/// Retention window in hours, mirroring `natholeAnalysisDataReserveHours`-style
/// housekeeping for the dashboard.
const RETENTION_HOURS: i64 = 24;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Per proxy counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStat {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub user: String,
    pub client_id: String,
    pub cur_conns: i64,
    pub today_traffic_in: i64,
    pub today_traffic_out: i64,
    pub last_start_time: i64,
    pub last_close_time: i64,
}

/// Per client counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStat {
    pub client_id: String,
    pub user: String,
    pub version: String,
    pub hostname: String,
    pub online: bool,
    pub last_online_time: i64,
}

/// A single traffic sample for the dashboard chart.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TrafficSample {
    pub at: i64,
    pub traffic_in: i64,
    pub traffic_out: i64,
}

#[derive(Debug, Default)]
struct Inner {
    clients: HashMap<String, ClientStat>,
    proxies: HashMap<String, ProxyStat>,
    samples: Vec<TrafficSample>,
}

/// Shared metrics registry.
#[derive(Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
    pub traffic_in: AtomicI64,
    pub traffic_out: AtomicI64,
    pub conn_counts: AtomicI64,
    pub cur_conns: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_client(&self, client: ClientStat) {
        let mut inner = self.inner.lock().unwrap();
        inner.clients.insert(client.client_id.clone(), client);
    }

    pub fn close_client(&self, client_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(c) = inner.clients.get_mut(client_id) {
            c.online = false;
        }
    }

    pub fn new_proxy(&self, stat: ProxyStat) {
        let mut inner = self.inner.lock().unwrap();
        inner.proxies.insert(stat.name.clone(), stat);
    }

    pub fn close_proxy(&self, name: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.proxies.get_mut(name) {
            p.cur_conns = 0;
            p.last_close_time = now_secs();
        }
    }

    pub fn open_connection(&self, name: &str) {
        self.cur_conns.fetch_add(1, Ordering::Relaxed);
        self.conn_counts.fetch_add(1, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.proxies.get_mut(name) {
            p.cur_conns += 1;
        }
    }

    pub fn close_connection(&self, name: &str) {
        self.cur_conns.fetch_sub(1, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.proxies.get_mut(name) {
            p.cur_conns -= 1;
        }
    }

    pub fn add_traffic_in(&self, name: &str, bytes: i64) {
        self.traffic_in.fetch_add(bytes, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.proxies.get_mut(name) {
            p.today_traffic_in += bytes;
        }
    }

    pub fn add_traffic_out(&self, name: &str, bytes: i64) {
        self.traffic_out.fetch_add(bytes, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.proxies.get_mut(name) {
            p.today_traffic_out += bytes;
        }
    }

    /// Records a traffic sample, replacing the sample for the current minute.
    pub fn sample_traffic(&self) {
        let now = now_secs();
        let traffic_in = self.traffic_in.load(Ordering::Relaxed);
        let traffic_out = self.traffic_out.load(Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        if let Some(last) = inner.samples.last_mut() {
            if now - last.at < 60 {
                last.traffic_in = traffic_in;
                last.traffic_out = traffic_out;
                return;
            }
        }
        inner.samples.push(TrafficSample {
            at: now,
            traffic_in,
            traffic_out,
        });
        let cutoff = now - RETENTION_HOURS * 3600;
        inner.samples.retain(|s| s.at >= cutoff);
        if inner.samples.len() > MAX_TRAFFIC_SAMPLES {
            let excess = inner.samples.len() - MAX_TRAFFIC_SAMPLES;
            inner.samples.drain(..excess);
        }
    }

    /// Snapshot of clients, proxies and samples.
    pub fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock().unwrap();
        Snapshot {
            clients: inner.clients.values().cloned().collect(),
            proxies: inner.proxies.values().cloned().collect(),
            samples: inner.samples.clone(),
            total_traffic_in: self.traffic_in.load(Ordering::Relaxed),
            total_traffic_out: self.traffic_out.load(Ordering::Relaxed),
            cur_conns: self.cur_conns.load(Ordering::Relaxed),
            conn_counts: self.conn_counts.load(Ordering::Relaxed),
        }
    }

    /// Prometheus text exposition, matching the metric names upstream frps uses
    /// where the underlying counter exists in this implementation.
    pub fn render_prometheus(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP frp_server_client_counts Number of online clients.\n");
        out.push_str("# TYPE frp_server_client_counts gauge\n");
        let online = snap.clients.iter().filter(|c| c.online).count();
        out.push_str(&format!("frp_server_client_counts {online}\n"));

        out.push_str("# HELP frp_server_proxy_counts Number of active proxies.\n");
        out.push_str("# TYPE frp_server_proxy_counts gauge\n");
        out.push_str(&format!("frp_server_proxy_counts {}\n", snap.proxies.len()));

        out.push_str("# HELP frp_server_cur_conns Current connections.\n");
        out.push_str("# TYPE frp_server_cur_conns gauge\n");
        out.push_str(&format!("frp_server_cur_conns {}\n", snap.cur_conns));

        out.push_str("# HELP frp_server_conn_counts Total connections.\n");
        out.push_str("# TYPE frp_server_conn_counts counter\n");
        out.push_str(&format!("frp_server_conn_counts {}\n", snap.conn_counts));

        out.push_str("# HELP frp_server_traffic_in Bytes received in total.\n");
        out.push_str("# TYPE frp_server_traffic_in counter\n");
        out.push_str(&format!(
            "frp_server_traffic_in {}\n",
            snap.total_traffic_in
        ));

        out.push_str("# HELP frp_server_traffic_out Bytes sent in total.\n");
        out.push_str("# TYPE frp_server_traffic_out counter\n");
        out.push_str(&format!(
            "frp_server_traffic_out {}\n",
            snap.total_traffic_out
        ));

        out.push_str("# HELP frp_server_proxy_status Proxy status, 1 for online.\n");
        out.push_str("# TYPE frp_server_proxy_status gauge\n");
        for p in &snap.proxies {
            out.push_str(&format!(
                "frp_server_proxy_status{{name=\"{}\",type=\"{}\",client_id=\"{}\"}} 1\n",
                escape(&p.name),
                escape(&p.proxy_type),
                escape(&p.client_id)
            ));
        }

        out.push_str("# HELP frp_server_proxy_cur_conns Current connections per proxy.\n");
        out.push_str("# TYPE frp_server_proxy_cur_conns gauge\n");
        for p in &snap.proxies {
            out.push_str(&format!(
                "frp_server_proxy_cur_conns{{name=\"{}\",type=\"{}\"}} {}\n",
                escape(&p.name),
                escape(&p.proxy_type),
                p.cur_conns
            ));
        }

        out.push_str("# HELP frp_server_proxy_traffic_in Bytes received per proxy.\n");
        out.push_str("# TYPE frp_server_proxy_traffic_in counter\n");
        for p in &snap.proxies {
            out.push_str(&format!(
                "frp_server_proxy_traffic_in{{name=\"{}\",type=\"{}\"}} {}\n",
                escape(&p.name),
                escape(&p.proxy_type),
                p.today_traffic_in
            ));
        }

        out.push_str("# HELP frp_server_proxy_traffic_out Bytes sent per proxy.\n");
        out.push_str("# TYPE frp_server_proxy_traffic_out counter\n");
        for p in &snap.proxies {
            out.push_str(&format!(
                "frp_server_proxy_traffic_out{{name=\"{}\",type=\"{}\"}} {}\n",
                escape(&p.name),
                escape(&p.proxy_type),
                p.today_traffic_out
            ));
        }

        out
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Immutable view of the metrics registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub clients: Vec<ClientStat>,
    pub proxies: Vec<ProxyStat>,
    pub samples: Vec<TrafficSample>,
    pub total_traffic_in: i64,
    pub total_traffic_out: i64,
    pub cur_conns: i64,
    pub conn_counts: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(name: &str) -> ProxyStat {
        ProxyStat {
            name: name.to_string(),
            proxy_type: "tcp".into(),
            user: "u".into(),
            client_id: "c".into(),
            last_start_time: now_secs(),
            ..Default::default()
        }
    }

    #[test]
    fn counters_track_connections_and_traffic() {
        let m = Metrics::new();
        m.new_proxy(proxy("p1"));

        m.open_connection("p1");
        m.open_connection("p1");
        m.add_traffic_in("p1", 100);
        m.add_traffic_out("p1", 200);
        m.close_connection("p1");

        let snap = m.snapshot();
        assert_eq!(snap.cur_conns, 1);
        assert_eq!(snap.conn_counts, 2);
        assert_eq!(snap.total_traffic_in, 100);
        assert_eq!(snap.total_traffic_out, 200);
        let p = snap.proxies.iter().find(|p| p.name == "p1").unwrap();
        assert_eq!(p.cur_conns, 1);
    }

    #[test]
    fn client_lifecycle() {
        let m = Metrics::new();
        m.new_client(ClientStat {
            client_id: "c1".into(),
            user: "u".into(),
            online: true,
            ..Default::default()
        });
        assert_eq!(m.snapshot().clients.len(), 1);
        m.close_client("c1");
        assert!(!m.snapshot().clients[0].online);
    }

    #[test]
    fn prometheus_output_shape() {
        let m = Metrics::new();
        m.new_proxy(proxy("p1"));
        m.new_client(ClientStat {
            client_id: "c1".into(),
            online: true,
            ..Default::default()
        });
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE frp_server_client_counts gauge"));
        assert!(text.contains("frp_server_client_counts 1"));
        assert!(
            text.contains("frp_server_proxy_status{name=\"p1\",type=\"tcp\",client_id=\"c\"} 1")
        );
    }

    #[test]
    fn traffic_samples_are_bounded() {
        let m = Metrics::new();
        for _ in 0..10 {
            m.sample_traffic();
        }
        // Repeated calls within the same minute collapse into one sample.
        assert_eq!(m.snapshot().samples.len(), 1);
    }
}
