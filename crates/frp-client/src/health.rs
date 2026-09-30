//! Local service health checks, mirroring upstream `client/health/health.go`.
//!
//! The proxy wrapper starts a monitor when `healthCheck.type` is set and
//! `localPort > 0`. A failing check makes the wrapper withdraw its proxy from
//! the server and a recovering check makes it register again, which is why the
//! callbacks here only flip a flag and wake the status worker rather than
//! touching the control connection directly.

use std::time::Duration;

use frp_core::config::proxy::HealthCheckConfig;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Runs checks against one local address until cancelled.
pub struct Monitor {
    check_type: String,
    interval: Duration,
    timeout: Duration,
    max_failed: u64,
    addr: String,
    url: String,
    headers: Vec<(String, String)>,
    status_ok: bool,
    failed_times: u64,
    cancel: CancellationToken,
}

impl Monitor {
    pub fn new(cfg: &HealthCheckConfig, addr: String, cancel: CancellationToken) -> Self {
        let mut cfg = cfg.clone();
        cfg.complete();
        let url = if cfg.check_type == "http" && !cfg.path.is_empty() {
            let mut url = format!("http://{addr}");
            if !cfg.path.starts_with('/') {
                url.push('/');
            }
            url.push_str(&cfg.path);
            url
        } else {
            String::new()
        };
        Self {
            check_type: cfg.check_type.clone(),
            interval: Duration::from_secs(cfg.interval_seconds.max(1) as u64),
            timeout: Duration::from_secs(cfg.timeout_seconds.max(1) as u64),
            max_failed: cfg.max_failed.max(1) as u64,
            addr,
            url,
            headers: cfg
                .http_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            status_ok: false,
            failed_times: 0,
            cancel,
        }
    }

    /// Runs the check loop until cancelled.
    ///
    /// `on_normal` and `on_failed` are called only on a state *change*, so a
    /// service that stays down does not spam the server with registrations.
    pub async fn run<F, G>(mut self, on_normal: F, on_failed: G)
    where
        F: Fn(),
        G: Fn(),
    {
        loop {
            let result = tokio::time::timeout(self.timeout, self.check_once()).await;
            let ok = matches!(result, Ok(Ok(())));
            match result {
                Ok(Ok(())) => {
                    debug!(target = %self.addr, "health check succeeded");
                }
                Ok(Err(e)) => warn!(target = %self.addr, error = %e, "health check failed"),
                Err(_) => warn!(target = %self.addr, "health check timed out"),
            }

            if ok {
                if !self.status_ok {
                    self.status_ok = true;
                    self.failed_times = 0;
                    info!(target = %self.addr, "health check status changed to success");
                    on_normal();
                }
            } else {
                self.failed_times += 1;
                if self.status_ok && self.failed_times >= self.max_failed {
                    self.status_ok = false;
                    warn!(target = %self.addr, "health check status changed to failed");
                    on_failed();
                }
            }

            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep(self.interval) => {}
            }
        }
    }

    async fn check_once(&self) -> Result<(), String> {
        match self.check_type.as_str() {
            "tcp" => self.check_tcp().await,
            "http" => self.check_http().await,
            other => Err(format!("unsupported health check type [{other}]")),
        }
    }

    async fn check_tcp(&self) -> Result<(), String> {
        if self.addr.is_empty() {
            return Ok(());
        }
        TcpStream::connect(&self.addr)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Minimal HTTP/1.1 GET: any 2xx status counts as healthy, matching the
    /// upstream `resp.StatusCode/100 != 2` check.
    async fn check_http(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Ok(());
        }
        let (authority, path) =
            split_url(&self.url).ok_or_else(|| "bad health check url".to_string())?;
        let mut stream = TcpStream::connect(authority)
            .await
            .map_err(|e| e.to_string())?;

        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.host_header(authority)
        );
        for (name, value) in &self.headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;

        let head = String::from_utf8_lossy(&response);
        let status_line = head.lines().next().unwrap_or_default();
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| "malformed HTTP status line".to_string())?;
        if code / 100 == 2 {
            Ok(())
        } else {
            Err(format!("status code {code} is not 2xx"))
        }
    }

    /// Uses an explicit `Host` header when the caller supplied one.
    fn host_header(&self, authority: &str) -> String {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| authority.to_string())
    }
}

fn split_url(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("http://")?;
    match rest.find('/') {
        Some(index) => Some((&rest[..index], &rest[index..])),
        None => Some((rest, "/")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_splitting() {
        assert_eq!(
            split_url("http://127.0.0.1:8080/health"),
            Some(("127.0.0.1:8080", "/health"))
        );
        assert_eq!(
            split_url("http://127.0.0.1:8080"),
            Some(("127.0.0.1:8080", "/"))
        );
        assert_eq!(split_url("ftp://x"), None);
    }

    #[tokio::test]
    async fn tcp_check_detects_a_listening_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let cfg = HealthCheckConfig {
            check_type: "tcp".into(),
            interval_seconds: 1,
            timeout_seconds: 1,
            max_failed: 1,
            ..Default::default()
        };
        let monitor = Monitor::new(&cfg, addr, CancellationToken::new());
        assert!(monitor.check_once().await.is_ok());
    }

    #[tokio::test]
    async fn tcp_check_reports_a_closed_port() {
        // Bind and drop so the port is almost certainly unused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let cfg = HealthCheckConfig {
            check_type: "tcp".into(),
            ..Default::default()
        };
        let monitor = Monitor::new(&cfg, addr, CancellationToken::new());
        assert!(monitor.check_once().await.is_err());
    }

    #[tokio::test]
    async fn http_check_accepts_a_2xx_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let cfg = HealthCheckConfig {
            check_type: "http".into(),
            path: "/healthz".into(),
            ..Default::default()
        };
        let monitor = Monitor::new(&cfg, addr.to_string(), CancellationToken::new());
        assert!(monitor.check_once().await.is_ok());
    }

    #[tokio::test]
    async fn http_check_rejects_a_5xx_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let cfg = HealthCheckConfig {
            check_type: "http".into(),
            path: "/healthz".into(),
            ..Default::default()
        };
        let monitor = Monitor::new(&cfg, addr.to_string(), CancellationToken::new());
        assert!(monitor.check_once().await.is_err());
    }

    #[tokio::test]
    async fn failures_only_fire_the_callback_on_a_state_change() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let cfg = HealthCheckConfig {
            check_type: "tcp".into(),
            interval_seconds: 1,
            timeout_seconds: 1,
            max_failed: 1,
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let monitor = Monitor::new(&cfg, addr, cancel.clone());
        let normal = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));

        let normal_hits = normal.clone();
        let failed_hits = failed.clone();
        let handle = tokio::spawn(async move {
            monitor
                .run(
                    move || {
                        normal_hits.fetch_add(1, Ordering::SeqCst);
                    },
                    move || {
                        failed_hits.fetch_add(1, Ordering::SeqCst);
                    },
                )
                .await;
        });

        // The monitor starts in the "not ok" state, so a failure must not fire
        // the callback; only a recovery followed by a failure would.
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        handle.await.unwrap();
        assert_eq!(normal.load(Ordering::SeqCst), 0);
        assert_eq!(failed.load(Ordering::SeqCst), 0);
    }
}
