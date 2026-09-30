//! `static_file`: serve a local directory over HTTP.
//!
//! Upstream mounts `http.StripPrefix(prefix, http.FileServer(http.Dir(localPath)))`
//! on a gorilla router with `PathPrefix(prefix)` and `Methods("GET")`, behind
//! `NewHTTPAuthMiddleware`. Three consequences of that wiring are reproduced
//! here because they are observable:
//!
//! * only `GET` is routed — gorilla's method matcher compares the method
//!   exactly, so `HEAD` gets the bare `405` a path match with a method mismatch
//!   produces;
//! * `stripPrefix` becomes `"/" + stripPrefix + "/"` (or `"/"`), so the prefix
//!   must be followed by a slash in the request path;
//! * a failure from the auth middleware is Go's `http.Error`, body and headers
//!   included.
//!
//! Deliberately different: upstream wraps the file server in a gzip handler and
//! uses Go's directory-listing markup. Both are response-formatting details
//! rather than protocol, and the README records the difference.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use frp_core::crypto::auth::constant_time_eq;
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ACCEPT_RANGES, AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE,
};
use hyper::{Method, Request, Response, StatusCode};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::bridge::{full_body, Bridge, Handler, RespBody};
use super::{ConnInfo, Plugin};

/// Upper bound on the size of one buffered response.
///
/// Responses are buffered rather than streamed, so this caps how much a single
/// request can pull into memory. A larger file is refused rather than silently
/// truncated.
const MAX_SERVED_BYTES: u64 = 64 * 1024 * 1024;

pub struct StaticFilePlugin {
    cancel: CancellationToken,
    bridge: Arc<Bridge>,
}

impl StaticFilePlugin {
    pub fn new(
        local_path: &str,
        strip_prefix: &str,
        http_user: &str,
        http_password: &str,
    ) -> anyhow::Result<Arc<Self>> {
        let state = HandlerState {
            root: PathBuf::from(local_path),
            prefix: prefix_for(strip_prefix),
            user: http_user.to_string(),
            password: http_password.to_string(),
        };
        let handler: Handler = Arc::new(
            move |req: Request<Incoming>, _peer: Option<SocketAddr>, _sni: Option<String>| {
                let state = state.clone();
                Box::pin(async move { state.serve(req).await })
            },
        );

        let cancel = CancellationToken::new();
        let bridge = Bridge::new(handler, None, false, cancel.clone());
        Ok(Arc::new(Self { cancel, bridge }))
    }
}

impl Plugin for StaticFilePlugin {
    fn name(&self) -> &'static str {
        "static_file"
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let bridge = self.bridge.clone();
        let peer = info.src_addr;
        let conn = info.conn;
        Box::pin(async move { bridge.put_conn(conn, peer) })
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

/// Upstream: `prefix = "/" + stripPrefix + "/"`, or `"/"` when empty.
fn prefix_for(strip_prefix: &str) -> String {
    if strip_prefix.is_empty() {
        "/".to_string()
    } else {
        format!("/{strip_prefix}/")
    }
}

/// Everything the handler needs, cloned once per request.
#[derive(Clone)]
struct HandlerState {
    root: PathBuf,
    prefix: String,
    user: String,
    password: String,
}

impl HandlerState {
    async fn serve(&self, req: Request<Incoming>) -> Response<RespBody> {
        if !self.authorised(&req) {
            return unauthorized();
        }
        // `router.Methods("GET")` matches exactly GET, so HEAD is a 405 too.
        if req.method() != Method::GET {
            return status_only(StatusCode::METHOD_NOT_ALLOWED);
        }

        let path = req.uri().path().to_string();
        // `http.serveFile` refuses any path containing a ".." element outright.
        if path.split('/').any(|segment| segment == "..") {
            return http_error(StatusCode::BAD_REQUEST, "invalid URL path");
        }

        let relative = path.strip_prefix(self.prefix.as_str()).unwrap_or("");
        let Some(target) = self.resolve(relative) else {
            return status_only(StatusCode::FORBIDDEN);
        };

        let meta = match fs::metadata(&target).await {
            Ok(meta) => meta,
            Err(e) => {
                debug!(path = %target.display(), error = %e, "static file lookup failed");
                return not_found();
            }
        };

        if meta.is_dir() {
            let index = target.join("index.html");
            if let Ok(index_meta) = fs::metadata(&index).await {
                if index_meta.is_file() {
                    return self
                        .serve_file(&index, index_meta.len(), range_header(&req))
                        .await;
                }
            }
            return directory_listing(&target, &path).await;
        }
        if !meta.is_file() {
            return not_found();
        }
        self.serve_file(&target, meta.len(), range_header(&req)).await
    }

    /// Applies the optional basic auth, comparing in constant time like
    /// upstream's `util.ConstantTimeEqString`.
    fn authorised(&self, req: &Request<Incoming>) -> bool {
        if self.user.is_empty() && self.password.is_empty() {
            return true;
        }
        let Some(value) = req.headers().get(AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(encoded) = value.strip_prefix("Basic ") else {
            return false;
        };
        use base64::Engine as _;
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = decoded.split_once(':') else {
            return false;
        };
        constant_time_eq(&self.user, user) && constant_time_eq(&self.password, password)
    }

    /// Maps the route-relative path under the root.
    ///
    /// Segments of `..` were refused by the caller, so the path cannot climb
    /// out; the `starts_with` check still catches a segment that carries a
    /// Windows drive prefix, which makes `Path::push` replace the whole path.
    fn resolve(&self, relative: &str) -> Option<PathBuf> {
        let mut out = self.root.clone();
        for segment in relative.split('/') {
            match segment {
                "" | "." => continue,
                ".." => return None,
                other => out.push(other),
            }
        }
        out.starts_with(&self.root).then_some(out)
    }

    async fn serve_file(
        &self,
        path: &Path,
        size: u64,
        range: Option<RangeSpec>,
    ) -> Response<RespBody> {
        let (status, start, end) = match range {
            None | Some(RangeSpec::Unsupported) => {
                (StatusCode::OK, 0, size.saturating_sub(1))
            }
            Some(spec) => match spec.resolve(size) {
                Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end),
                None => return range_not_satisfiable(size),
            },
        };
        let body_len = if size == 0 { 0 } else { end - start + 1 };
        if body_len > MAX_SERVED_BYTES {
            debug!(path = %path.display(), size = body_len, "static file is too large to buffer");
            return status_only(StatusCode::INTERNAL_SERVER_ERROR);
        }

        let mut file = match fs::File::open(path).await {
            Ok(file) => file,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "cannot open the static file");
                return not_found();
            }
        };
        if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return status_only(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let mut buf = Vec::with_capacity(body_len as usize);
        if file.take(body_len).read_to_end(&mut buf).await.is_err() {
            return status_only(StatusCode::INTERNAL_SERVER_ERROR);
        }

        let mut builder = Response::builder()
            .status(status)
            .header(ACCEPT_RANGES, "bytes")
            .header(CONTENT_TYPE, content_type_for(path))
            .header(CONTENT_LENGTH, body_len.to_string());
        if status == StatusCode::PARTIAL_CONTENT {
            builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
        }
        builder
            .body(full_body(buf))
            .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
    }
}

/// A byte range from a `Range` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeSpec {
    /// `bytes=10-19`, or `bytes=10-` for an open-ended range.
    FromTo { first: u64, last: Option<u64> },
    /// `bytes=-500`: the final 500 bytes.
    Suffix { len: u64 },
    /// A range this server does not implement, such as a multi-range request.
    /// The whole entity is the fallback, which the specification allows.
    Unsupported,
}

impl RangeSpec {
    /// Clamps the range to the entity, or `None` when it cannot be satisfied,
    /// which is a 416 rather than a fallback.
    fn resolve(self, size: u64) -> Option<(u64, u64)> {
        match self {
            RangeSpec::FromTo { first, last } => {
                if first >= size {
                    return None;
                }
                let end = last.unwrap_or(size - 1).min(size - 1);
                (first <= end).then_some((first, end))
            }
            RangeSpec::Suffix { len } => {
                if len == 0 || size == 0 {
                    return None;
                }
                Some((size.saturating_sub(len), size - 1))
            }
            RangeSpec::Unsupported => None,
        }
    }
}

/// Parses a single `bytes=` range.
fn range_header(req: &Request<Incoming>) -> Option<RangeSpec> {
    let raw = req.headers().get(RANGE)?.to_str().ok()?.trim();
    let spec = raw.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return Some(RangeSpec::Unsupported);
    }
    let (first, last) = spec.split_once('-')?;
    if first.trim().is_empty() {
        let len: u64 = last.trim().parse().ok()?;
        return Some(RangeSpec::Suffix { len });
    }
    let first: u64 = first.trim().parse().ok()?;
    let last = if last.trim().is_empty() {
        None
    } else {
        Some(last.trim().parse().ok()?)
    };
    Some(RangeSpec::FromTo { first, last })
}

async fn directory_listing(dir: &Path, request_path: &str) -> Response<RespBody> {
    let mut entries = match fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(_) => return not_found(),
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry
            .file_type()
            .await
            .map(|kind| kind.is_dir())
            .unwrap_or(false);
        names.push((name, is_dir));
    }
    names.sort();

    let shown = if request_path.ends_with('/') {
        request_path.to_string()
    } else {
        format!("{request_path}/")
    };
    let mut html = String::from(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Directory listing</title>\n</head>\n<body>\n",
    );
    html.push_str(&format!(
        "<h1>Directory listing for {}</h1>\n<hr>\n<ul>\n",
        escape(&shown)
    ));
    for (name, is_dir) in names {
        let suffix = if is_dir { "/" } else { "" };
        html.push_str(&format!(
            "<li><a href=\"{}{}\">{}{}</a></li>\n",
            url_encode(&name),
            suffix,
            escape(&name),
            suffix
        ));
    }
    html.push_str("</ul>\n<hr>\n</body>\n</html>\n");

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(html))
        .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
}

fn content_type_for(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" | "md" | "log" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn status_only(status: StatusCode) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .body(full_body(""))
        .unwrap_or_else(|_| Response::new(full_body("")))
}

/// Reproduces Go's `http.Error`.
fn http_error(status: StatusCode, message: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(full_body(format!("{message}\n")))
        .unwrap_or_else(|_| status_only(status))
}

fn unauthorized() -> Response<RespBody> {
    let mut response = http_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    response.headers_mut().insert(
        "www-authenticate",
        HeaderValue::from_static("Basic realm=\"Restricted\""),
    );
    response
}

fn not_found() -> Response<RespBody> {
    http_error(StatusCode::NOT_FOUND, "404 page not found")
}

fn range_not_satisfiable(size: u64) -> Response<RespBody> {
    let mut response = status_only(StatusCode::RANGE_NOT_SATISFIABLE);
    response.headers_mut().insert(
        CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{size}"))
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(root: &str) -> HandlerState {
        HandlerState {
            root: PathBuf::from(root),
            prefix: "/".into(),
            user: String::new(),
            password: String::new(),
        }
    }

    #[test]
    fn the_prefix_follows_the_upstream_rule() {
        // `stripPrefix = ""` mounts at "/", so nothing is stripped.
        assert_eq!(prefix_for(""), "/");
        // Anything else gains a leading and a trailing slash.
        assert_eq!(prefix_for("static"), "/static/");
    }

    #[test]
    fn resolve_maps_paths_and_rejects_traversal() {
        let state = state("/srv/www");
        assert_eq!(
            state.resolve("a/b.txt"),
            Some(PathBuf::from("/srv/www/a/b.txt"))
        );
        assert_eq!(state.resolve(""), Some(PathBuf::from("/srv/www")));
        assert_eq!(state.resolve("."), Some(PathBuf::from("/srv/www")));
        assert_eq!(state.resolve("../etc/passwd"), None);
        assert_eq!(state.resolve("a/../../etc/passwd"), None);
    }

    #[test]
    fn content_types_cover_the_common_web_assets() {
        assert_eq!(
            content_type_for(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("a.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(content_type_for(Path::new("a.PNG")), "image/png");
        assert_eq!(content_type_for(Path::new("a.woff2")), "font/woff2");
        assert_eq!(
            content_type_for(Path::new("a.unknown")),
            "application/octet-stream"
        );
    }

    #[test]
    fn a_single_range_is_clamped_to_the_entity() {
        let spec = RangeSpec::FromTo {
            first: 10,
            last: Some(19),
        };
        assert_eq!(spec.resolve(100), Some((10, 19)));

        // A last byte past the end is clamped.
        let spec = RangeSpec::FromTo {
            first: 90,
            last: Some(1000),
        };
        assert_eq!(spec.resolve(100), Some((90, 99)));

        // An open-ended range runs to the end.
        let spec = RangeSpec::FromTo {
            first: 95,
            last: None,
        };
        assert_eq!(spec.resolve(100), Some((95, 99)));
    }

    #[test]
    fn a_suffix_range_counts_back_from_the_end() {
        let spec = RangeSpec::Suffix { len: 10 };
        assert_eq!(spec.resolve(100), Some((90, 99)));
        // A suffix longer than the entity is the whole entity.
        let spec = RangeSpec::Suffix { len: 500 };
        assert_eq!(spec.resolve(100), Some((0, 99)));
        // `bytes=-0` is not satisfiable.
        assert_eq!(RangeSpec::Suffix { len: 0 }.resolve(100), None);
    }

    #[test]
    fn an_unsatisfiable_range_is_detected() {
        let spec = RangeSpec::FromTo {
            first: 100,
            last: None,
        };
        assert_eq!(spec.resolve(100), None);
        // A start beyond the end is unsatisfiable even with an explicit end.
        let spec = RangeSpec::FromTo {
            first: 200,
            last: Some(300),
        };
        assert_eq!(spec.resolve(100), None);
    }

    #[test]
    fn a_multi_range_request_falls_back_to_the_whole_entity() {
        // `Unsupported` is not an error: the caller returns 200.
        assert_eq!(RangeSpec::Unsupported.resolve(100), None);
    }

    #[test]
    fn escapes_and_encodes_listing_entries() {
        assert_eq!(escape("<a&b>"), "&lt;a&amp;b&gt;");
        assert_eq!(url_encode("a b/c"), "a%20b%2Fc");
    }
}
