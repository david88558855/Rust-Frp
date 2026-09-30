//! A yamux implementation that is wire compatible with `hashicorp/yamux`.
//!
//! frp enables stream multiplexing by default (`transport.tcpMux`), so both
//! peers wrap the control connection in a yamux session: frpc is the client and
//! frps the server. Without this module the Rust implementation could only
//! interoperate with upstream when `tcpMux` was turned off on both sides.
//!
//! Frame layout, the stream identifier rules (odd for the client, even for the
//! server), the flag state machine and the receive window accounting are
//! reproduced from the Go sources: a twelve byte header of
//! `version:u8 || type:u8 || flags:u16 || stream_id:u32 || length:u32`, every
//! integer big endian.
//!
//! Two details are easy to get wrong and are called out where they matter:
//!
//! * Opening a stream *is* a window update frame carrying `SYN`, and its
//!   `length` field is the window delta rather than a payload size.
//! * Both sides start their receive window at 256 KiB while
//!   `max_stream_window_size` may be larger, so the first window update a
//!   stream ever emits is what lifts the peer's send window to the configured
//!   size. Upstream computes the delta against the *unread* buffer length, and
//!   so does this implementation.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch, Notify};

/// Size of the fixed yamux frame header.
pub const HEADER_SIZE: usize = 12;

/// The only protocol version yamux defines.
const PROTO_VERSION: u8 = 0;

/// Frame types, in the order upstream declares them.
pub mod frame_type {
    pub const DATA: u8 = 0;
    pub const WINDOW_UPDATE: u8 = 1;
    pub const PING: u8 = 2;
    pub const GO_AWAY: u8 = 3;
}

/// Frame flags.
pub mod frame_flags {
    pub const SYN: u16 = 1;
    pub const ACK: u16 = 2;
    pub const FIN: u16 = 4;
    pub const RST: u16 = 8;
}

/// Go away reason codes.
const GO_AWAY_NORMAL: u32 = 0;

/// Every stream starts with this window on both directions, regardless of the
/// configured maximum.
pub const INITIAL_STREAM_WINDOW: u32 = 256 * 1024;

/// Which side of the session this endpoint is. It only decides the parity of
/// the stream identifiers it allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    fn first_stream_id(self) -> u32 {
        match self {
            Mode::Client => 1,
            Mode::Server => 2,
        }
    }
}

/// Tuning knobs mirroring `yamux.Config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// How many accepted streams may sit unclaimed before the peer is reset.
    pub accept_backlog: usize,
    pub enable_keepalive: bool,
    pub keepalive_interval: Duration,
    /// The window a stream is allowed to grow to once it reports progress.
    pub max_stream_window_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            accept_backlog: 256,
            enable_keepalive: true,
            keepalive_interval: Duration::from_secs(30),
            max_stream_window_size: INITIAL_STREAM_WINDOW,
        }
    }
}

impl Config {
    /// The configuration frp applies when building its yamux session.
    pub fn for_frp(keepalive_interval: Duration) -> Self {
        Self {
            keepalive_interval,
            max_stream_window_size: 6 * 1024 * 1024,
            ..Self::default()
        }
    }
}

/// Lifecycle of a single stream, mirroring upstream `streamState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    SynSent,
    SynReceived,
    Established,
    LocalClose,
    RemoteClose,
    Closed,
    Reset,
}

/// A frame queued for the session writer.
struct Outgoing {
    header: [u8; HEADER_SIZE],
    body: Vec<u8>,
}

/// Per-stream receive buffer plus the window still advertised to the peer.
struct Recv {
    buf: VecDeque<u8>,
    window: u32,
}

/// Where a parked reader or writer waits.
#[derive(Default)]
struct WakerSlot(Mutex<Option<Waker>>);

impl WakerSlot {
    fn register(&self, cx: &mut Context<'_>) {
        let waker = cx.waker().clone();
        let mut slot = self.0.lock().unwrap();
        match slot.as_mut() {
            Some(existing) if existing.will_wake(&waker) => {}
            _ => *slot = Some(waker),
        }
    }

    fn wake(&self) {
        // Take the waker out inside a block so the mutex guard is released
        // before `wake` runs; `wake` may re-enter the stream.
        let taken = { self.0.lock().unwrap().take() };
        if let Some(waker) = taken {
            waker.wake();
        }
    }
}

/// State shared by the session and every stream it owns.
struct Shared {
    streams: Mutex<HashMap<u32, Arc<StreamInner>>>,
    next_stream_id: AtomicU32,
    max_window: u32,
    out: mpsc::UnboundedSender<Outgoing>,
    accept_tx: mpsc::UnboundedSender<Arc<StreamInner>>,
    accept_backlog: usize,
    accept_backlog_count: AtomicUsize,
    /// Streams opened locally that the peer has not acknowledged yet.
    inflight: Mutex<HashMap<u32, ()>>,
    inflight_notify: Notify,
    pings: Mutex<HashMap<u32, oneshot::Sender<()>>>,
    next_ping_id: AtomicU32,
    remote_go_away: AtomicBool,
    local_go_away: AtomicBool,
    closed: AtomicBool,
    closed_tx: watch::Sender<bool>,
}

impl Shared {
    fn send_frame(&self, header: [u8; HEADER_SIZE], body: Vec<u8>) {
        let _ = self.out.send(Outgoing { header, body });
    }

    fn send_control(&self, ftype: u8, flags: u16, stream_id: u32, length: u32) {
        let header = encode_header(ftype, flags, stream_id, length);
        self.send_frame(header, Vec::new());
    }

    fn remove_stream(&self, id: u32) {
        let _ = self.streams.lock().unwrap().remove(&id);
        let was_inflight = { self.inflight.lock().unwrap().remove(&id).is_some() };
        if was_inflight {
            self.inflight_notify.notify_one();
        }
    }

    fn establish_stream(&self, id: u32) {
        let was_inflight = { self.inflight.lock().unwrap().remove(&id).is_some() };
        if was_inflight {
            self.inflight_notify.notify_one();
        }
    }

    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.local_go_away.store(true, Ordering::SeqCst);
        let _ = self.closed_tx.send(true);
        self.inflight_notify.notify_waiters();

        let drained: Vec<Arc<StreamInner>> = {
            let mut streams = self.streams.lock().unwrap();
            streams.drain().map(|(_, v)| v).collect()
        };
        for stream in drained {
            stream.force_close();
        }
        let pings: Vec<oneshot::Sender<()>> = {
            let mut pings = self.pings.lock().unwrap();
            pings.drain().map(|(_, v)| v).collect()
        };
        // Dropping the senders makes every pending `ping` return an error.
        drop(pings);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// One multiplexed stream.
struct StreamInner {
    id: u32,
    shared: Arc<Shared>,
    state: Mutex<State>,
    recv: Mutex<Recv>,
    send_window: AtomicU32,
    read_waker: WakerSlot,
    write_waker: WakerSlot,
}

impl StreamInner {
    fn new(id: u32, state: State, shared: Arc<Shared>) -> Self {
        Self {
            id,
            shared,
            state: Mutex::new(state),
            recv: Mutex::new(Recv {
                buf: VecDeque::new(),
                window: INITIAL_STREAM_WINDOW,
            }),
            send_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            read_waker: WakerSlot::default(),
            write_waker: WakerSlot::default(),
        }
    }

    fn state(&self) -> State {
        *self.state.lock().unwrap()
    }

    fn force_close(&self) {
        {
            let mut state = self.state.lock().unwrap();
            *state = State::Closed;
        }
        self.read_waker.wake();
        self.write_waker.wake();
    }

    /// Consumes the pending `SYN`/`ACK` this stream owes the peer.
    fn take_send_flags(&self) -> u16 {
        let mut state = self.state.lock().unwrap();
        match *state {
            State::Init => {
                *state = State::SynSent;
                frame_flags::SYN
            }
            State::SynReceived => {
                *state = State::Established;
                frame_flags::ACK
            }
            _ => 0,
        }
    }

    /// The window update that also announces a locally opened stream.
    fn open_window_update(&self) {
        let max = self.shared.max_window;
        let delta = {
            let mut recv = self.recv.lock().unwrap();
            let delta = max.saturating_sub(recv.window);
            recv.window = recv.window.saturating_add(delta);
            delta
        };
        let flags = self.take_send_flags();
        self.shared
            .send_control(frame_type::WINDOW_UPDATE, flags, self.id, delta);
    }

    /// Advertises freed receive window, skipping the frame when less than half
    /// the window has become available unless a flag still has to go out.
    fn send_window_update(&self) {
        let max = self.shared.max_window;
        let flags = self.take_send_flags();

        let delta = {
            let recv = self.recv.lock().unwrap();
            let buffered = recv.buf.len() as u32;
            max.saturating_sub(buffered).saturating_sub(recv.window)
        };
        if delta < max / 2 && flags == 0 {
            return;
        }
        {
            let mut recv = self.recv.lock().unwrap();
            recv.window = recv.window.saturating_add(delta);
        }
        self.shared
            .send_control(frame_type::WINDOW_UPDATE, flags, self.id, delta);
    }

    fn close(&self) {
        let (send_fin, remove) = {
            let mut state = self.state.lock().unwrap();
            match *state {
                State::Init | State::SynSent | State::SynReceived | State::Established => {
                    *state = State::LocalClose;
                    (true, false)
                }
                State::RemoteClose => {
                    *state = State::Closed;
                    (true, true)
                }
                State::LocalClose | State::Closed | State::Reset => (false, false),
            }
        };
        if remove {
            self.shared.remove_stream(self.id);
        }
        if send_fin {
            self.shared
                .send_control(frame_type::WINDOW_UPDATE, frame_flags::FIN, self.id, 0);
        }
        self.read_waker.wake();
        self.write_waker.wake();
    }

    fn process_flags(&self, flags: u16) -> Result<(), ()> {
        let mut remove = false;
        {
            let mut state = self.state.lock().unwrap();
            if flags & frame_flags::ACK != 0 && *state == State::SynSent {
                *state = State::Established;
            }
            if flags & frame_flags::FIN != 0 {
                match *state {
                    State::SynSent | State::SynReceived | State::Established => {
                        *state = State::RemoteClose;
                    }
                    State::LocalClose => {
                        *state = State::Closed;
                        remove = true;
                    }
                    _ => return Err(()),
                }
            }
            if flags & frame_flags::RST != 0 {
                *state = State::Reset;
                remove = true;
            }
        }
        if flags & frame_flags::ACK != 0 {
            self.shared.establish_stream(self.id);
        }
        if remove {
            self.shared.remove_stream(self.id);
        }
        self.read_waker.wake();
        self.write_waker.wake();
        Ok(())
    }

    fn buffer_data(&self, mut body: Vec<u8>) -> Result<(), ()> {
        {
            let mut recv = self.recv.lock().unwrap();
            if body.len() as u32 > recv.window {
                return Err(());
            }
            recv.window -= body.len() as u32;
            recv.buf.extend(body.drain(..));
        }
        self.read_waker.wake();
        Ok(())
    }

    fn wake_write(&self) {
        self.write_waker.wake();
    }
}

/// A single logical stream inside a [`Session`].
///
/// Dropping the handle closes the stream, mirroring the explicit `Close` call
/// upstream expects from its callers.
pub struct Stream {
    inner: Arc<StreamInner>,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.inner.id
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = &self.inner;
        loop {
            match inner.state() {
                State::Reset => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "yamux stream reset by peer",
                    )))
                }
                State::RemoteClose | State::Closed => {
                    let empty = { inner.recv.lock().unwrap().buf.is_empty() };
                    if empty {
                        // Nothing left to hand out: a short read signals EOF.
                        return Poll::Ready(Ok(()));
                    }
                }
                _ => {}
            }

            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let drained = {
                let mut recv = inner.recv.lock().unwrap();
                if recv.buf.is_empty() {
                    None
                } else {
                    let n = recv.buf.len().min(buf.remaining());
                    recv.buf.make_contiguous();
                    buf.put_slice(&recv.buf.as_slices().0[..n]);
                    drop(recv.buf.drain(..n));
                    Some(n)
                }
            };
            if drained.is_some() {
                inner.send_window_update();
                return Poll::Ready(Ok(()));
            }

            inner.read_waker.register(cx);

            // Re-check after registering so a wakeup that landed between the
            // first check and the registration is not lost.
            let recheck = inner.recv.lock().unwrap().buf.is_empty();
            match inner.state() {
                State::Reset => continue,
                State::RemoteClose | State::Closed => continue,
                _ if !recheck => continue,
                _ => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let inner = &self.inner;
        loop {
            match inner.state() {
                State::Reset => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "yamux stream reset by peer",
                    )))
                }
                State::Closed | State::LocalClose => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "yamux stream closed",
                    )))
                }
                _ => {}
            }

            let window = inner.send_window.load(Ordering::SeqCst);
            if window == 0 {
                inner.write_waker.register(cx);
                match inner.state() {
                    State::Reset | State::Closed | State::LocalClose => continue,
                    _ => {}
                }
                if inner.send_window.load(Ordering::SeqCst) == 0 {
                    return Poll::Pending;
                }
                continue;
            }

            let n = (window as usize).min(buf.len());
            let flags = inner.take_send_flags();
            inner.shared.send_frame(
                encode_header(frame_type::DATA, flags, inner.id, n as u32),
                buf[..n].to_vec(),
            );
            inner.send_window.fetch_sub(n as u32, Ordering::SeqCst);
            return Poll::Ready(Ok(n));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.close();
        Poll::Ready(Ok(()))
    }
}

/// A multiplexed session over one underlying byte stream.
pub struct Session {
    shared: Arc<Shared>,
    accept_rx: mpsc::UnboundedReceiver<Arc<StreamInner>>,
    closed_rx: watch::Receiver<bool>,
}

impl Session {
    /// Starts a session. The caller must be inside a Tokio runtime: the reader,
    /// writer and keepalive drivers are spawned here.
    pub fn new<S>(stream: S, mode: Mode, config: Config) -> Session
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (closed_tx, closed_rx) = watch::channel(false);

        let shared = Arc::new(Shared {
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(mode.first_stream_id()),
            max_window: config.max_stream_window_size.max(INITIAL_STREAM_WINDOW),
            out: out_tx,
            accept_tx,
            accept_backlog: config.accept_backlog.max(1),
            accept_backlog_count: AtomicUsize::new(0),
            inflight: Mutex::new(HashMap::new()),
            inflight_notify: Notify::new(),
            pings: Mutex::new(HashMap::new()),
            next_ping_id: AtomicU32::new(0),
            remote_go_away: AtomicBool::new(false),
            local_go_away: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            closed_tx,
        });

        tokio::spawn(write_loop(write_half, out_rx, shared.clone()));
        tokio::spawn(read_loop(read_half, shared.clone()));
        if config.enable_keepalive {
            tokio::spawn(keepalive_loop(shared.clone(), config.keepalive_interval));
        }

        Session {
            shared,
            accept_rx,
            closed_rx,
        }
    }

    /// Opens a new outbound stream.
    pub async fn open(&self) -> io::Result<Stream> {
        loop {
            if self.shared.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "yamux session is closed",
                ));
            }
            if self.shared.remote_go_away.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "yamux peer is not accepting new streams",
                ));
            }
            let inflight = { self.shared.inflight.lock().unwrap().len() };
            if inflight < self.shared.accept_backlog {
                break;
            }
            // Wait for a SYN to be acknowledged or a stream to be reclaimed.
            self.shared.inflight_notify.notified().await;
        }

        let id = self.shared.next_stream_id.fetch_add(2, Ordering::SeqCst);
        if id >= u32::MAX - 1 {
            return Err(io::Error::other("yamux streams exhausted"));
        }
        let inner = Arc::new(StreamInner::new(id, State::Init, self.shared.clone()));
        {
            let mut streams = self.shared.streams.lock().unwrap();
            streams.insert(id, inner.clone());
        }
        {
            let mut inflight = self.shared.inflight.lock().unwrap();
            inflight.insert(id, ());
        }
        inner.open_window_update();
        Ok(Stream { inner })
    }

    /// Waits for the peer to open a stream, or `None` once the session ends.
    pub async fn accept(&mut self) -> Option<Stream> {
        let closed = *self.closed_rx.borrow();
        if closed {
            return None;
        }
        // Drain whatever the reader already queued before parking.
        match self.accept_rx.try_recv() {
            Ok(inner) => return Some(self.claim(inner)),
            Err(mpsc::error::TryRecvError::Disconnected) => return None,
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        // `changed()` is version based, so a close that landed between the
        // check above and this await still completes immediately.
        tokio::select! {
            biased;
            received = self.accept_rx.recv() => match received {
                Some(inner) => Some(self.claim(inner)),
                None => None,
            },
            _ = self.closed_rx.changed() => None,
        }
    }

    fn claim(&self, inner: Arc<StreamInner>) -> Stream {
        self.shared
            .accept_backlog_count
            .fetch_sub(1, Ordering::SeqCst);
        Stream { inner }
    }

    /// Sends a keepalive ping and waits for the echo.
    pub async fn ping(&self) -> io::Result<()> {
        if self.shared.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "yamux session is closed",
            ));
        }
        let id = self.shared.next_ping_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut pings = self.shared.pings.lock().unwrap();
            pings.insert(id, tx);
        }
        self.shared
            .send_control(frame_type::PING, frame_flags::SYN, 0, id);
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "yamux session is closed"))
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Closes the session and every stream on it.
    pub fn close(&self) {
        self.shared.shutdown();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shared.shutdown();
    }
}

fn encode_header(ftype: u8, flags: u16, stream_id: u32, length: u32) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0] = PROTO_VERSION;
    header[1] = ftype;
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..8].copy_from_slice(&stream_id.to_be_bytes());
    header[8..12].copy_from_slice(&length.to_be_bytes());
    header
}

async fn write_loop<S>(
    mut write_half: S,
    mut rx: mpsc::UnboundedReceiver<Outgoing>,
    shared: Arc<Shared>,
) where
    S: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = rx.recv().await {
        if write_half.write_all(&frame.header).await.is_err() {
            break;
        }
        if !frame.body.is_empty() && write_half.write_all(&frame.body).await.is_err() {
            break;
        }
        // Flushing matters when the session rides on TLS, where the write half
        // only hands bytes to the record layer.
        if write_half.flush().await.is_err() {
            break;
        }
    }
    shared.shutdown();
}

async fn read_loop<S>(mut read_half: S, shared: Arc<Shared>)
where
    S: AsyncRead + Unpin + Send + 'static,
{
    let mut header = [0u8; HEADER_SIZE];
    loop {
        if read_half.read_exact(&mut header).await.is_err() {
            break;
        }
        if header[0] != PROTO_VERSION {
            break;
        }
        let ftype = header[1];
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let stream_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);

        let outcome: Result<(), ()> = match ftype {
            frame_type::DATA => {
                if length > shared.max_window {
                    break;
                }
                let mut body = vec![0u8; length as usize];
                if length > 0 && read_half.read_exact(&mut body).await.is_err() {
                    break;
                }
                handle_stream_frame(&shared, stream_id, flags, ftype, length, Some(body))
            }
            frame_type::WINDOW_UPDATE => {
                handle_stream_frame(&shared, stream_id, flags, ftype, length, None)
            }
            frame_type::PING => {
                handle_ping(&shared, flags, length);
                Ok(())
            }
            frame_type::GO_AWAY => handle_go_away(&shared, length),
            _ => break,
        };
        if outcome.is_err() {
            break;
        }
    }
    shared.shutdown();
}

fn handle_stream_frame(
    shared: &Arc<Shared>,
    stream_id: u32,
    flags: u16,
    ftype: u8,
    length: u32,
    body: Option<Vec<u8>>,
) -> Result<(), ()> {
    if flags & frame_flags::SYN != 0 && incoming_stream(shared, stream_id).is_err() {
        return Err(());
    }

    let stream = { shared.streams.lock().unwrap().get(&stream_id).cloned() };
    // A frame for a stream we already reset is legal; the payload was consumed
    // above, so there is nothing left to drain.
    let Some(stream) = stream else {
        return Ok(());
    };

    if ftype == frame_type::WINDOW_UPDATE {
        stream.process_flags(flags)?;
        stream.send_window.fetch_add(length, Ordering::SeqCst);
        stream.wake_write();
        return Ok(());
    }

    stream.process_flags(flags)?;
    match body {
        Some(body) if !body.is_empty() => stream.buffer_data(body),
        _ => Ok(()),
    }
}

fn incoming_stream(shared: &Arc<Shared>, stream_id: u32) -> Result<(), ()> {
    if shared.local_go_away.load(Ordering::SeqCst) {
        shared.send_control(frame_type::WINDOW_UPDATE, frame_flags::RST, stream_id, 0);
        return Ok(());
    }

    let inner = Arc::new(StreamInner::new(
        stream_id,
        State::SynReceived,
        shared.clone(),
    ));
    {
        let mut streams = shared.streams.lock().unwrap();
        if streams.contains_key(&stream_id) {
            return Err(());
        }
        streams.insert(stream_id, inner.clone());
    }

    let backlog = shared.accept_backlog_count.fetch_add(1, Ordering::SeqCst) + 1;
    if backlog > shared.accept_backlog || shared.accept_tx.send(inner).is_err() {
        shared.accept_backlog_count.fetch_sub(1, Ordering::SeqCst);
        shared.remove_stream(stream_id);
        shared.send_control(frame_type::WINDOW_UPDATE, frame_flags::RST, stream_id, 0);
        return Ok(());
    }
    Ok(())
}

fn handle_ping(shared: &Arc<Shared>, flags: u16, ping_id: u32) {
    if flags & frame_flags::SYN != 0 {
        shared.send_control(frame_type::PING, frame_flags::ACK, 0, ping_id);
        return;
    }
    let waiter = { shared.pings.lock().unwrap().remove(&ping_id) };
    if let Some(waiter) = waiter {
        let _ = waiter.send(());
    }
}

fn handle_go_away(shared: &Arc<Shared>, code: u32) -> Result<(), ()> {
    if code == GO_AWAY_NORMAL {
        shared.remote_go_away.store(true, Ordering::SeqCst);
        Ok(())
    } else {
        Err(())
    }
}

async fn keepalive_loop(shared: Arc<Shared>, interval: Duration) {
    if interval.is_zero() {
        return;
    }
    loop {
        tokio::time::sleep(interval).await;
        if shared.is_closed() {
            return;
        }
        let id = shared.next_ping_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut pings = shared.pings.lock().unwrap();
            pings.insert(id, tx);
        }
        shared.send_control(frame_type::PING, frame_flags::SYN, 0, id);
        if rx.await.is_err() {
            // The session went away while the ping was outstanding.
            shared.shutdown();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_session(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Session {
        Session::new(stream, Mode::Client, Config::default())
    }

    fn server_session(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Session {
        Session::new(stream, Mode::Server, Config::default())
    }

    #[test]
    fn header_encoding_matches_upstream_layout() {
        let header = encode_header(frame_type::WINDOW_UPDATE, frame_flags::SYN, 0x0102_0304, 9);
        assert_eq!(header[0], 0);
        assert_eq!(header[1], 1);
        assert_eq!(&header[2..4], &[0, 1]);
        assert_eq!(&header[4..8], &[1, 2, 3, 4]);
        assert_eq!(&header[8..12], &[0, 0, 0, 9]);
        assert_eq!(HEADER_SIZE, 12);
    }

    #[test]
    fn client_and_server_allocate_different_parities() {
        assert_eq!(Mode::Client.first_stream_id(), 1);
        assert_eq!(Mode::Server.first_stream_id(), 2);
    }

    #[tokio::test]
    async fn opening_a_stream_sends_syn_with_the_window_delta() {
        let (client_half, mut peer) = tokio::io::duplex(4096);
        let config = Config {
            enable_keepalive: false,
            max_stream_window_size: 6 * 1024 * 1024,
            ..Config::default()
        };
        let client = Session::new(client_half, Mode::Client, config);

        let _stream = client.open().await.unwrap();

        let mut header = [0u8; HEADER_SIZE];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], PROTO_VERSION);
        assert_eq!(header[1], frame_type::WINDOW_UPDATE);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), frame_flags::SYN);
        assert_eq!(
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            1
        );
        assert_eq!(
            u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
            6 * 1024 * 1024 - INITIAL_STREAM_WINDOW
        );
    }

    #[tokio::test]
    async fn data_flows_both_ways_and_fin_becomes_eof() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = client_session(a);
        let mut server = server_session(b);

        let server_task = tokio::spawn(async move {
            let mut stream = server.accept().await.expect("peer opened a stream");
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.unwrap();
            // Closing our side must surface as EOF on the peer.
            stream.shutdown().await.unwrap();
            // Hold the session open until the peer is finished.
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(server);
        });

        let mut stream = client.open().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");

        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty(), "expected a clean EOF, got {tail:?}");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn bulk_transfer_stalls_and_resumes_on_window_updates() {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let client = client_session(a);
        let mut server = server_session(b);

        // Far more than the initial 256 KiB window, so the writer can only
        // finish if the reader keeps advertising freed capacity.
        let total = 1024 * 1024;
        let server_task = tokio::spawn(async move {
            let mut stream = server.accept().await.expect("peer opened a stream");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received.len()
        });

        let mut stream = client.open().await.unwrap();
        let payload = vec![0x5au8; total];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        assert_eq!(server_task.await.unwrap(), total);
    }

    #[tokio::test]
    async fn several_streams_are_independent() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = client_session(a);
        let mut server = server_session(b);

        let server_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..3 {
                let mut stream = server.accept().await.expect("stream");
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.unwrap();
                seen.push(String::from_utf8(buf).unwrap());
            }
            seen
        });

        let mut handles = Vec::new();
        for name in ["alpha", "beta", "gamma"] {
            let mut stream = client.open().await.unwrap();
            let payload = name.to_string();
            handles.push(tokio::spawn(async move {
                stream.write_all(payload.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                // Keep the stream alive until the write has been queued.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        let mut seen = server_task.await.unwrap();
        seen.sort();
        assert_eq!(seen, vec!["alpha", "beta", "gamma"]);
    }

    #[tokio::test]
    async fn ping_is_answered_by_the_peer() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = client_session(a);
        let _server = server_session(b);

        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn closing_the_session_wakes_every_stream() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = client_session(a);
        let _server = server_session(b);

        let mut stream = client.open().await.unwrap();
        let mut probe = [0u8; 1];
        let read = tokio::spawn(async move {
            // Returns 0 bytes once the session is torn down.
            let _ = stream.read(&mut probe).await;
        });

        client.close();
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .expect("reader was not woken by the session shutdown")
            .unwrap();
    }
}
