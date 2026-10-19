//! Interruptible HTTPS JWKS fetch driven by WaitLatchOrSocket.
//!
//! libcurl's multi interface tells us which sockets it wants; we sleep on them through
//! Postgres's latch machinery so a cancel, terminate or postmaster death stops the fetch.

use std::collections::BTreeMap;
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use curl::easy::{Easy2, Handler, WriteError};
use curl::multi::{Events, Multi, Socket};
use curl::MultiError;
use pgrx::pg_sys;

#[derive(Debug)]
pub enum FetchError {
    NotHttps,
    Timeout,
    Http(u32),
    TooLarge,
    /// curl's error description only, never response body text.
    Transport(String),
}

const MAX_REDIRECTS: u32 = 3;
const WL_SOCKET_RW: u32 = pg_sys::WL_SOCKET_READABLE | pg_sys::WL_SOCKET_WRITEABLE;

// libcurl option numbers (curl.h: CURLOPTTYPE_STRINGPOINT 10000 + 318/319); the curl crate has
// no setter for these. They need libcurl >= 7.85; older libcurl rejects them and the fetch fails.
const CURLOPT_PROTOCOLS_STR: c_int = 10318;
const CURLOPT_REDIR_PROTOCOLS_STR: c_int = 10319;

unsafe extern "C" {
    // Exported by libcurl, which the curl crate links. Returns a CURLcode (unsigned enum).
    fn curl_easy_setopt(handle: *mut c_void, option: c_int, ...) -> c_uint;
}

/// Sockets curl currently wants watched, with the WL_SOCKET_* bits it asked for.
type Watched = Arc<Mutex<BTreeMap<Socket, u32>>>;

struct Collector {
    body: Vec<u8>,
    max_bytes: usize,
    too_large: bool,
}

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        if self.body.len().saturating_add(data.len()) > self.max_bytes {
            self.too_large = true;
            return Ok(0); // short write: curl aborts the transfer
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
}

/// GET `uri` over HTTPS and return the body. Gives up after `timeout` or `max_bytes`.
pub fn fetch_jwks(uri: &str, timeout: Duration, max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    if !uri.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return Err(FetchError::NotHttps);
    }
    let deadline = Instant::now().checked_add(timeout).ok_or(FetchError::Timeout)?;

    let mut easy = Easy2::new(Collector { body: Vec::new(), max_bytes, too_large: false });
    configure(&mut easy, uri, timeout).map_err(transport)?;

    let watched = Watched::default();
    let mut multi = Multi::new();
    let w = Arc::clone(&watched);
    multi
        .socket_function(move |fd, ev, _| {
            let mut map = w.lock().unwrap_or_else(PoisonError::into_inner);
            if ev.remove() {
                map.remove(&fd);
                return;
            }
            let mut want = 0;
            if ev.input() || ev.input_and_output() {
                want |= pg_sys::WL_SOCKET_READABLE;
            }
            if ev.output() || ev.input_and_output() {
                want |= pg_sys::WL_SOCKET_WRITEABLE;
            }
            map.insert(fd, want);
        })
        .map_err(multi_err)?;

    // Declared after `multi` so it is dropped (detached) first, also on early return or unwind.
    let handle = multi.add2(easy).map_err(multi_err)?;
    let mut running = multi.timeout().map_err(multi_err)?;
    while running > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::Timeout);
        }
        let wait = multi.get_timeout().map_err(multi_err)?.map_or(remaining, |t| t.min(remaining));
        let fds: Vec<(Socket, u32)> = watched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(&fd, &want)| (fd, want))
            .collect();

        let ready = wait_for(&fds, wait);
        if ready.is_empty() {
            running = multi.timeout().map_err(multi_err)?;
        }
        for (fd, got) in ready {
            let mut ev = Events::new();
            ev.input(got & pg_sys::WL_SOCKET_READABLE != 0)
                .output(got & pg_sys::WL_SOCKET_WRITEABLE != 0);
            running = multi.action(fd, &ev).map_err(multi_err)?;
        }
    }

    let mut result = None;
    multi.messages(|m| {
        if let Some(r) = m.result() {
            result = Some(r);
        }
    });
    let mut easy = multi.remove2(handle).map_err(multi_err)?;

    if easy.get_ref().too_large {
        return Err(FetchError::TooLarge);
    }
    match result {
        Some(Ok(())) => {}
        Some(Err(e)) if e.is_operation_timedout() => return Err(FetchError::Timeout),
        Some(Err(e)) => return Err(transport(e)),
        None => return Err(FetchError::Transport("transfer ended without a result".into())),
    }
    match easy.response_code().map_err(transport)? {
        200 => Ok(std::mem::take(&mut easy.get_mut().body)),
        code => Err(FetchError::Http(code)),
    }
}

fn configure(easy: &mut Easy2<Collector>, uri: &str, timeout: Duration) -> Result<(), curl::Error> {
    easy.url(uri)?;
    easy.timeout(timeout)?;
    easy.follow_location(true)?;
    easy.max_redirections(MAX_REDIRECTS)?;
    easy.ssl_verify_peer(true)?;
    easy.ssl_verify_host(true)?;
    for opt in [CURLOPT_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS_STR] {
        // SAFETY: `raw()` is a live easy handle; both options take a NUL-terminated string,
        // which libcurl copies, and `c"https"` is static anyway.
        let rc = unsafe { curl_easy_setopt(easy.raw().cast(), opt, c"https".as_ptr()) };
        if rc != 0 {
            return Err(curl::Error::new(rc));
        }
    }
    Ok(())
}

/// Sleep until a watched socket is ready, the latch is set, or `wait` passes.
/// Returns the ready sockets with their WL_SOCKET_* bits; empty on timeout or latch.
fn wait_for(fds: &[(Socket, u32)], wait: Duration) -> Vec<(Socket, u32)> {
    let ms = c_long::try_from(wait.as_micros().div_ceil(1000)).unwrap_or(c_long::MAX);
    match fds {
        [] => wait_one(pg_sys::PGINVALID_SOCKET, 0, ms),
        [(fd, want)] => wait_one(*fd, *want, ms),
        _ => wait_many(fds, ms),
    }
}

fn wait_one(fd: Socket, want: u32, ms: c_long) -> Vec<(Socket, u32)> {
    let events = pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH | want;
    // SAFETY: MyLatch is this backend's latch; `fd` is a socket curl owns, or invalid with no socket events.
    let rc =
        unsafe { pg_sys::WaitLatchOrSocket(pg_sys::MyLatch, events as c_int, fd, ms, 0) } as u32;
    if rc & pg_sys::WL_LATCH_SET != 0 {
        on_latch();
    }
    let got = rc & want;
    if got != 0 {
        vec![(fd, got)]
    } else {
        Vec::new()
    }
}

/// curl can watch several sockets at once (e.g. IPv4 and IPv6 during connect).
fn wait_many(fds: &[(Socket, u32)], ms: c_long) -> Vec<(Socket, u32)> {
    let cap = fds.len().saturating_add(2);
    let Ok(n) = c_int::try_from(cap) else {
        return Vec::new();
    };
    let mut out = vec![pg_sys::WaitEvent::default(); cap];
    // SAFETY: the set is sized for latch + PM death + every fd, `out` holds `n` events,
    // and the set is freed on return (or by CurrentResourceOwner, when set, if an ERROR escapes).
    let got = unsafe {
        let set = pg_sys::CreateWaitEventSet(pg_sys::CurrentResourceOwner, n);
        pg_sys::AddWaitEventToSet(
            set,
            pg_sys::WL_LATCH_SET,
            pg_sys::PGINVALID_SOCKET,
            pg_sys::MyLatch,
            ptr::null_mut(),
        );
        if pg_sys::IsUnderPostmaster {
            pg_sys::AddWaitEventToSet(
                set,
                pg_sys::WL_EXIT_ON_PM_DEATH,
                pg_sys::PGINVALID_SOCKET,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
        for &(fd, want) in fds {
            pg_sys::AddWaitEventToSet(set, want, fd, ptr::null_mut(), ptr::null_mut());
        }
        let got = pg_sys::WaitEventSetWait(set, ms, out.as_mut_ptr(), n, 0);
        pg_sys::FreeWaitEventSet(set);
        got
    };

    let mut latch = false;
    let mut ready = Vec::new();
    for ev in out.iter().take(usize::try_from(got).unwrap_or(0)) {
        latch |= ev.events & pg_sys::WL_LATCH_SET != 0;
        let bits = ev.events & WL_SOCKET_RW;
        if bits != 0 {
            ready.push((ev.fd, bits));
        }
    }
    if latch {
        on_latch();
    }
    ready
}

/// Any ERROR/FATAL raised here propagates; curl handles are dropped on the way out.
pub(crate) fn on_latch() {
    // SAFETY: MyLatch is this backend's own latch.
    unsafe { pg_sys::ResetLatch(pg_sys::MyLatch) };
    pgrx::check_for_interrupts!();
}

fn transport(e: curl::Error) -> FetchError {
    FetchError::Transport(e.description().to_owned())
}

fn multi_err(e: MultiError) -> FetchError {
    FetchError::Transport(e.description().to_owned())
}
