//! JWKS cache in PostgreSQL shared memory.
//!
//! One copy of the raw JWKS bytes, shared by every backend through a named DSM segment.
//! `plan` is the pure fetch decision; everything else touches Postgres.

use std::ffi::{c_int, c_void, CStr};
use std::panic::AssertUnwindSafe;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pgrx::pg_sys::LWLockMode;
use pgrx::prelude::*;

use crate::settings::Settings;

/// Largest JWKS document the cache holds.
pub const JWKS_MAX_BYTES: usize = 65536;
/// Largest `jwks_uri` the cache holds.
const URI_MAX_BYTES: usize = 1024;
const NAME: &CStr = c"pg_oauth_rs";

/// A copy of the cache taken under the lock.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub jwks: Vec<u8>,
    pub uri: String,
    pub last_ok: Option<SystemTime>,
    pub last_attempt: Option<SystemTime>,
}

/// What to do about the JWKS for this login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Cached keys are fresh enough; no fetch.
    UseCache,
    /// Fetch now (the caller records the attempt first).
    Fetch,
    /// A fetch is wanted but throttled; the cached keys are still usable.
    UseCacheNoFetch,
    /// A fetch is wanted but throttled, and there is nothing usable cached.
    Refuse,
}

#[derive(Debug)]
pub enum CacheError {
    /// Postgres raised an ERROR (or a panic happened) while touching the segment or its lock.
    Postgres,
    UriTooLong,
    JwksTooLarge,
    /// Stored lengths or bytes are invalid.
    Corrupt,
}

/// Decide whether to use the cache, fetch, or refuse. Pure: no Postgres calls.
pub fn plan(s: &Snapshot, cfg_uri: &str, need_kid: bool, now: SystemTime, set: &Settings) -> Plan {
    // A clock that went backwards counts as "no time has passed".
    let since = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::ZERO);
    // Keys cached for another URI, or older than max_stale, count as no keys at all.
    let age = s
        .last_ok
        .filter(|_| s.uri == cfg_uri && !s.jwks.is_empty())
        .map(since)
        .filter(|age| *age <= set.max_stale);
    let want_fetch = match age {
        None => true,
        Some(age) => need_kid || age > set.max_age,
    };
    if !want_fetch {
        return Plan::UseCache;
    }
    let may_fetch = match s.last_attempt {
        None => true,
        Some(t) => since(t) >= set.refetch_interval,
    };
    match (may_fetch, age) {
        (true, _) => Plan::Fetch,
        (false, Some(_)) => Plan::UseCacheNoFetch,
        (false, None) => Plan::Refuse,
    }
}

/// Copy the cache out under a shared lock.
pub fn read() -> Result<Snapshot, CacheError> {
    with_lock(LWLockMode::LW_SHARED, |p| {
        // SAFETY: `p` is the attached segment and we hold its lock in shared mode. Only the
        // lock-protected fields are borrowed, never the lock itself.
        let (uri, uri_len, jwks, jwks_len, last_ok, last_attempt) = unsafe {
            (
                &(*p).uri,
                (*p).uri_len,
                &(*p).jwks,
                (*p).jwks_len,
                (*p).last_ok,
                (*p).last_attempt,
            )
        };
        let uri = uri.get(..uri_len).ok_or(CacheError::Corrupt)?;
        let jwks = jwks.get(..jwks_len).ok_or(CacheError::Corrupt)?;
        Ok(Snapshot {
            jwks: jwks.to_vec(),
            uri: String::from_utf8(uri.to_vec()).map_err(|_| CacheError::Corrupt)?,
            last_ok: from_secs(last_ok),
            last_attempt: from_secs(last_attempt),
        })
    })
}

/// Store a successfully fetched JWKS for `uri`. Too-long input is refused, never truncated.
pub fn store_ok(uri: &str, jwks: &[u8], now: SystemTime) -> Result<(), CacheError> {
    with_lock(LWLockMode::LW_EXCLUSIVE, |p| {
        // SAFETY: `p` is the attached segment and we hold its lock exclusively. Only the
        // lock-protected fields are borrowed, never the lock itself.
        let (u, j) = unsafe { (&mut (*p).uri, &mut (*p).jwks) };
        // Both slices are taken before writing, so a refusal leaves the cache untouched.
        let u = u.get_mut(..uri.len()).ok_or(CacheError::UriTooLong)?;
        let j = j.get_mut(..jwks.len()).ok_or(CacheError::JwksTooLarge)?;
        u.copy_from_slice(uri.as_bytes());
        j.copy_from_slice(jwks);
        // SAFETY: as above.
        unsafe {
            (*p).uri_len = uri.len();
            (*p).jwks_len = jwks.len();
            (*p).last_ok = to_secs(now);
        }
        Ok(())
    })
}

/// Record a fetch attempt (successful or not); this is the throttle every backend shares.
pub fn note_attempt(now: SystemTime) -> Result<(), CacheError> {
    with_lock(LWLockMode::LW_EXCLUSIVE, |p| {
        // SAFETY: `p` is the attached segment and we hold its lock exclusively.
        unsafe { (*p).last_attempt = to_secs(now) };
        Ok(())
    })
}

/// Shared-memory layout. Zeroed means empty; times are unix seconds, 0 = never.
#[repr(C)]
struct Shared {
    lock: pg_sys::LWLock,
    tranche_id: c_int,
    uri_len: usize,
    uri: [u8; URI_MAX_BYTES],
    jwks_len: usize,
    last_ok: i64,
    last_attempt: i64,
    jwks: [u8; JWKS_MAX_BYTES],
}

/// This backend's mapping of the segment; null until attached and the tranche is registered.
static SEGMENT: AtomicPtr<Shared> = AtomicPtr::new(ptr::null_mut());

/// Run `f`, turning a Postgres ERROR (or a panic) into `CacheError::Postgres`.
fn guarded<R>(f: impl FnOnce() -> R) -> Result<R, CacheError> {
    PgTryBuilder::new(AssertUnwindSafe(|| Ok(f())))
        .catch_others(|_| Err(CacheError::Postgres))
        .execute()
}

/// Take the lock, run `f`, and release the lock on every path.
fn with_lock<R>(
    mode: LWLockMode::Type,
    f: impl FnOnce(*mut Shared) -> Result<R, CacheError>,
) -> Result<R, CacheError> {
    let shared = segment()?;
    // SAFETY: `shared` points to the attached segment; no reference is created.
    let lock = unsafe { ptr::addr_of_mut!((*shared).lock) };
    // SAFETY: `lock` was initialised by `init_shared`.
    guarded(|| unsafe { pg_sys::LWLockAcquire(lock, mode) })?;
    let out = guarded(|| f(shared)).and_then(|r| r);
    // SAFETY: this backend acquired `lock` just above.
    guarded(|| unsafe { pg_sys::LWLockRelease(lock) })?;
    out
}

/// Attach (creating on first use cluster-wide) the segment, once per backend.
fn segment() -> Result<*mut Shared, CacheError> {
    let p = SEGMENT.load(Ordering::Relaxed);
    if !p.is_null() {
        return Ok(p);
    }
    let mut found = false;
    let size = std::mem::size_of::<Shared>();
    // SAFETY: NAME is a static C string; `init` matches the callback type; `found` outlives the call.
    #[cfg(not(feature = "pg19"))]
    let raw = guarded(|| unsafe {
        pg_sys::GetNamedDSMSegment(NAME.as_ptr(), size, Some(init), &mut found)
    })?;
    // SAFETY: as above; the extra init argument is unused.
    #[cfg(feature = "pg19")]
    let raw = guarded(|| unsafe {
        pg_sys::GetNamedDSMSegment(NAME.as_ptr(), size, Some(init), &mut found, ptr::null_mut())
    })?;
    let p = raw.cast::<Shared>();
    if p.is_null() {
        return Err(CacheError::Postgres);
    }
    #[cfg(not(feature = "pg19"))]
    {
        // SAFETY: `p` is the attached segment, initialised before GetNamedDSMSegment returned.
        let id = unsafe { (*p).tranche_id };
        // SAFETY: NAME is static, as LWLockRegisterTranche requires.
        guarded(|| unsafe { pg_sys::LWLockRegisterTranche(id, NAME.as_ptr()) })?;
    }
    SEGMENT.store(p, Ordering::Relaxed);
    Ok(p)
}

#[cfg(not(feature = "pg19"))]
#[pg_guard]
unsafe extern "C-unwind" fn init(ptr: *mut c_void) {
    // SAFETY: Postgres hands us a fresh segment of size_of::<Shared>() bytes.
    unsafe { init_shared(ptr.cast()) }
}

#[cfg(feature = "pg19")]
#[pg_guard]
unsafe extern "C-unwind" fn init(ptr: *mut c_void, _arg: *mut c_void) {
    // SAFETY: Postgres hands us a fresh segment of size_of::<Shared>() bytes.
    unsafe { init_shared(ptr.cast()) }
}

/// # Safety
/// `shared` must point to `size_of::<Shared>()` writable, suitably aligned bytes.
unsafe fn init_shared(shared: *mut Shared) {
    // SAFETY: guaranteed by the caller; all-zero is a valid (empty) `Shared`.
    unsafe {
        ptr::write_bytes(shared, 0, 1);
        #[cfg(not(feature = "pg19"))]
        let id = pg_sys::LWLockNewTrancheId();
        #[cfg(feature = "pg19")]
        let id = pg_sys::LWLockNewTrancheId(NAME.as_ptr());
        (*shared).tranche_id = id;
        pg_sys::LWLockInitialize(ptr::addr_of_mut!((*shared).lock), id);
    }
}

fn to_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn from_secs(s: i64) -> Option<SystemTime> {
    u64::try_from(s)
        .ok()
        .filter(|&s| s > 0)
        .and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s)))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    const URI: &str = "https://idp.example/jwks";

    fn set() -> Settings {
        Settings {
            audience: "db".into(),
            jwks_uri: URI.into(),
            identity_claim: "sub".into(),
            leeway: Duration::from_secs(60),
            jwks_timeout: Duration::from_secs(5),
            refetch_interval: Duration::from_secs(60),
            max_age: Duration::from_secs(3600),
            max_stale: Duration::from_secs(86400),
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    fn cached(ok: u64, attempt: u64) -> Snapshot {
        Snapshot {
            jwks: b"{\"keys\":[]}".to_vec(),
            uri: URI.into(),
            last_ok: Some(at(ok)),
            last_attempt: Some(at(attempt)),
        }
    }

    #[test]
    fn empty_cache_fetches() {
        assert_eq!(plan(&Snapshot::default(), URI, false, at(0), &set()), Plan::Fetch);
    }

    #[test]
    fn throttle_blocks_second_attempt() {
        let s = Snapshot {
            last_attempt: Some(at(0)),
            ..Snapshot::default()
        };
        assert_eq!(plan(&s, URI, false, at(30), &set()), Plan::Refuse);
        assert_eq!(plan(&s, URI, false, at(60), &set()), Plan::Fetch);
    }

    #[test]
    fn failed_attempt_also_throttles() {
        // Keys from t=0 are past max_age; the refresh at t=4000 failed.
        let s = cached(0, 4000);
        assert_eq!(plan(&s, URI, false, at(4010), &set()), Plan::UseCacheNoFetch);
        assert_eq!(plan(&s, URI, false, at(4060), &set()), Plan::Fetch);
    }

    #[test]
    fn stale_beyond_max_stale_refuses() {
        // Last attempt (failed) at t=86_350, so fetching is throttled until t=86_410.
        let s = cached(0, 86_350);
        assert_eq!(plan(&s, URI, false, at(86_400), &set()), Plan::UseCacheNoFetch);
        assert_eq!(plan(&s, URI, false, at(86_401), &set()), Plan::Refuse);
        assert_eq!(plan(&s, URI, false, at(86_410), &set()), Plan::Fetch);
    }

    #[test]
    fn uri_change_ignores_old_keys() {
        let s = cached(0, 0);
        let new = "https://other.example/jwks";
        assert_eq!(plan(&s, URI, false, at(10), &set()), Plan::UseCache);
        assert_eq!(plan(&s, new, false, at(10), &set()), Plan::Refuse);
        assert_eq!(plan(&s, new, false, at(60), &set()), Plan::Fetch);
    }

    #[test]
    fn old_cache_refreshes() {
        let s = cached(0, 0);
        assert_eq!(plan(&s, URI, false, at(3600), &set()), Plan::UseCache);
        assert_eq!(plan(&s, URI, false, at(3601), &set()), Plan::Fetch);
    }

    #[test]
    fn unknown_kid_fetches_once_per_interval() {
        let s = cached(0, 0);
        assert_eq!(plan(&s, URI, true, at(10), &set()), Plan::UseCacheNoFetch);
        assert_eq!(plan(&s, URI, true, at(60), &set()), Plan::Fetch);
        // After that fetch was noted, the next unknown kid waits again.
        let s = cached(0, 60);
        assert_eq!(plan(&s, URI, true, at(90), &set()), Plan::UseCacheNoFetch);
    }
}
