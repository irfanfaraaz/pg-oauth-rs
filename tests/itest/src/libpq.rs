//! A tiny hand-written binding to libpq 18, just enough to log in with a bearer token.
//!
//! Declarations follow PostgreSQL 18's `libpq-fe.h`. The OAuth part: libpq calls the auth-data
//! hook with `PQAUTHDATA_OAUTH_BEARER_TOKEN` when the server asks for a token; the hook fills in
//! `PGoauthBearerRequest.token`, so no browser or device flow is needed.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::Once;

/// Opaque `PGconn`.
#[repr(C)]
pub struct PGconn {
    _private: [u8; 0],
}

/// Opaque `PGresult`.
#[repr(C)]
pub struct PGresult {
    _private: [u8; 0],
}

// `PGauthData`: PQAUTHDATA_PROMPT_OAUTH_DEVICE = 0, PQAUTHDATA_OAUTH_BEARER_TOKEN = 1.
const PQAUTHDATA_OAUTH_BEARER_TOKEN: c_int = 1;
// `ConnStatusType`.
const CONNECTION_OK: c_int = 0;
// `ExecStatusType`.
const PGRES_COMMAND_OK: c_int = 1;
const PGRES_TUPLES_OK: c_int = 2;

type AuthDataHook =
    unsafe extern "C" fn(kind: c_int, conn: *mut PGconn, data: *mut c_void) -> c_int;

/// `PGoauthBearerRequest`, field for field.
#[repr(C)]
struct PGoauthBearerRequest {
    /// Hook input: the OIDC discovery URI.
    openid_configuration: *const c_char,
    /// Hook input: required scope(s), or NULL.
    scope: *const c_char,
    /// `async` in C: for flows that need several steps. We never set it.
    async_:
        Option<unsafe extern "C" fn(*mut PGconn, *mut PGoauthBearerRequest, *mut c_int) -> c_int>,
    /// Called once libpq no longer needs `token`.
    cleanup: Option<unsafe extern "C" fn(*mut PGconn, *mut PGoauthBearerRequest)>,
    /// Hook output: the bearer token.
    token: *mut c_char,
    /// Hook-private data. We never set it.
    user: *mut c_void,
}

#[link(name = "pq")]
extern "C" {
    fn PQconnectdb(conninfo: *const c_char) -> *mut PGconn;
    fn PQstatus(conn: *const PGconn) -> c_int;
    fn PQerrorMessage(conn: *const PGconn) -> *const c_char;
    fn PQfinish(conn: *mut PGconn);
    fn PQexec(conn: *mut PGconn, query: *const c_char) -> *mut PGresult;
    fn PQresultStatus(res: *const PGresult) -> c_int;
    fn PQntuples(res: *const PGresult) -> c_int;
    fn PQgetvalue(res: *const PGresult, row: c_int, column: c_int) -> *const c_char;
    fn PQclear(res: *mut PGresult);
    fn PQsetAuthDataHook(hook: Option<AuthDataHook>);
    fn PQdefaultAuthDataHook(kind: c_int, conn: *mut PGconn, data: *mut c_void) -> c_int;
}

thread_local! {
    // Per thread, not one global: `PQconnectdb` blocks and calls the hook on the calling thread,
    // so parallel logins in one test each see their own token.
    static TOKEN: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// libpq asks us for authentication data. We answer only bearer-token requests.
unsafe extern "C" fn auth_data_hook(kind: c_int, conn: *mut PGconn, data: *mut c_void) -> c_int {
    if kind != PQAUTHDATA_OAUTH_BEARER_TOKEN {
        // SAFETY: passing libpq's own arguments through to its default hook.
        return unsafe { PQdefaultAuthDataHook(kind, conn, data) };
    }
    let Some(token) = TOKEN.with(|t| t.borrow().clone()) else {
        return 0; // no token set: "not handled"
    };
    // SAFETY: for PQAUTHDATA_OAUTH_BEARER_TOKEN, `data` points to a PGoauthBearerRequest.
    let request = unsafe { &mut *data.cast::<PGoauthBearerRequest>() };
    // libpq copies the token and then calls `cleanup`, which frees this copy.
    request.token = token.into_raw();
    request.cleanup = Some(free_token);
    1 // handled
}

unsafe extern "C" fn free_token(_conn: *mut PGconn, request: *mut PGoauthBearerRequest) {
    // SAFETY: libpq passes back the request our hook filled in.
    let request = unsafe { &mut *request };
    if !request.token.is_null() {
        // SAFETY: `token` came from `CString::into_raw` in `auth_data_hook`.
        drop(unsafe { CString::from_raw(request.token) });
        request.token = ptr::null_mut();
    }
}

fn install_hook() {
    static HOOK: Once = Once::new();
    // SAFETY: the hook has the C signature libpq expects and lives for the whole process.
    HOOK.call_once(|| unsafe { PQsetAuthDataHook(Some(auth_data_hook)) });
}

/// One open connection; closed on drop.
pub struct Conn(*mut PGconn);

impl Drop for Conn {
    fn drop(&mut self) {
        // SAFETY: the pointer came from PQconnectdb and is finished exactly once.
        unsafe { PQfinish(self.0) };
    }
}

impl Conn {
    fn error(&self) -> String {
        // SAFETY: PQerrorMessage returns a NUL-terminated string (also for a NULL conn).
        unsafe { CStr::from_ptr(PQerrorMessage(self.0)) }.to_string_lossy().trim().to_owned()
    }

    /// Run one SQL statement. Returns the first column of the first row, if there is one.
    pub fn query(&self, sql: &str) -> Result<Option<String>, String> {
        let sql = CString::new(sql).expect("SQL without NUL bytes");
        // SAFETY: open connection and a NUL-terminated query.
        let res = unsafe { PQexec(self.0, sql.as_ptr()) };
        // SAFETY: PQresultStatus, PQntuples and PQgetvalue accept the result (even NULL).
        let out = match unsafe { PQresultStatus(res) } {
            PGRES_TUPLES_OK if unsafe { PQntuples(res) } > 0 => {
                // SAFETY: row 0, column 0 exists; the value is NUL-terminated.
                let value = unsafe { CStr::from_ptr(PQgetvalue(res, 0, 0)) };
                Ok(Some(value.to_string_lossy().into_owned()))
            }
            PGRES_TUPLES_OK | PGRES_COMMAND_OK => Ok(None),
            _ => Err(self.error()),
        };
        // SAFETY: frees the result exactly once (PQclear ignores NULL).
        unsafe { PQclear(res) };
        out
    }
}

/// Open a connection. Errors carry libpq's message.
pub fn connect(conninfo: &str) -> Result<Conn, String> {
    install_hook();
    let conninfo = CString::new(conninfo).expect("conninfo without NUL bytes");
    // SAFETY: NUL-terminated conninfo. The result is wrapped at once so it is always finished.
    let conn = Conn(unsafe { PQconnectdb(conninfo.as_ptr()) });
    // SAFETY: PQstatus accepts any PQconnectdb result (NULL gives CONNECTION_BAD).
    if unsafe { PQstatus(conn.0) } != CONNECTION_OK {
        return Err(conn.error());
    }
    Ok(conn)
}

/// Log in with `token` as the OAuth bearer token. Returns `current_user`, or libpq's error.
pub fn connect_with_token(conninfo: &str, token: &str) -> Result<String, String> {
    TOKEN.with(|t| *t.borrow_mut() = Some(CString::new(token).expect("token without NUL bytes")));
    let result = connect(conninfo)
        .and_then(|conn| conn.query("SELECT current_user"))
        .map(Option::unwrap_or_default);
    TOKEN.with(|t| *t.borrow_mut() = None);
    result
}
