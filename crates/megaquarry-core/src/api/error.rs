use std::fmt;

/// A MEGA API error code (negative numbers in API replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Internal,
    Args,
    Again,
    RateLimit,
    Failed,
    TooMany,
    Range,
    Expired,
    NotFound,
    Circular,
    AccessDenied,
    Exists,
    Incomplete,
    Key,
    BadSession,
    Blocked,
    OverQuota,
    TempUnavailable,
    TooManyConnections,
    Write,
    Read,
    AppKey,
    Ssl,
    GoingOverQuota,
    RolledBack,
    MfaRequired,
    MasterOnly,
    BusinessPastDue,
    Paywall,
    SubuserKeyMissing,
    Unknown(i64),
}

/// Numbering follows the MEGA SDK (`include/mega/types.h`).
const TABLE: [(ErrorCode, i64, &str, &str); 30] = [
    (ErrorCode::Internal, -1, "EINTERNAL", "internal error"),
    (ErrorCode::Args, -2, "EARGS", "invalid arguments"),
    (
        ErrorCode::Again,
        -3,
        "EAGAIN",
        "temporary congestion, try again",
    ),
    (
        ErrorCode::RateLimit,
        -4,
        "ERATELIMIT",
        "rate limit exceeded",
    ),
    (ErrorCode::Failed, -5, "EFAILED", "operation failed"),
    (
        ErrorCode::TooMany,
        -6,
        "ETOOMANY",
        "too many requests or logins",
    ),
    (ErrorCode::Range, -7, "ERANGE", "out of range"),
    (ErrorCode::Expired, -8, "EEXPIRED", "resource expired"),
    (ErrorCode::NotFound, -9, "ENOENT", "not found"),
    (ErrorCode::Circular, -10, "ECIRCULAR", "circular linkage"),
    (ErrorCode::AccessDenied, -11, "EACCESS", "access denied"),
    (ErrorCode::Exists, -12, "EEXIST", "already exists"),
    (ErrorCode::Incomplete, -13, "EINCOMPLETE", "incomplete"),
    (ErrorCode::Key, -14, "EKEY", "decryption failed"),
    (
        ErrorCode::BadSession,
        -15,
        "ESID",
        "invalid or expired session",
    ),
    (
        ErrorCode::Blocked,
        -16,
        "EBLOCKED",
        "blocked (account suspended or link taken down)",
    ),
    (
        ErrorCode::OverQuota,
        -17,
        "EOVERQUOTA",
        "transfer quota exceeded",
    ),
    (
        ErrorCode::TempUnavailable,
        -18,
        "ETEMPUNAVAIL",
        "temporarily unavailable",
    ),
    (
        ErrorCode::TooManyConnections,
        -19,
        "ETOOMANYCONNECTIONS",
        "too many connections",
    ),
    (ErrorCode::Write, -20, "EWRITE", "write error"),
    (ErrorCode::Read, -21, "EREAD", "read error"),
    (ErrorCode::AppKey, -22, "EAPPKEY", "invalid application key"),
    (ErrorCode::Ssl, -23, "ESSL", "SSL verification failed"),
    (
        ErrorCode::GoingOverQuota,
        -24,
        "EGOINGOVERQUOTA",
        "storage quota would be exceeded",
    ),
    (
        ErrorCode::RolledBack,
        -25,
        "EROLLEDBACK",
        "a grouped request was rolled back",
    ),
    (
        ErrorCode::MfaRequired,
        -26,
        "EMFAREQUIRED",
        "two-factor authentication required",
    ),
    (
        ErrorCode::MasterOnly,
        -27,
        "EMASTERONLY",
        "not allowed for business sub-users",
    ),
    (
        ErrorCode::BusinessPastDue,
        -28,
        "EBUSINESSPASTDUE",
        "business account expired",
    ),
    (
        ErrorCode::Paywall,
        -29,
        "EPAYWALL",
        "over storage quota (paywall)",
    ),
    (
        ErrorCode::SubuserKeyMissing,
        -30,
        "ESUBUSERKEYMISSING",
        "business sub-user key not shared with the admin",
    ),
];

impl ErrorCode {
    /// Maps a numeric API code to its variant.
    pub fn from_code(code: i64) -> Self {
        TABLE
            .iter()
            .find(|(_, c, _, _)| *c == code)
            .map_or(Self::Unknown(code), |(e, _, _, _)| *e)
    }

    /// The numeric API code.
    pub fn code(self) -> i64 {
        match self {
            Self::Unknown(code) => code,
            known => TABLE
                .iter()
                .find(|(e, _, _, _)| *e == known)
                .map(|(_, c, _, _)| *c)
                .expect("every known variant is in the table"),
        }
    }

    /// True for errors worth retrying the same request for.
    pub fn is_transient(self) -> bool {
        matches!(self, Self::Internal | Self::Again)
    }

    fn describe(self) -> (&'static str, &'static str) {
        TABLE
            .iter()
            .find(|(e, _, _, _)| *e == self)
            .map_or(("UNKNOWN", "unknown error"), |(_, _, name, text)| {
                (*name, *text)
            })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, text) = self.describe();
        write!(f, "MEGA error {} ({name}): {text}", self.code())
    }
}

/// Errors returned by the API client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Mega(ErrorCode),
    #[error("unexpected HTTP status {0}")]
    Http(u16),
    #[error("network error: {0}")]
    Transport(String),
    #[error("invalid API response: {0}")]
    InvalidResponse(String),
    #[error("hashcash challenge failed: {0}")]
    Hashcash(String),
}
