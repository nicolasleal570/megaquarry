//! Account login: password derivation, master key, RSA session id, 2FA.

use num_bigint::BigUint;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiTransport, ErrorCode, MegaApi};
use crate::crypto::{
    AesKey, b64url_decode, b64url_encode, derive_v2, ecb_decrypt, prepare_key_v1, user_hash_v1,
};

/// Bytes of the decrypted `csid` that form the session id.
const SID_LEN: usize = 43;
/// Largest accepted RSA modulus; MEGA account keys are 2048 bits.
const MAX_MODULUS_BITS: u64 = 8192;

/// What is needed to log in again without the password; these are
/// kept instead of the password when re-creating sessions).
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Normalized email (lowercase, alias suffix removed).
    pub email: String,
    pub password_aes: AesKey,
    pub user_hash: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// A logged-in account session.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    pub sid: String,
    pub master_key: AesKey,
    pub user_handle: String,
    pub credentials: Credentials,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("email", &self.credentials.email)
            .field("user_handle", &self.user_handle)
            .finish_non_exhaustive()
    }
}

/// Why a login failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoginError {
    #[error("wrong email or password")]
    BadCredentials,
    #[error("the email address is empty")]
    InvalidEmail,
    #[error("two-factor authentication is enabled: a code is required")]
    MfaRequired,
    #[error("this account uses a key format megaquarry does not support")]
    UnsupportedAccount,
    #[error("unexpected login reply: {0}")]
    Malformed(String),
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Lowercases the email and drops a trailing `# alias`.
pub fn normalize_email(email: &str) -> String {
    email
        .split('#')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Logs in with email and password, setting the API's session id.
pub async fn login<T: ApiTransport>(
    api: &MegaApi<T>,
    email: &str,
    password: &str,
    mfa_code: Option<&str>,
) -> Result<Session, LoginError> {
    let email = normalize_email(email);
    if email.is_empty() {
        return Err(LoginError::InvalidEmail);
    }
    api.set_session_id(None);
    let prelogin = api
        .call(json!({"a": "us0", "user": email}))
        .await
        .map_err(unknown_user)?;
    // Without `v`, a salt means a v2 account (v1 accounts have no salt).
    let version = prelogin["v"]
        .as_u64()
        .unwrap_or(if prelogin["s"].is_string() { 2 } else { 1 });
    let (password_aes, user_hash) = if version == 1 {
        let key = prepare_key_v1(password);
        let hash = user_hash_v1(&email, &key);
        (key, hash)
    } else {
        let salt = prelogin["s"]
            .as_str()
            .and_then(|s| b64url_decode(s).ok())
            .ok_or_else(|| LoginError::Malformed("missing salt".into()))?;
        derive_v2(password, &salt)
    };
    let credentials = Credentials {
        email,
        password_aes,
        user_hash,
    };
    login_with_credentials(api, &credentials, mfa_code).await
}

/// Logs in from stored credentials (no password needed).
pub async fn login_with_credentials<T: ApiTransport>(
    api: &MegaApi<T>,
    credentials: &Credentials,
    mfa_code: Option<&str>,
) -> Result<Session, LoginError> {
    api.set_session_id(None);
    if mfa_code.is_none() {
        let enabled = api
            .call(json!({"a": "mfag", "e": credentials.email}))
            .await
            .map_err(unknown_user)?;
        if enabled.as_i64() == Some(1) {
            return Err(LoginError::MfaRequired);
        }
    }

    let mut command = json!({"a": "us", "user": credentials.email, "uh": credentials.user_hash});
    if let Some(code) = mfa_code {
        command["mfa"] = json!(code);
    }
    let reply = match api.call(command).await {
        Ok(reply) => reply,
        Err(ApiError::Mega(ErrorCode::NotFound)) => return Err(LoginError::BadCredentials),
        Err(ApiError::Mega(ErrorCode::MfaRequired)) => return Err(LoginError::MfaRequired),
        Err(e) => return Err(e.into()),
    };

    if reply.get("k").is_none() && reply.get("keys").is_some() {
        return Err(LoginError::UnsupportedAccount);
    }
    let master_key = decode_master_key(&reply, &credentials.password_aes)?;
    // The RSA decryption is CPU-bound: keep it off the async workers.
    let sid = {
        let reply = reply.clone();
        tokio::task::spawn_blocking(move || decode_session_id(&reply, &master_key))
            .await
            .map_err(|e| LoginError::Malformed(e.to_string()))??
    };
    api.set_session_id(Some(sid.clone()));
    Ok(Session {
        sid,
        master_key,
        user_handle: reply["u"].as_str().unwrap_or_default().to_owned(),
        credentials: credentials.clone(),
    })
}

/// `-9` (not found) before `us` means the account does not exist.
fn unknown_user(error: ApiError) -> LoginError {
    match error {
        ApiError::Mega(ErrorCode::NotFound) => LoginError::BadCredentials,
        other => other.into(),
    }
}

fn field(reply: &Value, name: &str) -> Result<Vec<u8>, LoginError> {
    reply[name]
        .as_str()
        .and_then(|s| b64url_decode(s).ok())
        .ok_or_else(|| LoginError::Malformed(format!("missing or invalid `{name}`")))
}

fn decode_master_key(reply: &Value, password_aes: &AesKey) -> Result<AesKey, LoginError> {
    let wrapped = field(reply, "k")?;
    let key = ecb_decrypt(password_aes, &wrapped)
        .map_err(|e| LoginError::Malformed(format!("master key: {e}")))?;
    key.try_into()
        .map_err(|_| LoginError::Malformed("master key is not 16 bytes".into()))
}

/// Reads one MPI (2-byte big-endian bit length, then the bytes).
fn read_mpi(data: &[u8]) -> Option<(BigUint, &[u8])> {
    let bits = usize::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
    let len = bits.div_ceil(8);
    let bytes = data.get(2..2 + len)?;
    Some((BigUint::from_bytes_be(bytes), &data[2 + len..]))
}

fn decode_session_id(reply: &Value, master_key: &AesKey) -> Result<String, LoginError> {
    let bad_key = || LoginError::Malformed("the RSA private key does not decrypt".into());
    let privk = ecb_decrypt(master_key, &field(reply, "privk")?).map_err(|_| bad_key())?;
    let (p, rest) = read_mpi(&privk).ok_or_else(bad_key)?;
    let (q, rest) = read_mpi(rest).ok_or_else(bad_key)?;
    let (d, rest) = read_mpi(rest).ok_or_else(bad_key)?;
    let (u, _) = read_mpi(rest).ok_or_else(bad_key)?;
    // A wrong master key yields garbage. `u` is the CRT coefficient; accept
    // either convention (p^-1 mod q or q^-1 mod p) since only consistency
    // matters here.
    let one = BigUint::from(1u8);
    if p <= one || q <= one || ((&u * &p) % &q != one && (&u * &q) % &p != one) {
        return Err(bad_key());
    }
    let n = &p * &q;
    if n.bits() > MAX_MODULUS_BITS || d.bits() > MAX_MODULUS_BITS {
        return Err(LoginError::Malformed("RSA key too large".into()));
    }

    let (ciphertext, _) = read_mpi(&field(reply, "csid")?)
        .ok_or_else(|| LoginError::Malformed("invalid `csid`".into()))?;
    if ciphertext >= n {
        return Err(bad_key());
    }
    let plain = ciphertext.modpow(&d, &n).to_bytes_be();
    let sid = sid_from_plaintext(&plain, n.bits().div_ceil(8) as usize)
        .ok_or_else(|| LoginError::Malformed("session id too short".into()))?;
    Ok(b64url_encode(&sid))
}

/// The sid inside the RSA plaintext: the RSA output at its fixed
/// modulus length, minus one leading zero byte, first 43 bytes. Unlike
/// stripping every leading zero, this keeps a sid that starts with 0x00.
fn sid_from_plaintext(plain: &[u8], modulus_len: usize) -> Option<Vec<u8>> {
    let mut fixed = vec![0u8; modulus_len.saturating_sub(plain.len())];
    fixed.extend_from_slice(plain);
    let body = fixed.strip_prefix(&[0u8]).unwrap_or(&fixed);
    body.get(..SID_LEN).map(<[u8]>::to_vec)
}
