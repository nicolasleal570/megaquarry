//! MEGA's `X-Hashcash` proof of work.
//!
//! Challenge `1:<easiness>:<timestamp>:<token>`; find a 4-byte nonce such that
//! the first big-endian `u32` of `SHA-256(nonce || token * 262144)` is at most
//! the threshold derived from the easiness. Answer `1:<token>:<b64url(nonce)>`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::crypto::{b64url_decode, b64url_encode};

const TOKEN_LEN: usize = 48;
const TOKEN_REPEATS: usize = 262_144;
const MAX_THREADS: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(300);

struct Challenge {
    token_text: String,
    token: Vec<u8>,
    threshold: u32,
}

fn parse(challenge: &str) -> Result<Challenge, String> {
    let parts: Vec<&str> = challenge.split(':').collect();
    let [version, easiness, _timestamp, token_text] = parts[..] else {
        return Err("expected 4 fields".into());
    };
    if version != "1" {
        return Err(format!("unsupported version {version}"));
    }
    let easiness: u8 = easiness
        .parse()
        .map_err(|_| format!("bad easiness {easiness}"))?;
    let token = b64url_decode(token_text).map_err(|e| e.to_string())?;
    if token.len() != TOKEN_LEN {
        return Err(format!("token must be {TOKEN_LEN} bytes"));
    }
    let e = u32::from(easiness);
    let threshold = (((e & 63) << 1) + 1) << (((e >> 6) & 3) * 7 + 3);
    Ok(Challenge {
        token_text: token_text.to_owned(),
        token,
        threshold,
    })
}

fn meets(nonce: u32, body: &[u8], threshold: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(nonce.to_be_bytes());
    hasher.update(body);
    let digest = hasher.finalize();
    u32::from_be_bytes(digest[..4].try_into().expect("4 bytes")) <= threshold
}

/// Solves a challenge using up to 8 threads (blocking; at most 5 minutes).
pub fn solve(challenge: &str) -> Result<String, String> {
    let c = parse(challenge)?;
    let body = c.token.repeat(TOKEN_REPEATS);
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(MAX_THREADS) as u64;
    let found = AtomicU64::new(u64::MAX);
    let stop = AtomicBool::new(false);
    let deadline = Instant::now() + TIMEOUT;

    std::thread::scope(|scope| {
        for start in 0..threads {
            let (body, found, stop) = (&body, &found, &stop);
            scope.spawn(move || {
                let mut nonce = start;
                while nonce <= u64::from(u32::MAX) && !stop.load(Ordering::Relaxed) {
                    if Instant::now() > deadline {
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                    if meets(nonce as u32, body, c.threshold) {
                        found.fetch_min(nonce, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                    nonce += threads;
                }
            });
        }
    });

    match found.load(Ordering::Relaxed) {
        u64::MAX => Err("no solution found in time".into()),
        nonce => Ok(format!(
            "1:{}:{}",
            c.token_text,
            b64url_encode(&(nonce as u32).to_be_bytes())
        )),
    }
}

/// Checks that `solution` answers `challenge`.
pub fn verify(challenge: &str, solution: &str) -> bool {
    let Ok(c) = parse(challenge) else {
        return false;
    };
    let parts: Vec<&str> = solution.split(':').collect();
    let ["1", token, nonce] = parts[..] else {
        return false;
    };
    let Ok(nonce) = b64url_decode(nonce) else {
        return false;
    };
    let Ok(nonce) = <[u8; 4]>::try_from(nonce.as_slice()) else {
        return false;
    };
    token == c.token_text
        && meets(
            u32::from_be_bytes(nonce),
            &c.token.repeat(TOKEN_REPEATS),
            c.threshold,
        )
}
