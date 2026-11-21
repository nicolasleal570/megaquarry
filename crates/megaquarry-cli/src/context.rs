//! Wiring: the store, the API client and the adapters behind the commands.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use megaquarry_core::adapters::gluetun::GluetunControl;
use megaquarry_core::adapters::http::ReqwestTransport;
use megaquarry_core::api::{ApiConfig, ApiError, ErrorCode, MegaApi};
use megaquarry_core::egress::{
    QuotaRotation, RotateError, RotationEvent, RotationOptions, Rotator,
};
use megaquarry_core::session::{self, LoginError, Session};
use megaquarry_core::store::{Settings, Store, TransferLock, Vault};

pub type Api = MegaApi<ReqwestTransport>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub const ACCOUNT_PASSWORD_ENV: &str = "MEGAQUARRY_PASSWORD";
pub const MASTER_PASSWORD_ENV: &str = "MEGAQUARRY_MASTER_PASSWORD";
pub const NEW_MASTER_PASSWORD_ENV: &str = "MEGAQUARRY_NEW_MASTER_PASSWORD";

pub struct Context {
    pub store: Arc<Store>,
    pub settings: Settings,
    api_url: Option<String>,
    home: PathBuf,
    egress: Egress,
}

/// Where exit IP rotation is controlled (gluetun), when enabled.
#[derive(Debug, Default)]
pub struct Egress {
    pub url: Option<String>,
    pub key_file: Option<PathBuf>,
}

impl Context {
    pub fn open(
        home: Option<PathBuf>,
        api_url: Option<String>,
        egress: Egress,
    ) -> Result<Self, Error> {
        let home = match home {
            Some(home) => home,
            None => dirs::data_dir()
                .ok_or("cannot find a data directory; pass --home")?
                .join("megaquarry"),
        };
        let store = Store::open(&home.join("megaquarry.db"))?;
        let settings = Settings::load(&store)?;
        Ok(Self {
            store: Arc::new(store),
            settings,
            api_url,
            home,
            egress,
        })
    }

    /// The lock every transferring command holds, so only one runs at a time.
    pub fn transfer_lock(&self) -> Result<TransferLock, Error> {
        let path = self.home.join("transfer.lock");
        TransferLock::try_acquire(&path)?.ok_or_else(|| {
            format!(
                "another megaquarry transfer is running (lock: {}); wait for it to finish",
                path.display()
            )
            .into()
        })
    }

    /// Exit IP rotation through gluetun, ready to use: the control server is
    /// protected, the tunnel is up and its IP is not cooling down. `None`
    /// when rotation is not configured or downloads go through an account.
    pub async fn rotation(
        &self,
        through_account: bool,
    ) -> Result<Option<Arc<dyn QuotaRotation>>, Error> {
        let Some(url) = &self.egress.url else {
            return Ok(None);
        };
        if through_account {
            eprintln!(
                "warning: downloads through an account do not rotate the exit IP (MEGA counts their quota per account)"
            );
            return Ok(None);
        }
        let key_file = self.egress.key_file.as_ref().ok_or(
            "--egress-key-file (MEGAQUARRY_EGRESS_KEY_FILE) is required with --egress-url",
        )?;
        let key = std::fs::read_to_string(key_file)
            .map_err(|e| {
                format!(
                    "cannot read the VPN control API key file {}: {e}",
                    key_file.display()
                )
            })?
            .trim()
            .to_owned();
        if key.is_empty() {
            return Err(format!("the API key file {} is empty", key_file.display()).into());
        }
        let control = GluetunControl::new(url, key)?;
        let protected = control.requires_auth().await.map_err(|e| {
            format!("cannot check the VPN control: {e}; check `docker compose logs vpn`")
        })?;
        if !protected {
            return Err(format!(
                "the VPN control at {url} accepts requests without an API key; refusing to use it \
                 (give gluetun a config.toml with an API key role, see the README)"
            )
            .into());
        }

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                eprintln!("{}", describe(&event));
            }
        });
        let settings = &self.settings;
        let rotator = Rotator::new(
            control,
            self.store.clone(),
            RotationOptions {
                fallback_cooldown: settings.egress_cooldown_fallback,
                max_attempts: settings.egress_max_attempts,
                reconnect_timeout: settings.egress_reconnect_timeout,
                ..RotationOptions::default()
            },
        )
        .with_events(tx);
        match rotator.prepare().await {
            Ok(ip) => eprintln!("downloading through exit IP {ip}"),
            // Downloads will wait for an IP to rest enough.
            Err(RotateError::Exhausted) => {}
            Err(e) => {
                return Err(
                    format!("the VPN is not ready: {e}; check `docker compose logs vpn`").into(),
                );
            }
        }
        Ok(Some(Arc::new(rotator)))
    }

    pub fn api(&self) -> Result<Arc<Api>, Error> {
        let mut config = ApiConfig::default();
        if let Some(url) = &self.api_url {
            config.api_url = url.trim_end_matches('/').to_owned();
        }
        if let Some(key) = &self.settings.app_key {
            config.app_key = key.clone();
        }
        Ok(Arc::new(MegaApi::new(ReqwestTransport::new()?, config)))
    }

    /// The unlocked vault, asking for the master password when one is set.
    pub fn vault(&self) -> Result<Vault, Error> {
        if !self.store.has_master_password()? {
            return Ok(self.store.unlock(None)?);
        }
        let password = secret(MASTER_PASSWORD_ENV, "Master password: ")?;
        Ok(self.store.unlock(Some(&password))?)
    }

    /// A session for a stored account: the cached one, or a fresh login
    /// from the stored credentials (which is then cached).
    pub async fn session(&self, api: &Api, email: &str) -> Result<Session, Error> {
        let email = session::normalize_email(email);
        let vault = self.vault()?;
        if let Some(session) = self.store.session(&vault, &email)? {
            api.set_session_id(Some(session.sid.clone()));
            // A session invalidated elsewhere (logout, password change) is
            // replaced by a fresh login from the stored credentials.
            match api.call(serde_json::json!({"a": "uq"})).await {
                Err(ApiError::Mega(ErrorCode::BadSession)) => {
                    api.set_session_id(None);
                    self.store.delete_session(&email)?;
                }
                _ => return Ok(session),
            }
        }
        let credentials = self
            .store
            .account(&vault, &email)?
            .ok_or_else(|| format!("no stored account {email}: run `megaquarry login {email}`"))?;
        let session = match session::login_with_credentials(api, &credentials, None).await {
            Err(LoginError::MfaRequired) => {
                let code = prompt("Two-factor code: ")?;
                session::login_with_credentials(api, &credentials, Some(&code)).await?
            }
            other => other?,
        };
        self.store.save_session(&vault, &session)?;
        Ok(session)
    }
}

/// A secret from an environment variable, or prompted for on a terminal.
pub fn secret(env: &str, label: &str) -> Result<String, Error> {
    if let Ok(value) = std::env::var(env) {
        return Ok(value);
    }
    if !std::io::stdin().is_terminal() {
        return Err(format!("no terminal to ask for it: set {env}").into());
    }
    Ok(rpassword::prompt_password(label)?)
}

/// A visible answer read from the terminal.
pub fn prompt(label: &str) -> Result<String, Error> {
    if !std::io::stdin().is_terminal() {
        return Err(format!("{} needs a terminal", label.trim_end_matches([':', ' '])).into());
    }
    eprint!("{label}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Joins a `/`-separated remote path below `base`. Only plain name
/// components are kept, so a remote name can never escape `base` (no `..`,
/// roots, drive prefixes or embedded separators on any platform).
pub fn local_path(base: &Path, remote: &str) -> PathBuf {
    remote
        .split('/')
        .filter(|part| {
            let mut components = Path::new(part).components();
            matches!(
                (components.next(), components.next()),
                (Some(std::path::Component::Normal(_)), None)
            ) && !part.contains(['\\', ':'])
        })
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// One line for the user about a rotation.
fn describe(event: &RotationEvent) -> String {
    match event {
        RotationEvent::QuotaHit { ip, cooldown } => format!(
            "quota hit on {}, rotating… (it rests {} min)",
            ip.as_deref().unwrap_or("the current exit IP"),
            cooldown.as_secs().div_ceil(60)
        ),
        RotationEvent::SkippedCooling { ip } => format!("{ip} is still resting, reconnecting…"),
        RotationEvent::Rotated { ip, cooling } => format!("now on {ip} (cooling: {cooling})"),
        RotationEvent::Exhausted { cooling } => {
            format!("every exit IP tried is resting (cooling: {cooling}); downloads wait")
        }
        RotationEvent::Unavailable { error } => format!("VPN control problem: {error}"),
    }
}
