//! Command implementations.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use megaquarry_core::adapters::http::{ReqwestDownloadTransport, ReqwestUploadTransport};
use megaquarry_core::chunk::{DOWNLOAD_CHUNK_MULTIPLIER, MAC_CHUNK_MULTIPLIER};
use megaquarry_core::download::{DownloadOptions, Downloader};
use megaquarry_core::egress::QuotaRotation;
use megaquarry_core::link::parse_link;
use megaquarry_core::public;
use megaquarry_core::queue::{self, MegaRunner, QueueEvent, QueueLimits, Scheduler};
use megaquarry_core::session::{self, LoginError, Session};
use megaquarry_core::store::{KNOWN_SETTINGS, QueueKind};
use megaquarry_core::throttle::RateLimiter;
use megaquarry_core::upload::{self, UploadOptions, Uploader};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::context::{
    ACCOUNT_PASSWORD_ENV, Api, Context, Egress, Error, NEW_MASTER_PASSWORD_ENV, local_path, prompt,
    secret,
};
use crate::{Cli, Command, ConfigCommand, MasterPasswordCommand, QueueCommand};

pub async fn run(cli: Cli) -> Result<ExitCode, Error> {
    let egress = Egress {
        url: cli.egress_url,
        key_file: cli.egress_key_file,
    };
    let ctx = Context::open(cli.home, cli.api_url, egress)?;
    match cli.command {
        Command::Login { email, mfa } => login(&ctx, &email, mfa).await,
        Command::Logout { email } => {
            ctx.store
                .delete_account(&session::normalize_email(&email))?;
            println!("forgot {email}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Accounts => {
            for email in ctx.store.account_emails()? {
                println!("{email}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Ls { link } => ls(&ctx, &link).await,
        Command::Download {
            links,
            output,
            no_start,
        } => download(&ctx, &links, output.as_deref(), no_start).await,
        Command::Upload {
            paths,
            account,
            to,
            no_start,
        } => upload(&ctx, &paths, &account, to, no_start).await,
        Command::Queue(command) => queue_command(&ctx, command).await,
        Command::Config(command) => config(&ctx, command),
        Command::MasterPassword(command) => master_password(&ctx, command),
    }
}

async fn login(ctx: &Context, email: &str, mfa: Option<String>) -> Result<ExitCode, Error> {
    let api = ctx.api()?;
    let password = secret(ACCOUNT_PASSWORD_ENV, "Password: ")?;
    let session = match session::login(&api, email, &password, mfa.as_deref()).await {
        Err(LoginError::MfaRequired) if mfa.is_none() => {
            let code = prompt("Two-factor code: ")?;
            session::login(&api, email, &password, Some(&code)).await?
        }
        other => other?,
    };
    let vault = ctx.vault()?;
    ctx.store.save_account(&vault, &session.credentials)?;
    ctx.store.save_session(&vault, &session)?;
    println!("logged in as {}", session.credentials.email);
    Ok(ExitCode::SUCCESS)
}

async fn ls(ctx: &Context, link: &str) -> Result<ExitCode, Error> {
    let api = ctx.api()?;
    let files = public::resolve(&api, &parse_link(link)?).await?;
    for file in &files {
        println!("{:>14}  {}", file.file.size, file.path);
    }
    let total: u64 = files.iter().map(|f| f.file.size).sum();
    println!("{} file(s), {total} bytes", files.len());
    Ok(ExitCode::SUCCESS)
}

async fn download(
    ctx: &Context,
    links: &[String],
    output: Option<&Path>,
    no_start: bool,
) -> Result<ExitCode, Error> {
    // Take the lock and check the VPN before anything reaches MEGA.
    let (lock, rotation) = if no_start {
        (None, None)
    } else {
        let lock = ctx.transfer_lock()?;
        let rotation = ctx
            .rotation(ctx.settings.download_account.is_some())
            .await?;
        (Some(lock), rotation)
    };
    let api = ctx.api()?;
    // Downloads through an account use its session for the URL requests.
    let session = match &ctx.settings.download_account {
        Some(account) => Some(ctx.session(&api, account).await?),
        None => None,
    };
    let base = output.unwrap_or(&ctx.settings.download_dir);
    let mut queued = 0;
    for text in links {
        let link = parse_link(text).map_err(|e| format!("{text}: {e}"))?;
        for file in public::resolve(&api, &link).await? {
            let destination = local_path(base, &file.path);
            ctx.store.enqueue(
                QueueKind::Download,
                &json!({
                    "link": file.file.link.to_url(),
                    "name": file.file.name,
                    "size": file.file.size,
                    "destination": destination.display().to_string(),
                }),
            )?;
            queued += 1;
        }
    }
    println!("queued {queued} file(s)");
    if no_start {
        return Ok(ExitCode::SUCCESS);
    }
    let code = run_queue(ctx, api, session, &[QueueKind::Download], rotation).await;
    drop(lock);
    code
}

async fn upload(
    ctx: &Context,
    paths: &[std::path::PathBuf],
    account: &str,
    to: Option<String>,
    no_start: bool,
) -> Result<ExitCode, Error> {
    let lock = if no_start {
        None
    } else {
        Some(ctx.transfer_lock()?)
    };
    let api = ctx.api()?;
    let session = ctx.session(&api, account).await?;
    let parent = match to {
        Some(handle) => handle,
        None => upload::root_handle(&api).await?,
    };
    let mut queued = 0;
    for path in paths {
        queued += enqueue_upload(ctx, &api, &session, path, &parent).await?;
    }
    println!("queued {queued} file(s)");
    if no_start {
        return Ok(ExitCode::SUCCESS);
    }
    let code = run_queue(ctx, api, Some(session), &[QueueKind::Upload], None).await;
    drop(lock);
    code
}

/// Queues a file, or mirrors a directory remotely and queues its files.
async fn enqueue_upload(
    ctx: &Context,
    api: &Api,
    session: &Session,
    path: &Path,
    parent: &str,
) -> Result<usize, Error> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.is_file() {
        ctx.store.enqueue(
            QueueKind::Upload,
            &json!({"path": path.display().to_string(), "parent": parent}),
        )?;
        return Ok(1);
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{}: cannot upload this path", path.display()))?;
    let folder = upload::create_folder(api, session, parent, &name).await?;
    let mut entries: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    let mut queued = 0;
    for entry in entries {
        queued += Box::pin(enqueue_upload(ctx, api, session, &entry.path(), &folder)).await?;
    }
    Ok(queued)
}

/// Runs the queue (entries of `kinds`) until empty; Ctrl-C cancels and
/// keeps the entries, a second Ctrl-C exits at once.
async fn run_queue(
    ctx: &Context,
    api: Arc<Api>,
    session: Option<Session>,
    kinds: &[QueueKind],
    rotation: Option<Arc<dyn QuotaRotation>>,
) -> Result<ExitCode, Error> {
    let settings = &ctx.settings;
    let limiter = |limit: Option<u64>| limit.map(|bps| Arc::new(RateLimiter::new(bps)));
    let mut downloader = Downloader::new(
        Arc::new(ReqwestDownloadTransport::new()?),
        limiter(settings.download_speed_limit),
        DownloadOptions {
            workers: if settings.multi_slot_downloads {
                settings.download_workers
            } else {
                1
            },
            chunk_multiplier: if settings.multi_slot_downloads {
                DOWNLOAD_CHUNK_MULTIPLIER
            } else {
                MAC_CHUNK_MULTIPLIER
            },
            verify: settings.verify_downloads,
            ..DownloadOptions::default()
        },
    );
    if let Some(rotation) = rotation {
        downloader = downloader.with_rotation(rotation);
    }
    let uploader = Uploader::new(
        Arc::new(ReqwestUploadTransport::new()?),
        limiter(settings.upload_speed_limit),
        UploadOptions {
            workers: settings.upload_workers,
            ..UploadOptions::default()
        },
    );
    let runner = Arc::new(MegaRunner::new(
        api,
        session,
        ctx.store.clone(),
        downloader,
        uploader,
        settings.generate_upload_links,
    ));
    let scheduler = Arc::new(
        Scheduler::new(
            ctx.store.clone(),
            runner,
            QueueLimits {
                max_downloads: settings.max_downloads,
                max_uploads: settings.max_uploads,
                ..QueueLimits::default()
            },
        )
        .only(kinds),
    );

    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("stopping; unfinished transfers stay queued (Ctrl-C again to quit now)");
                cancel.cancel();
            }
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        });
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let printer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                QueueEvent::Started { id, kind } => eprintln!("[{id}] started {kind:?}"),
                QueueEvent::Finished { id, summary } => println!("[{id}] {summary}"),
                QueueEvent::Retrying { id, error, after } => {
                    eprintln!("[{id}] {error}; retrying in {}s", after.as_secs());
                }
                QueueEvent::Failed { id, error } => eprintln!("[{id}] failed: {error}"),
                QueueEvent::Cancelled { id } => eprintln!("[{id}] stopped"),
            }
        }
    });
    let ticker = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                for (id, done, total) in scheduler.progress() {
                    if total > 0 {
                        eprintln!(
                            "[{id}] {:.1}% ({done}/{total})",
                            done as f64 * 100.0 / total as f64
                        );
                    }
                }
            }
        })
    };
    let report = scheduler.run(cancel, Some(tx)).await?;
    ticker.abort();
    let _ = printer.await;
    println!(
        "done: {} completed, {} failed, {} stopped",
        report.completed, report.failed, report.cancelled
    );
    Ok(if report.failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn queue_command(ctx: &Context, command: QueueCommand) -> Result<ExitCode, Error> {
    match command {
        QueueCommand::List => {
            for kind in [QueueKind::Download, QueueKind::Upload] {
                for entry in ctx.store.entries(kind)? {
                    let payload = &entry.payload;
                    let target = payload["destination"]
                        .as_str()
                        .or(payload["path"].as_str())
                        .unwrap_or("?");
                    let state = payload["state"].as_str().unwrap_or("queued");
                    let error = payload["error"]
                        .as_str()
                        .map(|e| format!("  ({e})"))
                        .unwrap_or_default();
                    let kind = match kind {
                        QueueKind::Download => "download",
                        QueueKind::Upload => "upload",
                    };
                    println!("{:>5}  {kind:<8}  {state:<7}  {target}{error}", entry.id);
                }
            }
        }
        QueueCommand::Run { account } => {
            let lock = ctx.transfer_lock()?;
            let through_account = account.is_some() || ctx.settings.download_account.is_some();
            let rotation = ctx.rotation(through_account).await?;
            let api = ctx.api()?;
            let session = match account {
                Some(email) => Some(ctx.session(&api, &email).await?),
                None => None,
            };
            let session = match (session, &ctx.settings.download_account) {
                (None, Some(account)) => Some(ctx.session(&api, account).await?),
                (session, _) => session,
            };
            // Uploads need an account; without one they wait in the queue.
            let kinds: &[QueueKind] = if session.is_some() {
                &[QueueKind::Download, QueueKind::Upload]
            } else {
                if !ctx.store.entries(QueueKind::Upload)?.is_empty() {
                    eprintln!("uploads stay queued: pass --account to run them");
                }
                &[QueueKind::Download]
            };
            let code = run_queue(ctx, api, session, kinds, rotation).await;
            drop(lock);
            return code;
        }
        QueueCommand::Pause { id } => queue::pause(&ctx.store, id)?,
        QueueCommand::Resume { id } => queue::requeue(&ctx.store, id)?,
        QueueCommand::Retry => {
            let count = queue::requeue_failed(&ctx.store)?;
            println!("requeued {count} failed transfer(s)");
        }
        QueueCommand::Remove { id } => ctx.store.remove_entry(id)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn known(key: &str) -> Result<&'static (&'static str, &'static str, &'static str), Error> {
    KNOWN_SETTINGS
        .iter()
        .find(|(k, _, _)| *k == key)
        .ok_or_else(|| format!("unknown setting `{key}` (see `megaquarry config list`)").into())
}

fn config(ctx: &Context, command: ConfigCommand) -> Result<ExitCode, Error> {
    match command {
        ConfigCommand::List => {
            for (key, default, meaning) in KNOWN_SETTINGS {
                let value = ctx.store.setting(key)?;
                let shown = value.as_deref().unwrap_or(default);
                let marker = if value.is_some() { "" } else { " (default)" };
                println!("{key} = {shown}{marker}    # {meaning}");
            }
        }
        ConfigCommand::Get { key } => {
            let (_, default, _) = known(&key)?;
            println!("{}", ctx.store.setting(&key)?.as_deref().unwrap_or(default));
        }
        ConfigCommand::Set { key, value } => {
            known(&key)?;
            ctx.store.set_setting(&key, &value)?;
        }
        ConfigCommand::Unset { key } => {
            known(&key)?;
            ctx.store.unset_setting(&key)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn master_password(ctx: &Context, command: MasterPasswordCommand) -> Result<ExitCode, Error> {
    let current = ctx.vault()?;
    match command {
        MasterPasswordCommand::Set => {
            let new = match std::env::var(NEW_MASTER_PASSWORD_ENV) {
                Ok(value) => value,
                Err(_) => {
                    let first = secret(NEW_MASTER_PASSWORD_ENV, "New master password: ")?;
                    let again = secret(NEW_MASTER_PASSWORD_ENV, "Repeat it: ")?;
                    if first != again {
                        return Err("the passwords do not match".into());
                    }
                    first
                }
            };
            if new.is_empty() {
                return Err(
                    "the master password cannot be empty (use `master-password remove`)".into(),
                );
            }
            ctx.store.set_master_password(&current, Some(&new))?;
            println!("master password set");
        }
        MasterPasswordCommand::Remove => {
            ctx.store.set_master_password(&current, None)?;
            println!("master password removed");
        }
    }
    Ok(ExitCode::SUCCESS)
}
