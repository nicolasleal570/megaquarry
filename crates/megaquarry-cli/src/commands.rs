//! Command implementations.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::CommandFactory;
use megaquarry_core::adapters::http::{ReqwestDownloadTransport, ReqwestUploadTransport};
use megaquarry_core::chunk::{DOWNLOAD_CHUNK_MULTIPLIER, MAC_CHUNK_MULTIPLIER};
use megaquarry_core::download::{DownloadOptions, Downloader};
use megaquarry_core::egress::QuotaRotation;
use megaquarry_core::link::parse_link;
use megaquarry_core::public;
use megaquarry_core::queue::{self, MegaRunner, QueueEvent, QueueLimits, Scheduler};
use megaquarry_core::session::{self, LoginError, Session};
use megaquarry_core::store::{
    KNOWN_SETTINGS, QueueKind, SettingSpec, StoreError, setting_spec, validate_setting,
};
use megaquarry_core::throttle::RateLimiter;
use megaquarry_core::upload::{self, UploadOptions, Uploader};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::context::{
    ACCOUNT_PASSWORD_ENV, Api, Context, Egress, Error, Failure, NEW_MASTER_PASSWORD_ENV, exit,
    local_path, prompt, secret,
};
use crate::output::{Reporter, human_size};
use crate::{Cli, Command, ConfigCommand, EgressArgs, MasterPasswordCommand, QueueCommand};

pub async fn run(cli: Cli) -> Result<ExitCode, Error> {
    // Completions need no data directory.
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "megaquarry",
            &mut std::io::stdout(),
        );
        return Ok(ExitCode::SUCCESS);
    }
    let egress = match &cli.command {
        Command::Download { egress, .. } | Command::Queue(QueueCommand::Run { egress, .. }) => {
            egress_of(egress)
        }
        _ => Egress::default(),
    };
    let ctx = Context::open(cli.home, cli.api_url, egress, Reporter::new(cli.quiet))?;
    match cli.command {
        Command::Login { email, mfa } => login(&ctx, &email, mfa).await,
        Command::Logout { email } => {
            ctx.store
                .delete_account(&session::normalize_email(&email))?;
            println!("forgot {email}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Accounts { json } => {
            let emails = ctx.store.account_emails()?;
            if json {
                let accounts: Vec<Value> = emails.iter().map(|e| json!({"email": e})).collect();
                print_json(&json!({"accounts": accounts}))?;
            } else {
                for email in emails {
                    println!("{email}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Ls { link, json } => ls(&ctx, &link, json).await,
        Command::Download {
            links,
            output,
            no_start,
            egress: _,
        } => download(&ctx, &links, output.as_deref(), no_start).await,
        Command::Upload {
            paths,
            account,
            to,
            public_link,
            no_start,
        } => {
            let account = ctx.upload_account(account)?;
            upload(&ctx, &paths, &account, to, public_link, no_start).await
        }
        Command::Queue(command) => queue_command(&ctx, command).await,
        Command::Config(command) => config(&ctx, command),
        Command::MasterPassword(command) => master_password(&ctx, command),
        Command::Completions { .. } => unreachable!("handled above"),
    }
}

fn egress_of(args: &EgressArgs) -> Egress {
    Egress {
        url: args.egress_url.clone(),
        key_file: args.egress_key_file.clone(),
    }
}

/// An unparsable link, with what valid links look like.
fn link_error(text: &str, error: impl std::fmt::Display) -> Error {
    format!(
        "{text}: {error} (links look like https://mega.nz/file/ID#KEY or https://mega.nz/folder/ID#KEY)"
    )
    .into()
}

fn print_json(value: &Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

async fn login(ctx: &Context, email: &str, mfa: Option<String>) -> Result<ExitCode, Error> {
    let api = ctx.api()?;
    let password = secret(ACCOUNT_PASSWORD_ENV, "Password: ")?;
    let session = match session::login(&api, email, &password, mfa.as_deref()).await {
        Err(LoginError::MfaRequired) if mfa.is_none() => {
            let code = prompt("Two-factor code: ")
                .map_err(|_| "this account needs a two-factor code: pass --mfa CODE")?;
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

async fn ls(ctx: &Context, link: &str, json: bool) -> Result<ExitCode, Error> {
    let api = ctx.api()?;
    let parsed = parse_link(link).map_err(|e| link_error(link, e))?;
    let files = public::resolve(&api, &parsed).await?;
    let total: u64 = files.iter().map(|f| f.file.size).sum();
    if json {
        let entries: Vec<Value> = files
            .iter()
            .map(|f| {
                json!({
                    "path": f.path,
                    "name": f.file.name,
                    "size": f.file.size,
                    "link": f.file.link.to_url(),
                })
            })
            .collect();
        print_json(&json!({"files": entries, "count": files.len(), "total_size": total}))?;
        return Ok(ExitCode::SUCCESS);
    }
    for file in &files {
        println!("{:>10}  {}", human_size(file.file.size), file.path);
    }
    println!("{} file(s), {}", files.len(), human_size(total));
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
        let link = parse_link(text).map_err(|e| link_error(text, e))?;
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
    ctx.reporter.result(format!("queued {queued} file(s)"));
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
    public_link: bool,
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
        queued += enqueue_upload(ctx, &api, &session, path, &parent, public_link).await?;
    }
    ctx.reporter.result(format!("queued {queued} file(s)"));
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
    public_link: bool,
) -> Result<usize, Error> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.is_file() {
        let mut entry = json!({"path": path.display().to_string(), "parent": parent});
        if public_link {
            entry["public_link"] = json!(true);
        }
        ctx.store.enqueue(QueueKind::Upload, &entry)?;
        return Ok(1);
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| {
            format!(
                "{}: cannot upload this path (pass a file or a folder)",
                path.display()
            )
        })?;
    let folder = upload::create_folder(api, session, parent, &name).await?;
    let mut entries: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    let mut queued = 0;
    for entry in entries {
        queued += Box::pin(enqueue_upload(
            ctx,
            api,
            session,
            &entry.path(),
            &folder,
            public_link,
        ))
        .await?;
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
        let reporter = ctx.reporter.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                reporter
                    .warn("stopping; unfinished transfers stay queued (Ctrl-C again to quit now)");
                cancel.cancel();
            }
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(exit::INTERRUPTED.into());
            }
        });
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let reporter = ctx.reporter.clone();
    let printer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                QueueEvent::Started { id, kind } => {
                    let kind = match kind {
                        QueueKind::Download => "download",
                        QueueKind::Upload => "upload",
                    };
                    reporter.status(format!("[{id}] started {kind}"));
                }
                QueueEvent::Finished { id, summary } => {
                    reporter.finish(id);
                    reporter.result(format!("[{id}] {summary}"));
                }
                QueueEvent::Retrying { id, error, after } => {
                    reporter.status(format!("[{id}] {error}; retrying in {}s", after.as_secs()));
                }
                QueueEvent::Failed { id, error } => {
                    reporter.finish(id);
                    reporter.warn(format!("[{id}] failed: {error}"));
                }
                QueueEvent::Cancelled { id } => {
                    reporter.finish(id);
                    reporter.status(format!("[{id}] stopped"));
                }
            }
        }
    });
    // Progress bars only on a terminal; logs get the lines above instead.
    let ticker = ctx.reporter.shows_bars().then(|| {
        let scheduler = scheduler.clone();
        let reporter = ctx.reporter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                for (id, done, total) in scheduler.progress() {
                    if total > 0 {
                        reporter.progress(id, done, total);
                    }
                }
            }
        })
    });
    let report = scheduler.run(cancel.clone(), Some(tx)).await?;
    if let Some(ticker) = ticker {
        ticker.abort();
    }
    let _ = printer.await;
    ctx.reporter.result(format!(
        "done: {} completed, {} failed, {} stopped",
        report.completed, report.failed, report.cancelled
    ));
    Ok(if cancel.is_cancelled() {
        ExitCode::from(exit::INTERRUPTED)
    } else if report.failed > 0 {
        ExitCode::from(exit::PARTIAL)
    } else {
        ExitCode::SUCCESS
    })
}

/// Names a missing queue entry and where to find the valid ids.
fn entry_error(id: i64) -> impl FnOnce(StoreError) -> Error {
    move |error| match error {
        StoreError::NotFound => format!("no queue entry {id} (see `megaquarry queue list`)").into(),
        other => other.into(),
    }
}

async fn queue_command(ctx: &Context, command: QueueCommand) -> Result<ExitCode, Error> {
    match command {
        QueueCommand::List { json } => {
            let mut entries = Vec::new();
            for kind in [QueueKind::Download, QueueKind::Upload] {
                for entry in ctx.store.entries(kind)? {
                    let payload = &entry.payload;
                    let target = payload["destination"]
                        .as_str()
                        .or(payload["path"].as_str())
                        .unwrap_or("?");
                    let kind = match kind {
                        QueueKind::Download => "download",
                        QueueKind::Upload => "upload",
                    };
                    entries.push(json!({
                        "id": entry.id,
                        "kind": kind,
                        "state": payload["state"].as_str().unwrap_or("queued"),
                        "target": target,
                        "error": payload["error"].as_str(),
                    }));
                }
            }
            if json {
                print_json(&json!({"entries": entries}))?;
            } else {
                for entry in &entries {
                    let error = entry["error"]
                        .as_str()
                        .map(|e| format!("  ({e})"))
                        .unwrap_or_default();
                    println!(
                        "{:>5}  {:<8}  {:<7}  {}{error}",
                        entry["id"].as_i64().unwrap_or_default(),
                        entry["kind"].as_str().unwrap_or_default(),
                        entry["state"].as_str().unwrap_or_default(),
                        entry["target"].as_str().unwrap_or_default(),
                    );
                }
            }
        }
        QueueCommand::Run { account, egress: _ } => {
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
                    ctx.reporter
                        .warn("uploads stay queued: pass --account EMAIL to run them");
                }
                &[QueueKind::Download]
            };
            let code = run_queue(ctx, api, session, kinds, rotation).await;
            drop(lock);
            return code;
        }
        QueueCommand::Pause { id } => queue::pause(&ctx.store, id).map_err(entry_error(id))?,
        QueueCommand::Resume { id } => queue::requeue(&ctx.store, id).map_err(entry_error(id))?,
        QueueCommand::Retry => {
            let count = queue::requeue_failed(&ctx.store)?;
            println!("requeued {count} failed transfer(s)");
        }
        QueueCommand::Remove { id } => ctx.store.remove_entry(id).map_err(entry_error(id))?,
    }
    Ok(ExitCode::SUCCESS)
}

/// A known setting, or a usage error naming where the keys are listed.
fn known(key: &str) -> Result<&'static SettingSpec, Error> {
    setting_spec(key).ok_or_else(|| {
        Failure::error(
            exit::USAGE,
            format!("unknown setting `{key}` (see `megaquarry config list`)"),
        )
    })
}

fn setting_json(ctx: &Context, spec: &SettingSpec) -> Result<Value, Error> {
    let stored = ctx.store.setting(spec.key)?;
    Ok(json!({
        "key": spec.key,
        "value": stored.as_deref().unwrap_or(spec.default),
        "default": spec.default,
        "is_default": stored.is_none(),
        "description": spec.meaning,
    }))
}

fn config(ctx: &Context, command: ConfigCommand) -> Result<ExitCode, Error> {
    match command {
        ConfigCommand::List { json } => {
            if json {
                let settings = KNOWN_SETTINGS
                    .iter()
                    .map(|spec| setting_json(ctx, spec))
                    .collect::<Result<Vec<_>, _>>()?;
                print_json(&json!({"settings": settings}))?;
            } else {
                for spec in KNOWN_SETTINGS {
                    let value = ctx.store.setting(spec.key)?;
                    let shown = value.as_deref().unwrap_or(spec.default);
                    let marker = if value.is_some() { "" } else { " (default)" };
                    println!("{} = {shown}{marker}    # {}", spec.key, spec.meaning);
                }
            }
        }
        ConfigCommand::Get { key, json } => {
            let spec = known(&key)?;
            if json {
                print_json(&setting_json(ctx, spec)?)?;
            } else {
                let value = ctx.store.setting(&key)?;
                println!("{}", value.as_deref().unwrap_or(spec.default));
            }
        }
        ConfigCommand::Set { key, value } => {
            known(&key)?;
            validate_setting(&key, &value)
                .map_err(|e| Failure::error(exit::USAGE, e.to_string()))?;
            ctx.store.set_setting(&key, value.trim())?;
        }
        ConfigCommand::Unset { key } => {
            known(&key)?;
            ctx.store.unset_setting(&key)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn master_password(ctx: &Context, command: MasterPasswordCommand) -> Result<ExitCode, Error> {
    match command {
        MasterPasswordCommand::Set => {
            let current = ctx.vault()?;
            let new = match std::env::var(NEW_MASTER_PASSWORD_ENV) {
                Ok(value) => value,
                Err(_) => {
                    let first = secret(NEW_MASTER_PASSWORD_ENV, "New master password: ")?;
                    let again = secret(NEW_MASTER_PASSWORD_ENV, "Repeat it: ")?;
                    if first != again {
                        return Err("the passwords do not match; run the command again".into());
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
        MasterPasswordCommand::Remove { yes } => {
            if !yes && std::io::stdin().is_terminal() {
                let answer =
                    prompt("Remove the master password and store accounts unencrypted? [y/N] ")?;
                if !matches!(answer.to_lowercase().as_str(), "y" | "yes") {
                    println!("kept the master password");
                    return Ok(ExitCode::SUCCESS);
                }
            }
            let current = ctx.vault()?;
            ctx.store.set_master_password(&current, None)?;
            println!("master password removed");
        }
    }
    Ok(ExitCode::SUCCESS)
}
