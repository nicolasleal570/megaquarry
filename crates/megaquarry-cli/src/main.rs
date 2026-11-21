//! `megaquarry`: command-line driver for the megaquarry core.

mod commands;
mod context;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Download and upload MEGA files from the command line.
#[derive(Debug, Parser)]
#[command(name = "megaquarry", version, about, long_about = None)]
struct Cli {
    /// Data directory (database and state). Default: the platform data dir.
    #[arg(long, global = true, env = "MEGAQUARRY_HOME")]
    home: Option<PathBuf>,

    /// MEGA API endpoint (for testing against another server).
    #[arg(long, global = true, env = "MEGAQUARRY_API_URL", hide = true)]
    api_url: Option<String>,

    /// gluetun control server URL (e.g. http://127.0.0.1:8000). Enables exit
    /// IP rotation when a download hits MEGA's transfer quota.
    #[arg(long, global = true, env = "MEGAQUARRY_EGRESS_URL")]
    egress_url: Option<String>,

    /// File holding the gluetun control API key (needed with --egress-url).
    #[arg(long, global = true, env = "MEGAQUARRY_EGRESS_KEY_FILE")]
    egress_key_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Log into a MEGA account and remember it.
    ///
    /// The password is read from MEGAQUARRY_PASSWORD or prompted for. Only
    /// the derived key is stored, never the password.
    Login {
        email: String,
        /// Two-factor authentication code.
        #[arg(long)]
        mfa: Option<String>,
    },
    /// Forget a stored account and its session.
    Logout { email: String },
    /// List stored accounts.
    Accounts,
    /// List the files a link points to.
    Ls { link: String },
    /// Queue the files of one or more links and download them.
    Download {
        #[arg(required = true)]
        links: Vec<String>,
        /// Output directory (default: the `default_down_dir` setting).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Only add the files to the queue.
        #[arg(long)]
        no_start: bool,
    },
    /// Queue local files or folders and upload them to an account.
    Upload {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Account to upload to.
        #[arg(long)]
        account: String,
        /// Remote folder handle (default: the account's Cloud Drive).
        #[arg(long)]
        to: Option<String>,
        /// Only add the files to the queue.
        #[arg(long)]
        no_start: bool,
    },
    /// Inspect and control the transfer queue.
    #[command(subcommand)]
    Queue(QueueCommand),
    /// Read and change settings.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Encrypt stored accounts with a master password.
    #[command(subcommand)]
    MasterPassword(MasterPasswordCommand),
}

#[derive(Debug, Subcommand)]
enum QueueCommand {
    /// Show queued transfers.
    List,
    /// Run the queue until it is empty (Ctrl-C stops and keeps the queue).
    Run {
        /// Account used for uploads in the queue.
        #[arg(long)]
        account: Option<String>,
    },
    /// Keep an entry in the queue without running it.
    Pause { id: i64 },
    /// Allow a paused or failed entry to run again.
    Resume { id: i64 },
    /// Allow every failed entry to run again.
    Retry,
    /// Remove an entry from the queue.
    Remove { id: i64 },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Show every setting with its value.
    List,
    /// Show one setting.
    Get { key: String },
    /// Change a setting.
    Set { key: String, value: String },
    /// Reset a setting to its default.
    Unset { key: String },
}

#[derive(Debug, Subcommand)]
enum MasterPasswordCommand {
    /// Set or change the master password (MEGAQUARRY_NEW_MASTER_PASSWORD or prompt).
    Set,
    /// Remove the master password and store accounts unencrypted.
    Remove,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
