//! `megaquarry`: command-line driver for the megaquarry core.

mod commands;
mod context;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::context::{Failure, exit};

const EXIT_CODES: &str = "\
Exit codes:
  0    success
  1    error
  2    bad usage or invalid value
  3    another transfer is already running
  4    the run finished but some transfers failed
  130  interrupted (Ctrl-C)";

const DOWNLOAD_EXAMPLES: &str = "\
Examples:
  megaquarry download 'https://mega.nz/folder/XXXX#KEY' -o ~/Downloads
  megaquarry download --no-start 'https://mega.nz/file/XXXX#KEY' 'https://mega.nz/file/YYYY#KEY'
  megaquarry queue run";

const LS_EXAMPLES: &str = "\
Examples:
  megaquarry ls 'https://mega.nz/folder/XXXX#KEY'
  megaquarry ls --json 'https://mega.nz/folder/XXXX#KEY' | jq '.total_size'";

const UPLOAD_EXAMPLES: &str = "\
Examples:
  megaquarry upload ./photos
  megaquarry upload report.pdf --account you@example.com --public-link
  megaquarry upload ./backup --to FOLDER_HANDLE --no-start";

const QUEUE_EXAMPLES: &str = "\
Examples:
  megaquarry queue list
  megaquarry queue pause 3
  megaquarry queue run --account you@example.com";

/// Download and upload MEGA files from the command line.
#[derive(Debug, Parser)]
#[command(
    name = "megaquarry",
    version,
    about = "Download and upload MEGA files from the command line.",
    long_about = None,
    after_help = EXIT_CODES
)]
struct Cli {
    /// Data directory (database and state). Default: the platform data dir.
    #[arg(long, global = true, env = "MEGAQUARRY_HOME")]
    home: Option<PathBuf>,

    /// MEGA API endpoint (for testing against another server).
    #[arg(long, global = true, env = "MEGAQUARRY_API_URL", hide = true)]
    api_url: Option<String>,

    /// Hide progress; errors, warnings, results and the final summary stay.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

/// Exit IP rotation through gluetun (only for commands that download).
#[derive(Debug, Default, Args)]
struct EgressArgs {
    /// gluetun control server URL (e.g. http://127.0.0.1:8000). Enables exit
    /// IP rotation when a download hits MEGA's transfer quota.
    #[arg(long, env = "MEGAQUARRY_EGRESS_URL")]
    egress_url: Option<String>,

    /// File holding the gluetun control API key (needed with --egress-url).
    #[arg(long, env = "MEGAQUARRY_EGRESS_KEY_FILE")]
    egress_key_file: Option<PathBuf>,
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
    Accounts {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List the files a link points to.
    #[command(after_help = LS_EXAMPLES)]
    Ls {
        link: String,
        /// Print JSON instead of text (sizes in bytes).
        #[arg(long)]
        json: bool,
    },
    /// Queue the files of one or more links and download them.
    #[command(after_help = DOWNLOAD_EXAMPLES)]
    Download {
        #[arg(required = true)]
        links: Vec<String>,
        /// Output directory (default: the `download_dir` setting, `.`).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Only add the files to the queue.
        #[arg(long)]
        no_start: bool,
        #[command(flatten)]
        egress: EgressArgs,
    },
    /// Queue local files or folders and upload them to an account.
    #[command(after_help = UPLOAD_EXAMPLES)]
    Upload {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Account to upload to (default: the only stored account).
        #[arg(long)]
        account: Option<String>,
        /// Remote folder handle (default: the account's Cloud Drive).
        #[arg(long)]
        to: Option<String>,
        /// Create and print a public link for each uploaded file.
        #[arg(long)]
        public_link: bool,
        /// Only add the files to the queue.
        #[arg(long)]
        no_start: bool,
    },
    /// Inspect and control the transfer queue.
    #[command(subcommand, after_help = QUEUE_EXAMPLES)]
    Queue(QueueCommand),
    /// Read and change settings.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Encrypt stored accounts with a master password.
    #[command(subcommand)]
    MasterPassword(MasterPasswordCommand),
    /// Print a shell completion script.
    ///
    /// For example: megaquarry completions bash > ~/.local/share/bash-completion/completions/megaquarry
    Completions { shell: clap_complete::Shell },
}

#[derive(Debug, Subcommand)]
enum QueueCommand {
    /// Show queued transfers.
    List {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Run the queue until it is empty (Ctrl-C stops and keeps the queue).
    Run {
        /// Account used for uploads in the queue.
        #[arg(long)]
        account: Option<String>,
        #[command(flatten)]
        egress: EgressArgs,
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
    List {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Show one setting.
    Get {
        key: String,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
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
    Remove {
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::run(cli).await {
        Ok(code) => code,
        Err(error) => {
            let code = error
                .downcast_ref::<Failure>()
                .map_or(exit::ERROR, |failure| failure.code);
            eprintln!("error: {error}");
            ExitCode::from(code)
        }
    }
}
