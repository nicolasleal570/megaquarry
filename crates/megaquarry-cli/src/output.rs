//! Where the CLI writes: results on stdout, status and progress on stderr.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::sync::{Arc, Mutex};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

/// Writes results, status lines, warnings and (on a terminal) progress bars
/// without the bars and the text overwriting each other.
#[derive(Clone)]
pub struct Reporter {
    quiet: bool,
    /// Present when stderr is a terminal and progress is shown.
    bars: Option<MultiProgress>,
    active: Arc<Mutex<HashMap<i64, ProgressBar>>>,
}

impl Reporter {
    pub fn new(quiet: bool) -> Self {
        let bars = (!quiet && std::io::stderr().is_terminal()).then(MultiProgress::new);
        Self {
            quiet,
            bars,
            active: Arc::default(),
        }
    }

    /// Whether progress bars are drawn.
    pub fn shows_bars(&self) -> bool {
        self.bars.is_some()
    }

    /// A result on stdout, never hidden.
    pub fn result(&self, line: impl AsRef<str>) {
        self.around_bars(|| println!("{}", line.as_ref()));
    }

    /// Progress and status on stderr, hidden by `--quiet`.
    pub fn status(&self, line: impl AsRef<str>) {
        if !self.quiet {
            self.around_bars(|| eprintln!("{}", line.as_ref()));
        }
    }

    /// A warning or error on stderr, never hidden.
    pub fn warn(&self, line: impl AsRef<str>) {
        self.around_bars(|| eprintln!("{}", line.as_ref()));
    }

    /// Updates the bar of a transfer, creating it on first use.
    pub fn progress(&self, id: i64, done: u64, total: u64) {
        let Some(bars) = &self.bars else {
            return;
        };
        let mut active = self.active.lock().expect("progress bars lock");
        let bar = active.entry(id).or_insert_with(|| {
            let bar = bars.add(ProgressBar::new(total));
            bar.set_style(
                ProgressStyle::with_template(
                    "{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes} {binary_bytes_per_sec} eta {eta}",
                )
                .expect("valid progress template"),
            );
            bar.set_prefix(format!("[{id}]"));
            bar
        });
        bar.set_length(total);
        bar.set_position(done);
    }

    /// Removes the bar of a finished, failed or stopped transfer.
    pub fn finish(&self, id: i64) {
        if let Some(bar) = self.active.lock().expect("progress bars lock").remove(&id) {
            bar.finish_and_clear();
        }
    }

    fn around_bars(&self, print: impl FnOnce()) {
        match &self.bars {
            Some(bars) => bars.suspend(print),
            None => print(),
        }
    }
}

/// A size for people: `1000 B`, `4.9 KiB`, `1.4 GiB`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    // 1023.95 and up would print as "1024.0", so it moves to the next unit.
    while value >= 1023.95 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn sizes_use_binary_units_with_one_decimal() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(5000), "4.9 KiB");
        assert_eq!(human_size(1_048_575), "1.0 MiB");
        assert_eq!(human_size(1_503_238_553), "1.4 GiB");
        assert_eq!(human_size(53_687_091_200), "50.0 GiB");
    }
}
