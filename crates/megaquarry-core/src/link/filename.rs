const MAX_CHARS: usize = 250;
/// An extension is kept on truncation when its dot is within the last 16 chars.
const MAX_EXTENSION_CHARS: usize = 16;

/// Makes a remote node name safe to use as a local file name.
///
/// Removes path separators (and the
/// characters Windows forbids, on Windows), collapses runs of dots, strips
/// control characters, trims, and caps the length at 250 characters while
/// keeping a short extension.
pub fn clean_filename(name: &str) -> String {
    let forbidden: &[char] = if cfg!(windows) {
        &['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    } else {
        &['/']
    };

    let mut cleaned = String::with_capacity(name.len());
    for c in name.chars() {
        if forbidden.contains(&c) || c.is_ascii_control() {
            continue;
        }
        if c == '.' && cleaned.ends_with('.') {
            continue;
        }
        cleaned.push(c);
    }
    let mut cleaned = cleaned.trim().to_owned();

    if cfg!(windows) {
        cleaned = cleaned.trim_end_matches(['.', ' ']).to_owned();
    }

    let len = cleaned.chars().count();
    if len > MAX_CHARS {
        let extension = cleaned
            .rfind('.')
            .filter(|&dot| cleaned[dot..].chars().count() < MAX_EXTENSION_CHARS)
            .map(|dot| cleaned[dot..].to_owned())
            .unwrap_or_default();
        let base_len = cleaned.len() - extension.len();
        let keep = MAX_CHARS.saturating_sub(extension.chars().count()).max(1);
        let base: String = cleaned[..base_len].chars().take(keep).collect();
        cleaned = base + &extension;
    }
    cleaned
}
