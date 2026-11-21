//! The README's settings table and `KNOWN_SETTINGS` list the same keys.

use std::collections::BTreeSet;

use megaquarry_core::store::KNOWN_SETTINGS;

const README: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md");

/// Keys of the table rows (`| `key` | ...`) in the `## Configuration` section.
fn configuration_keys(readme: &str) -> BTreeSet<&str> {
    readme
        .lines()
        .skip_while(|line| line.trim_end() != "## Configuration")
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|row| row.split_once('`').map(|(key, _)| key))
        .collect()
}

#[test]
fn readme_settings_table_matches_known_settings() {
    let readme = std::fs::read_to_string(README)
        .unwrap_or_else(|error| panic!("cannot read {README}: {error}"));
    let documented = configuration_keys(&readme);
    assert!(
        !documented.is_empty(),
        "README.md has no settings table under `## Configuration`"
    );

    let known: BTreeSet<&str> = KNOWN_SETTINGS.iter().map(|setting| setting.key).collect();
    let missing: Vec<&str> = known.difference(&documented).copied().collect();
    let unknown: Vec<&str> = documented.difference(&known).copied().collect();
    assert!(
        missing.is_empty() && unknown.is_empty(),
        "the README settings table and KNOWN_SETTINGS differ\n  \
         missing from the README: {missing:?}\n  \
         listed in the README but not a setting: {unknown:?}"
    );
}
