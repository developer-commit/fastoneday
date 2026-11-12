//! Text helpers for detection.

use std::collections::BTreeSet;

use crate::domain::PE_EXTENSIONS;

/// File names like `clfs.sys` or `win32kfull.sys` mentioned in free text.
pub fn file_names(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))) {
        let token = raw
            .trim_matches(|c: char| c == '.' || c == '-' || c == '_')
            .to_ascii_lowercase();
        let Some((stem, ext)) = token.rsplit_once('.') else {
            continue;
        };
        if stem.is_empty()
            || !stem.as_bytes()[0].is_ascii_alphanumeric()
            || ext == "mui"
            || !PE_EXTENSIONS.contains(&ext)
        {
            continue;
        }
        out.insert(token);
    }
    out
}

/// Lower-case words separated by single spaces, padded with spaces so that
/// `contains(" phrase ")` matches whole words only.
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push(' ');
    for word in text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        out.push_str(&word.to_ascii_lowercase());
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_binary_names_in_prose() {
        let names = file_names(
            "A flaw in CLFS.sys (and ntoskrnl.exe). Not readme.txt, not x.sys.mui, not .sys",
        );
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            vec!["clfs.sys", "ntoskrnl.exe"]
        );
    }

    #[test]
    fn normalizes_for_phrase_matching() {
        assert_eq!(normalize("Windows Win32K - GRFX"), " windows win32k grfx ");
    }
}
