use std::time::Duration;

use ratatui::{style::Style, text::Span};
use unicode_width_shim::width;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn spinner(tick: u64) -> &'static str {
    SPINNER[(tick as usize) % SPINNER.len()]
}

/// Display width of `text` in terminal columns.
pub fn columns(text: &str) -> usize {
    width(text)
}

/// Cuts `text` to `max` display columns, adding `…` when shortened.
pub fn fit(text: &str, max: usize) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let w = width(ch.encode_utf8(&mut [0; 4]));
        if used + w + 1 > max {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// Like [`fit`] but keeps the end (for paths): `…/cases/CVE-…/after`.
pub fn fit_left(text: &str, max: usize) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut kept: Vec<char> = Vec::new();
    let mut used = 0;
    for ch in text.chars().rev() {
        let w = width(ch.encode_utf8(&mut [0; 4]));
        if used + w + 1 > max {
            break;
        }
        kept.push(ch);
        used += w;
    }
    kept.reverse();
    format!("…{}", kept.into_iter().collect::<String>())
}

/// Splits `text` into spans, styling every case-insensitive occurrence of
/// any of `needles` (fzf-style match highlighting).
pub fn highlight<'a>(text: &str, needles: &[String], base: Style, hit: Style) -> Vec<Span<'a>> {
    let lower = text.to_lowercase();
    // Byte ranges of matches, computed on the lower-cased text; only safe to
    // map back when lower-casing kept every byte length (ASCII text).
    if lower.len() != text.len() || needles.iter().all(|n| n.is_empty()) {
        return vec![Span::styled(text.to_owned(), base)];
    }
    let mut marks = vec![false; text.len()];
    for needle in needles.iter().filter(|n| !n.is_empty()) {
        let needle = needle.to_lowercase();
        let mut from = 0;
        while let Some(at) = lower[from..].find(&needle) {
            let start = from + at;
            marks[start..start + needle.len()].fill(true);
            from = start + needle.len().max(1);
        }
    }
    let mut spans = Vec::new();
    let mut start = 0;
    for i in 1..=text.len() {
        let boundary = i == text.len() || marks[i] != marks[start];
        if boundary && text.is_char_boundary(start) && text.is_char_boundary(i) {
            let style = if marks[start] { hit } else { base };
            spans.push(Span::styled(text[start..i].to_owned(), style));
            start = i;
        }
    }
    spans
}

pub fn bytes(n: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    if n as f64 >= MB * 1024.0 {
        format!("{:.2} GB", n as f64 / (MB * 1024.0))
    } else if n as f64 >= MB {
        format!("{:.1} MB", n as f64 / MB)
    } else if n >= 1024 {
        format!("{} KB", n / 1024)
    } else {
        format!("{n} B")
    }
}

/// Transfer rate, e.g. `4.2 MB/s`.
pub fn rate(bytes_done: u64, elapsed: Duration) -> Option<String> {
    let secs = elapsed.as_secs_f64();
    (secs >= 0.5 && bytes_done > 0)
        .then(|| format!("{}/s", bytes((bytes_done as f64 / secs) as u64)))
}

pub fn bar(done: u64, total: u64, width: usize) -> String {
    let ratio = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    let filled = (ratio * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub fn seconds(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 {
        format!("{s:.1}s")
    } else {
        format!("{}m{:02}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

/// Display width without pulling in another crate: CJK and emoji count
/// double, everything else single.
mod unicode_width_shim {
    pub fn width(s: &str) -> usize {
        s.chars()
            .map(|c| {
                let cp = c as u32;
                if (0x1100..=0x115F).contains(&cp)
                    || (0x2E80..=0xA4CF).contains(&cp)
                    || (0xAC00..=0xD7A3).contains(&cp)
                    || (0xF900..=0xFAFF).contains(&cp)
                    || (0xFE30..=0xFE4F).contains(&cp)
                    || (0xFF00..=0xFF60).contains(&cp)
                    || (0x1F300..=0x1FAFF).contains(&cp)
                {
                    2
                } else {
                    1
                }
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fits_and_formats() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abc", 4), "abc");
        assert_eq!(fit_left("/a/b/cases/x", 8), "…cases/x");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(bar(1, 2, 4), "██░░");
        assert_eq!(
            rate(10 * 1024 * 1024, Duration::from_secs(2)).as_deref(),
            Some("5.0 MB/s")
        );
    }

    #[test]
    fn highlights_every_match() {
        let spans = highlight(
            "Windows NTFS Elevation",
            &["ntfs".into(), "ele".into()],
            Style::new(),
            Style::new().bold(),
        );
        let texts: Vec<String> = spans.iter().map(|s| s.content.to_string()).collect();
        assert_eq!(texts, ["Windows ", "NTFS", " ", "Ele", "vation"]);
    }
}
