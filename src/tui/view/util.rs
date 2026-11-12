use unicode_width_shim::width;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn spinner(tick: u64) -> &'static str {
    SPINNER[(tick as usize) % SPINNER.len()]
}

/// Cuts `text` to `max` display columns, adding `…` when shortened.
pub fn fit(text: &str, max: usize) -> String {
    if width(text) <= max {
        return text.to_owned();
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

pub fn bar(done: u64, total: u64, width: usize) -> String {
    let ratio = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    let filled = (ratio * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub fn seconds(d: std::time::Duration) -> String {
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
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(bar(1, 2, 4), "██░░");
    }
}
