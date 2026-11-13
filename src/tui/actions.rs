//! Things the result screen can do outside the terminal UI.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use base64::Engine as _;

/// Opens `path` in the platform's file manager.
pub fn open_folder(path: &Path) -> std::io::Result<()> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    Command::new(program)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

/// Puts `text` on the clipboard with the OSC 52 escape sequence, which most
/// terminals (iTerm2, WezTerm, kitty, Windows Terminal, tmux with
/// `set-clipboard on`) honour — no clipboard library or display needed.
pub fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(osc52(text).as_bytes())?;
    out.flush()
}

fn osc52(text: &str) -> String {
    format!(
        "\x1b]52;c;{}\x07",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn encodes_osc52() {
        assert_eq!(super::osc52("hi"), "\x1b]52;c;aGk=\x07");
    }
}
