//! User-facing console output facade: quiet-gating in one place.
//!
//! Tracing stays for diagnostics; anything a human reads goes through [`Ui`].
#[derive(Debug, Clone, Copy)]
pub struct Ui {
    quiet: bool,
}

impl Ui {
    pub fn new(quiet: bool) -> Self {
        Self { quiet }
    }

    /// Whether user-facing lines print (false in quiet mode).
    pub fn should_print(&self) -> bool {
        !self.quiet
    }

    /// Print a line unless quiet.
    pub fn line(&self, msg: impl AsRef<str>) {
        if self.should_print() {
            println!("{}", msg.as_ref());
        }
    }

    /// Print a line even when quiet (errors, final verdicts, machine output).
    pub fn emit(&self, msg: impl AsRef<str>) {
        println!("{}", msg.as_ref());
    }

    /// Progress chatter on stderr unless quiet (keeps stdout clean for pipes).
    pub fn status(&self, msg: impl AsRef<str>) {
        if self.should_print() {
            eprintln!("{}", msg.as_ref());
        }
    }

    /// Errors on stderr, even when quiet.
    pub fn error(&self, msg: impl AsRef<str>) {
        eprintln!("{}", msg.as_ref());
    }
}

/// Whether colored output is allowed (disabled by the NO_COLOR convention).
pub fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

/// Yellow stderr warning honoring NO_COLOR, for deep library paths where no
/// Ui instance is available.
pub fn warn_yellow(msg: impl AsRef<str>) {
    if use_color() {
        eprintln!("\u{1B}[33m[SCANNER] {}\u{1B}[0m", msg.as_ref());
    } else {
        eprintln!("[SCANNER] {}", msg.as_ref());
    }
}
