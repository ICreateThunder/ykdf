//! Terminal helpers: colour detection, coloured warnings, and a deliberate
//! "type YES" confirmation for destructive actions.

use std::io::{self, IsTerminal, Write};
use std::sync::OnceLock;

const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Whether stderr should carry ANSI colour.
///
/// Honours `NO_COLOR` (any value disables) and `CLICOLOR_FORCE` (any non-zero
/// value forces), and otherwise enables colour only when stderr is a terminal
/// that is not `TERM=dumb`. Computed once and cached.
fn colour_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0") {
            return true;
        }
        io::stderr().is_terminal() && std::env::var("TERM").as_deref() != Ok("dumb")
    })
}

/// Print `msg` to stderr, in bold red when the terminal supports colour. The
/// caller supplies the whole line (including any "warning:" prefix).
pub(crate) fn warn(msg: &str) {
    if colour_enabled() {
        eprintln!("{BOLD}{RED}{msg}{RESET}");
    } else {
        eprintln!("{msg}");
    }
}

/// Prompt for a destructive action and require the operator to type `YES`
/// exactly (uppercase, no abbreviation). Any other input, EOF, or a read error
/// returns `false`. The prompt is shown in bold red when colour is available.
pub(crate) fn confirm_destructive(prompt: &str) -> bool {
    if colour_enabled() {
        eprint!("{BOLD}{RED}{prompt}{RESET}");
    } else {
        eprint!("{prompt}");
    }
    let _ = io::stderr().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "YES"
}
