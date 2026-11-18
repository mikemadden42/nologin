//! List accounts whose login shell blocks interactive login.
//!
//! With no arguments, accounts come from the system user database via
//! `getpwent(3)`, which includes LDAP/SSSD/NIS/Directory Services users.
//! With a file argument, that file is parsed in `/etc/passwd` format.

use std::collections::HashSet;
use std::ffi::CStr;
use std::path::Path;
use std::process::ExitCode;
use std::{env, fs};

/// Shell basenames that deny interactive login.
const NOLOGIN_SHELLS: &[&str] = &["nologin", "false"];

fn is_nologin_shell(shell: &str) -> bool {
    let name = Path::new(shell)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    NOLOGIN_SHELLS.contains(&name)
}

/// Returns the user name if a passwd line has a nologin shell.
/// Blank lines, comments and malformed lines are skipped.
fn nologin_user(line: &str) -> Option<&str> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = line.split(':').collect();
    match fields.as_slice() {
        [name, _, _, _, _, _, shell] if is_nologin_shell(shell) => Some(name),
        _ => None,
    }
}

fn users_from_file(path: &str) -> std::io::Result<Vec<String>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents
        .lines()
        .filter_map(nologin_user)
        .map(String::from)
        .collect())
}

fn users_from_system() -> Vec<String> {
    let mut users = Vec::new();
    // Some platforms (e.g. macOS) report the same account from several sources.
    let mut seen = HashSet::new();
    // SAFETY: getpwent's iteration state and returned buffer are process-global;
    // this program is single-threaded and copies each entry before the next call.
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() {
                break;
            }
            let shell = CStr::from_ptr((*pw).pw_shell).to_string_lossy();
            if is_nologin_shell(&shell) {
                let name = CStr::from_ptr((*pw).pw_name).to_string_lossy();
                if seen.insert(name.to_string()) {
                    users.push(name.into_owned());
                }
            }
        }
        libc::endpwent();
    }
    users
}

fn main() -> ExitCode {
    let users = match env::args().nth(1) {
        Some(path) => match users_from_file(&path) {
            Ok(users) => users,
            Err(e) => {
                eprintln!("nologin: {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => users_from_system(),
    };
    for user in users {
        println!("{user}");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_nologin_variants() {
        for shell in [
            "/sbin/nologin",
            "/usr/sbin/nologin",
            "/bin/false",
            "/usr/bin/false",
        ] {
            assert!(is_nologin_shell(shell), "{shell}");
        }
    }

    #[test]
    fn rejects_login_shells() {
        for shell in ["/bin/sh", "/bin/bash", "/usr/sbin/uucico", ""] {
            assert!(!is_nologin_shell(shell), "{shell}");
        }
    }

    #[test]
    fn parses_passwd_lines() {
        assert_eq!(
            nologin_user("daemon:x:1:1::/:/usr/sbin/nologin"),
            Some("daemon")
        );
        assert_eq!(nologin_user("root:x:0:0::/root:/bin/bash"), None);
        // Empty shell field means /bin/sh.
        assert_eq!(nologin_user("old:x:2:2::/home/old:"), None);
        assert_eq!(nologin_user(""), None);
        assert_eq!(nologin_user("# nobody:x:3:3::/:/bin/false"), None);
        assert_eq!(nologin_user("short:x:4"), None);
    }
}
