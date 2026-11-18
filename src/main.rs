//! List accounts whose login shell blocks interactive login.
//!
//! With no file argument, accounts come from the system user database via
//! `getpwent(3)`, which includes LDAP/SSSD/NIS/Directory Services users.
//! With a file argument, that file is parsed in `/etc/passwd` format.
//!
//! With `--locked`, accounts that are locked or expired in a shadow file are
//! reported too, each with the reasons it was listed.

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, io};

/// Shell basenames that deny interactive login.
const NOLOGIN_SHELLS: &[&str] = &["nologin", "false"];

const DEFAULT_SHADOW: &str = "/etc/shadow";

const USAGE: &str = "\
Usage: nologin [OPTIONS] [PASSWD_FILE]

List accounts whose login shell is nologin or false. Without PASSWD_FILE,
accounts come from the system user database (including LDAP/SSSD/NIS).

Options:
      --locked         Also list accounts locked or expired in the shadow
                       file, printing each name with its reasons
                       (nologin, locked, expired), tab-separated
      --shadow FILE    Shadow file for --locked [default: /etc/shadow];
                       implies --locked
  -h, --help           Print help
  -V, --version        Print version";

struct Account {
    name: String,
    shell: String,
}

#[derive(Debug, Default, PartialEq)]
struct ShadowStatus {
    locked: bool,
    expired: bool,
}

#[derive(Debug, Default, PartialEq)]
struct Options {
    passwd: Option<String>,
    shadow: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Command {
    Run(Options),
    Help,
    Version,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut opts = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--locked" => {
                opts.shadow
                    .get_or_insert_with(|| DEFAULT_SHADOW.to_string());
            }
            "--shadow" => {
                let path = args.next().ok_or("--shadow requires a file")?;
                opts.shadow = Some(path);
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(format!("unknown option '{s}'"));
            }
            _ if opts.passwd.is_some() => {
                return Err(format!("unexpected argument '{arg}'"));
            }
            _ => opts.passwd = Some(arg),
        }
    }
    Ok(Command::Run(opts))
}

fn is_nologin_shell(shell: &str) -> bool {
    let name = Path::new(shell)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    NOLOGIN_SHELLS.contains(&name)
}

/// Returns the account on a passwd line.
/// Blank lines, comments and malformed lines are skipped.
fn parse_passwd_line(line: &str) -> Option<Account> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = line.split(':').collect();
    match fields.as_slice() {
        [name, _, _, _, _, _, shell] => Some(Account {
            name: name.to_string(),
            shell: shell.to_string(),
        }),
        _ => None,
    }
}

/// Returns the user name and status on a shadow line.
/// Blank lines, comments and malformed lines are skipped.
fn parse_shadow_line(line: &str, today: i64) -> Option<(&str, ShadowStatus)> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 2 {
        return None;
    }
    // `passwd -l` prefixes the hash with '!'; '*' and '!!' mean no usable
    // password was ever set. All of them block password login.
    let locked = fields[1].starts_with('!') || fields[1].starts_with('*');
    // Expiry is in days since the epoch. shadow(5) calls 0 ambiguous, but
    // `chage -E 0` is the usual way to disable an account, so it counts.
    let expired = fields
        .get(7)
        .and_then(|f| f.parse::<i64>().ok())
        .is_some_and(|day| day <= today);
    Some((fields[0], ShadowStatus { locked, expired }))
}

fn accounts_from_file(path: &str) -> io::Result<Vec<Account>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents.lines().filter_map(parse_passwd_line).collect())
}

fn accounts_from_system() -> Vec<Account> {
    let mut accounts = Vec::new();
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
            let name = CStr::from_ptr((*pw).pw_name).to_string_lossy();
            if seen.insert(name.to_string()) {
                let shell = CStr::from_ptr((*pw).pw_shell).to_string_lossy();
                accounts.push(Account {
                    name: name.into_owned(),
                    shell: shell.into_owned(),
                });
            }
        }
        libc::endpwent();
    }
    accounts
}

fn shadow_from_file(path: &str, today: i64) -> io::Result<HashMap<String, ShadowStatus>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents
        .lines()
        .filter_map(|line| parse_shadow_line(line, today))
        .map(|(name, status)| (name.to_string(), status))
        .collect())
}

fn days_since_epoch() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86_400) as i64
}

/// Reasons an account is disabled, in output order.
fn reasons(account: &Account, status: Option<&ShadowStatus>) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if is_nologin_shell(&account.shell) {
        reasons.push("nologin");
    }
    if let Some(status) = status {
        if status.locked {
            reasons.push("locked");
        }
        if status.expired {
            reasons.push("expired");
        }
    }
    reasons
}

fn run(opts: Options) -> Result<(), String> {
    let accounts = match &opts.passwd {
        Some(path) => accounts_from_file(path).map_err(|e| format!("{path}: {e}"))?,
        None => accounts_from_system(),
    };

    let Some(shadow_path) = &opts.shadow else {
        for account in accounts.iter().filter(|a| is_nologin_shell(&a.shell)) {
            println!("{}", account.name);
        }
        return Ok(());
    };

    let shadow = shadow_from_file(shadow_path, days_since_epoch()).map_err(|e| {
        let hint = if e.kind() == io::ErrorKind::PermissionDenied {
            " (reading it usually requires root)"
        } else {
            ""
        };
        format!("{shadow_path}: {e}{hint}")
    })?;
    for account in &accounts {
        let reasons = reasons(account, shadow.get(&account.name));
        if !reasons.is_empty() {
            println!("{}\t{}", account.name, reasons.join(","));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Ok(Command::Help) => println!("{USAGE}"),
        Ok(Command::Version) => println!("nologin {}", env!("CARGO_PKG_VERSION")),
        Ok(Command::Run(opts)) => {
            if let Err(e) = run(opts) {
                eprintln!("nologin: {e}");
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("nologin: {e}\nTry 'nologin --help' for more information.");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Command, String> {
        parse_args(list.iter().map(|s| s.to_string()))
    }

    fn account(shell: &str) -> Account {
        Account {
            name: "u".to_string(),
            shell: shell.to_string(),
        }
    }

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
        let acct = parse_passwd_line("daemon:x:1:1::/:/usr/sbin/nologin").unwrap();
        assert_eq!(acct.name, "daemon");
        assert_eq!(acct.shell, "/usr/sbin/nologin");
        // Empty shell field means /bin/sh.
        let acct = parse_passwd_line("old:x:2:2::/home/old:").unwrap();
        assert_eq!(acct.shell, "");
        assert!(parse_passwd_line("").is_none());
        assert!(parse_passwd_line("# nobody:x:3:3::/:/bin/false").is_none());
        assert!(parse_passwd_line("short:x:4").is_none());
    }

    #[test]
    fn parses_shadow_lines() {
        let today = 20_000;
        let status = |line| parse_shadow_line(line, today).map(|(_, s)| s);
        let active = ShadowStatus::default();
        let locked = ShadowStatus {
            locked: true,
            expired: false,
        };
        let expired = ShadowStatus {
            locked: false,
            expired: true,
        };

        assert_eq!(status("alice:$6$hash:19000:0:99999:7:::"), Some(active));
        assert_eq!(status("bob:!$6$hash:19000:0:99999:7:::"), Some(locked));
        assert_eq!(
            status("svc:*:19000:0:99999:7:::"),
            Some(ShadowStatus {
                locked: true,
                expired: false
            })
        );
        assert_eq!(
            status("carol:$6$hash:19000:0:99999:7::20000:"),
            Some(expired)
        );
        assert_eq!(
            status("dave:$6$hash:19000:0:99999:7::0:"),
            Some(ShadowStatus {
                locked: false,
                expired: true
            })
        );
        assert_eq!(
            status("erin:$6$hash:19000:0:99999:7::20001:"),
            Some(ShadowStatus::default())
        );
        // Empty password: login without a password is possible, not locked.
        assert_eq!(status("frank::19000::::::"), Some(ShadowStatus::default()));
        assert_eq!(status(""), None);
        assert_eq!(status("# comment"), None);
        assert_eq!(status("nocolon"), None);
    }

    #[test]
    fn combines_reasons() {
        let both = ShadowStatus {
            locked: true,
            expired: true,
        };
        assert_eq!(
            reasons(&account("/sbin/nologin"), Some(&both)),
            ["nologin", "locked", "expired"]
        );
        assert_eq!(reasons(&account("/bin/false"), None), ["nologin"]);
        assert!(reasons(&account("/bin/bash"), Some(&ShadowStatus::default())).is_empty());
    }

    #[test]
    fn parses_options() {
        assert_eq!(args(&[]), Ok(Command::Run(Options::default())));
        assert_eq!(args(&["-h"]), Ok(Command::Help));
        assert_eq!(args(&["--version"]), Ok(Command::Version));
        assert_eq!(
            args(&["--locked", "pw"]),
            Ok(Command::Run(Options {
                passwd: Some("pw".into()),
                shadow: Some(DEFAULT_SHADOW.into()),
            }))
        );
        assert_eq!(
            args(&["--shadow", "sh", "--locked"]),
            Ok(Command::Run(Options {
                passwd: None,
                shadow: Some("sh".into()),
            }))
        );
        assert!(args(&["--shadow"]).is_err());
        assert!(args(&["--bogus"]).is_err());
        assert!(args(&["a", "b"]).is_err());
    }
}
