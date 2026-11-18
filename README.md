nologin
=======

Lists accounts on *nix systems whose login shell blocks interactive login
(`nologin` or `false`, at any path, e.g. `/sbin/nologin`, `/usr/sbin/nologin`,
`/usr/bin/false`).

With `--locked`, accounts that are locked (`passwd -l`, or a `*`/`!!`
password) or expired (`chage -E`) in the shadow file are listed too, even if
they have a normal shell.

## Build

    cargo build --release

## Usage

    nologin              # query the system user database (getpwent), including
                         # LDAP/SSSD/NIS/Directory Services accounts
    nologin /etc/passwd  # parse a passwd-format file instead
    sudo nologin --locked                # also check /etc/shadow (Linux)
    nologin --shadow shadow.txt pw.txt   # check copies of the files

Prints one user name per line. With `--locked`, each line is the user name, a
tab, and the comma-separated reasons it was listed:

    daemon	nologin,locked
    bob	locked
    carol	expired

`--locked` reads `/etc/shadow`, which usually requires root. macOS has no
shadow file, so use `--shadow` with a file there or run it on Linux.

## Test

    cargo test
