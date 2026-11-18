nologin
=======

Lists accounts on *nix systems whose login shell blocks interactive login
(`nologin` or `false`, at any path, e.g. `/sbin/nologin`, `/usr/sbin/nologin`,
`/usr/bin/false`).

Note: this checks the login shell only. Accounts locked with `passwd -l` or
expired accounts that still have a normal shell are not reported.

## Build

    cargo build --release

## Usage

    nologin              # query the system user database (getpwent), including
                         # LDAP/SSSD/NIS/Directory Services accounts
    nologin /etc/passwd  # parse a passwd-format file instead

Prints one user name per line.

## Test

    cargo test
