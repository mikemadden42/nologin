#!/usr/bin/env perl

use 5.010;
use autodie;
use strict;
use warnings;

open( my $fh, '<', '/etc/passwd' ) or die "Cannot open file: $!";

my $NOLOGIN = "/sbin/nologin";

while (<$fh>) {
    chomp;
    next if /^#/;
    my @acct_data = split(':');
    if ( $acct_data[6] eq $NOLOGIN ) {
        say $acct_data[0];
    }
}

close $fh;
