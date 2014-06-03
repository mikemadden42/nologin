#!/usr/bin/env perl

use 5.016;
use autodie;
use strict;
use warnings;

open( fh, '<', '/etc/passwd' ) or die "Cannot open file: $!";

while (<fh>) {
    chomp;

    next if /^#/;

    my @acct_data = split(':');

    if ( $acct_data[6] ne '/bin/sh' ) {
        say $acct_data[0];
    }
}

close fh;
