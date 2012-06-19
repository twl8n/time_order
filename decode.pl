#!/usr/bin/perl

sub mktmp
{
    my $msg = $_[0];
    my $fn = $_[1];
    open(OUT, ">", $fn);
    print OUT $msg;
    close(OUT);
}

use strict;

main:
{
    my $str = $ARGV[0];

    $str =~ m/(.*) (-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----.*)/s;
    my $enc = $1;
    my $key = $2;

    mktmp($enc, "/tmp/decodeme.base64");
    `openssl enc -base64 -d -in /tmp/decodeme.base64 -out /tmp/decodeme.dat`;

    $enc = `cat /tmp/decodeme.dat`;
    chomp($enc);
    
    mktmp($enc, "/tmp/tmp.enc");
    mktmp($key, "/tmp/time_order.pub");
    `openssl rsautl -verify -inkey /tmp/time_order.pub -pubin -in /tmp/tmp.enc -out /tmp/decrypted.txt`;
    print `cat /tmp/decrypted.txt`;
}
