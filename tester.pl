#!/usr/bin/perl -w
use strict;

require "./set1/task02.fixed_xor.pl";

my $key = "414243444546474849505152535455565758596061626364656667686970";

open(my $fh1, '<', $ARGV[0]) or die 'bams';
my @messages;
while (<$fh1>) {
    chomp;
    push @messages,$_;
}

unlink $fh1;

my @ciphers = map {rox(unpack('H*',$_),$key)} @messages;

open(my $fh2, '>', './test.inputs/ttt_crypto') or die 'bams2';

map {print $fh2 $_."\n"} @ciphers;
