#!/usr/bin/perl
use strict;

# Task 9: Implement PKCS#7 padding

# Due to this func was already implemented in task7, include task and use function:
my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
require "$PATH/../set1/task07.aes_in_ecb_mode.pl";

my $stringToPad = "YELLOW SUBMARINE";
my $correctResult = "YELLOW SUBMARINE".pack('H*',"04040404");

my $paddedStr = add_pad($stringToPad,20);
($correctResult == $paddedStr) ? print 'correct': print 'fail';

