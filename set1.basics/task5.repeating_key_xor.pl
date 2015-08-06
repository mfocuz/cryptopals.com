#!/usr/bin/perl

use strict;

# Task 5: Implement repeating-key XOR

# Actually repeating-key xor is already implementer in function expand_key in :
require './task3.single_byte_xor.pl';
# so lets use it!

require './task2.fixed_xor.pl';

my $rawMessage = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
my $rawKey = 'ICE';

my $hexMessage = unpack('H*',$rawMessage);
my $messageLength = (length $hexMessage) / 2;
my $hexKey = unpack('H*',$rawKey);

my $cipher = rox($hexMessage,expand_key($hexKey,$messageLength));
print "Result is: $cipher";






