#!/usr/bin/perl

use strict;

# Task 5: Implement repeating-key XOR

my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;

# Actually repeating-key xor is already implemented in function expand_key in :
require "$PATH/task03.single_byte_xor.pl";
# so lets use it!

require "$PATH/task02.fixed_xor.pl";

my $rawMessage = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
my $rawKey = 'ICE';

my $hexMessage = unpack('H*',$rawMessage);
my $messageLength = (length $hexMessage) / 2;
my $hexKey = unpack('H*',$rawKey);

my $cipher = rox($hexMessage,expand_key($hexKey,$messageLength));

# TEST
my $correctResult = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272';
$correctResult .= 'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';
#print "Result is: $cipher";
($cipher eq $correctResult) ? print 'correct' : print 'fail';








