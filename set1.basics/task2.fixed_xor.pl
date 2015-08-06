#!/usr/bin/perl

use strict;

# Task 2: Fixed XOR

if (!caller) {
    my $input1 = '1c0111001f010100061a024b53535009181c';
    my $input2 = '686974207468652062756c6c277320657965';
    
    my $result = rox($input1,$input2);
    print $result;
}

# Simple xor rox!
# Input: 2 strings unpacked as HEX
sub rox {
    my ($x,$y) = @_;
    
    if ((length $x) != (length $y)) {
        die "Values for simple XOR have different length.\n";
    }
    
    my $xhex = pack('H*',$x);
    my $yhex = pack('H*',$y);

    return unpack('H*',$xhex ^ $yhex);
}

1;