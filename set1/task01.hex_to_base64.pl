#!/usr/bin/perl -w
use strict;

use List::MoreUtils qw(first_index);

# Task 1: Convert hex to base64

# base64 mapping
my @BASE64MAP = ('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
);

# Detect if we are included
if (!caller) {
    my $input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    
    # encode input file
    my $outputEncoded = base64_encode(pack('H*',$input));
    #print "Encoded base64: $outputEncoded\n";
    # decode input file
    my $outputDecoded = base64_decode($outputEncoded);
    #print "Decoded base64: $outputDecoded\n";
    #print $outputDecoded;
    
    # TEST
    my $correctBase64Encode = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    
    if (pack('H*',$input) eq $outputDecoded && $outputEncoded eq $correctBase64Encode) {
        print 'correct';
    }
    
}

#
# Funcs
#
sub base64_encode {
    my $data = shift;
    
    # Break data on 3 byte (24 bit) parts
    my @blocks24bit = unpack("(B24)*",$data);
    my $output;
    # Handle separately cases when last block is 3, 2 or 1 byte long
    foreach my $block (@blocks24bit) {
        # If last block contains of 3 bytes, no padding required
        if (length $block == 24) {
            # Break 24 bits(3 bytes/chars) into 4 part of 6 bits
            my @blocks6bit = unpack("(a6)*",$block);
            map {$output .= $BASE64MAP[oct("0b".$_)]} @blocks6bit;
        }
        # If last block contains of 2 bytes, fullfill the absent byte with 0 and concat '=' at the end
        elsif (length $block == 16) {
            $block .= '0' x 8;
            my @blocks6bit = unpack("(a6)3",$block);
            map {$output .= $BASE64MAP[oct("0b".$_)]} @blocks6bit;
            $output .= '='
        }
        # If last block contains of 1 bytes, fullfill the absent 2 bytes with 0 and concat '==' at the end
        elsif (length $block == 8) {
            $block .= '0' x 16;
            my @blocks6bit = unpack("(a6)2",$block);
            map {$output .= $BASE64MAP[oct("0b".$_)]} @blocks6bit;
            $output .= '==';
        }
    }
    return $output;
}

sub base64_decode {
    my $data = shift;
    
    # split base64 string into parts of 4 chars
    my @data = unpack('(a4)*',$data);
    my $result;

    # for each 4 char block replace chars with 6 bits binary values according to BASE64MAP
    # then concat 4 x 6 bit blocks into 24 bit block
    foreach my $block24bit (@data){
        my @chars = split('',$block24bit);
        
        my $bin6char;
        # default block length
        my $length = 24;
        
        # If last block with padding, then change block length to 16 for '=' and 8 for '=='
        if (my ($whichPad) = $block24bit =~ m/^(\w\w\w)=$|^(\w\w)==$/) {
            (defined $whichPad) ? ($length = 16): ($length = 8);
        }

        # replace chars with 6bit blocks accorging to BASE64MAP, last if '=' encountered
        foreach my $char (@chars) {
            last if $char =~ m/=/;
            $bin6char .= sprintf("%.6b", first_index {$_ eq $char} @BASE64MAP);
        }
        $result .= pack("B$length",$bin6char);
    }
    return $result;
}

1;