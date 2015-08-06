#!/usr/bin/perl -w
use strict;

# Task 8: Detect AES in ECB mode

# Detect if we are included
if (!caller) {
    my $file = $ARGV[0];
    
    # Read file
    open(my $fh, '<', $file) or die "Can not open file $file\n";
    # read by line
    my @strings;
    while (<$fh>) {
        chomp;
        push @strings,$_;
    }
    
    # Detect which string is ECB mode
    foreach my $string (@strings) {
        my $isEcbMode = detect_ecb_mode($string);
        print "String:\n $string \n\nis ECB mode encryption!\n" if ($isEcbMode eq 'true');
    }
}

# AES ECB mode detection function
# Input: CT
sub detect_ecb_mode {
    my $ct = shift;
    
    # Detect ECB by searhing equivalent blocks for each block lentgh 16 bytes
    # Unpack cipher text into 16 bytes blocks
    my @cipher = unpack("(H32)*",$ct);
    
    # Calculate repeated blocks
    my %blockCounter;
    map {$blockCounter{$_}++} @cipher;
    my $repeatedBlocks = grep {$blockCounter{$_} > 1} keys %blockCounter;
    
    # If there is repeated block, its most probably ECB mode
    return 'true' if ($repeatedBlocks > 0);
    
    # Otherwise 2 possible cases
    # 1) its not ECB
    # 2) there are no repeated blocks
    return 'false';
}

1;