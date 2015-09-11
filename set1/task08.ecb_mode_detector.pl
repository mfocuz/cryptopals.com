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
    my $resultString;
    foreach my $string (@strings) {
        my $isEcbMode = detect_ecb_mode($string);
        #print "String:\n $string \n\nis ECB mode encryption!\n" if ($isEcbMode eq 'true');
        $resultString = $string if ($isEcbMode eq 'true');
    }
    
    # TEST
    my $correctString = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f";
    $correctString .= "6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597";
    $correctString .= "949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6";
    $correctString .= "b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    
    ($resultString eq $correctString) ? print 'correct' : print 'fail';
}

# AES ECB mode detection function
# Input: CT
# Output: true or false
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