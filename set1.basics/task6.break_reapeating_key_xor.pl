#!/usr/bin/perl

use strict;

# Task 6: Break repeating-key XOR

# Detect if we are included
if (!caller) {
    require './task1.hex_to_base64.pl';
    require './task2.fixed_xor.pl';
    require './task3.single_byte_xor.pl';
    require './task4.detect_single_byte_xor.pl';
    
    my $file = $ARGV[0];
    
    # Test hamming distance
    my $testString1 = "this is a test";
    my $testString2 = "wokka wokka!!!";
    my $hd = hamming_distance($testString1,$testString2);
    print "Is hamming distance is 37? Current = $hd\n";
    
    # Open file and read whole to buffer
    open(my $fh, '<', $file) or die "Can not open file: $file\n";
    
    my $encryptedDataBase64;
    
    while (<$fh>) {
        chomp;
        $encryptedDataBase64 .= $_;
    }
    
    # Decode base64
    my $encryptedData = base64_decode($encryptedDataBase64);
    my $encryptedDataHex = unpack('H*',$encryptedData);
    
    # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40
    # Save hamming distances to:
    my %hdHash;
    # in bytes:
    foreach (1..40) {
        # in bits:
        my $keySize = $_ * 8;
        # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
        # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
        my @encDataChunks = unpack("(B$keySize)*",$encryptedData);
        
        # Calculate total hamming distance and normilize by key size
        my $totalhd = 0;
        for (my $i=0;$i<$#encDataChunks-1;$i++) {
            my $hd = hamming_distance($encDataChunks[$i],$encDataChunks[$i+1]);
            $totalhd += $hd/$keySize;
        }
        # Normalize by key size
        $hdHash{$keySize} = $totalhd/($#encDataChunks-1);
    }
    
    # Sort %hdHash by values and get 4 smallest hamming distances
    my @sortKeySizes = sort {$a <=> $b} values %hdHash;
    my @minValues = splice(@sortKeySizes,0,1);
    
    # Get most probably key sizes
    my @keySizeCandidates;
    foreach my $minVal (@minValues) {
       push @keySizeCandidates, grep {$hdHash{$_} eq $minVal} keys %hdHash;
    }

    # Break cipher text into blocks for each key size candidate
    foreach my $keySizeCandidate (@keySizeCandidates) {
        my @encDataChunks = unpack("(B$keySizeCandidate)*",$encryptedData);
        
        # Now transpose the blocks: make a block that is the first byte of every block,
        # and a block that is the second byte of every block, and so on.
        my @transposedBlocks;
        for (my $i=1;$i<=$keySizeCandidate;$i+=8) {
            my $block;
            foreach (@encDataChunks) {
                $block .= substr($_,0,8,'');
            }
            push @transposedBlocks,$block;
        }
        
        # Solve each block as if it was single-character XOR. You already have code to do this.
        my $keyCandidate;
        foreach (@transposedBlocks) {
            my $transposedBlock = pack('B*',$_);
            $keyCandidate .= break_single_byte_xor_with_space($transposedBlock);
        }
        
        print pack('H*',rox($encryptedDataHex,expand_key($keyCandidate,(length $encryptedDataHex)/2)));
    }
}

# Function for breaking single byte XOR encryption for encrypted English text (based on counting space in text)
# Input: Cipher string
sub break_single_byte_xor_with_space {
    my $input = shift;
    my $inputLength = (length $input);
    
    my @input = split('',$input);
    
    # Most frequent char is SPACE
    my %freqStat;
    map {$freqStat{$_}++} @input;
    
    # Sort dispStat by values and print the decrypted message with highest matches
    my @sortedValues = sort {$a <=> $b} values %freqStat;
    my $maxValue = $sortedValues[$#sortedValues];
    # Return best candidate
    my ($correctByte) = grep {$freqStat{$_} eq $maxValue} keys %freqStat;
    my $correctKey = rox(unpack('H*',$correctByte),unpack('H*'," "));
    return $correctKey;
}

# Function for calculate Hamming Distance in bits
sub hamming_distance {
    my $str1 = shift;
    my $str2 = shift;
    
    # Unpack string to binary 
    my @bStr1 = split('',unpack('B*',$str1));
    my @bStr2 = split('',unpack('B*',$str2));
    
    # Strings should have the same length
    if ($#bStr1 != $#bStr2) {
        die "Strings have different length, can not calc Hamming distance\n";
    }
    
    # Hamming distance
    my $hd = 0;
    
    for (my $i = 0; $i<=$#bStr1; $i++) {
        $hd++ if ($bStr1[$i] != $bStr2[$i]);
    }
    
    return $hd;
}