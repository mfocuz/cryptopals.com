#!/usr/bin/perl

use strict;

# Task 3: Single-byte XOR cipher

use Text::Ngrams;

# Detect if we are included or not
if (!caller) {    
    require './task2.fixed_xor.pl';
    
    my $input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    my $inputLength = (length $input) / 2;

    my $keys = break_single_byte_xor_with_letterfreq($input);
    
    map {print pack('H*',rox($input,expand_key(sprintf('%.2x',$_),$inputLength)))."key: $_\n"} @$keys;
}

# Function for breaking single byte XOR encryption for encrypted English text (based on English letter frequency)
# Input: Cipher string
sub break_single_byte_xor_with_letterfreq {
    my $input = shift;
    
    my $inputLength = (length $input) / 2;
    
    # English letter dispersion frequency table 
    my %dispTable;
    
    foreach my $singleByteKey (0..255) {
        # Expand single byte key to message length
        my $key = expand_key(sprintf('%.2x',$singleByteKey),$inputLength);
        # Decrypt message
        my $output = pack('H*',rox($input,$key));
        # Debug step
        #print "i:$singleByteKey str:$output\n";
        # Perform english letter frequency analysis
        my $result = letter_freq($output);
        # Summ min+max+avg dispersions, the minimum value is match to real english text
        my $resultDisp = $result->[0] + $result->[1] + $result->[2];
        # Drop cases with disp 0, probability that current text letters frequency is exactly equals to source freq table is very low
        ($resultDisp == 0) ? next : ($dispTable{$singleByteKey} = $resultDisp);
    }
    
    # Sort values in reverse order and take min value
    my @sortedValues = sort {$a <=> $b} reverse  values %dispTable;
    my $minValue = $sortedValues[0];
    
    # Get keys with min value and decrypt message with it
    my @keys = grep {$dispTable{$_} eq $minValue} keys %dispTable;
    return \@keys;
    #map {print pack('H*',rox($input,expand_key(sprintf('%.2x',$_),$inputLength)))."key: $_\n"} @keys;
    
}

# Function for expanding key to message length for stream cipher
# Input: key in hex string,length to expand, usually its a message(whic should be encrypted) length
sub expand_key {
    my $key = shift;
    my $length = shift;

    #$key =  sprintf('%.2x',$key) if (bytes::length($key) == 1);
    my $resultKey = "";
    while (1) {
        # Check current result key length
        my $lengthToFullfill = $length - (length $resultKey)/2;
        # If we have to fullfill more that length of key, then concat one more key
        if ($lengthToFullfill >= (length $key)/2) {
            $resultKey .= $key;
        }
        # If we have to fullfill less than length of key, then take only required number of key's chars/btyes
        elsif ($lengthToFullfill < (length $key)/2) {
            $resultKey .= substr($key,0,$lengthToFullfill*2);
            last;
        }
    }
    return $resultKey;
}

# English letter frequency analyzer, detect if input is english text based on english letter frequency
# Input any text/sequence of bytes
# Output: [min,max,avg] absolute values
sub letter_freq {
    my $inputText = shift;
    
    # Letter frequency, info from http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    my %sourceLetterFrequencyTable = (
        E => 12.02, T => 9.10, A => 8.12,
        O => 7.68, I => 7.31, N => 6.95,
        S => 6.28, R => 6.02, H => 5.92,
        D => 4.32, L => 3.98, U => 2.88,
        C => 2.71, M => 2.61, F => 2.30,
        Y => 2.11, W => 2.09, G => 2.03,
        P => 1.82, B => 1.49, V => 1.11,
        K => 0.69, X => 0.17, Q => 0.11,
        J => 0.10, Z => 0.07
    );

    my %inputTextFreq;
    my $letterCount = 0;

    # Split text to array and calculate number of each letter
    my @inputText = split('',$inputText);
    foreach (@inputText) {
        next if ($_ !~ m/[[:alpha:]]/);
        $inputTextFreq{uc $_}++;
        $letterCount++;
    }
    
    return ['undef','undef','undef'] if (keys %inputTextFreq == 0);
    
    # Transform number of letters to frequency
    foreach my $letter (keys %inputTextFreq) {
        $inputTextFreq{$letter} = $inputTextFreq{$letter} / $letterCount;
    }
    
    # Compare result frequency with source frequency table
    my %freqDisp;
    foreach my $letter (keys %inputTextFreq) {
        next if ($inputTextFreq{$letter} == 0);
        my $freqDiff = $sourceLetterFrequencyTable{$letter} - $inputTextFreq{$letter};
        my $freqDiffPercent = ($freqDiff/$sourceLetterFrequencyTable{$letter}) * 100;
        $freqDisp{$letter} = $freqDiffPercent;
    }

    # Calc min, max and avg dispersion
    my ($min,$max,$avg);
    my $encounteredLettersCount;
    foreach my $letter (keys %freqDisp) {
        $min = $freqDisp{$letter} unless ($min);
        $max = $freqDisp{$letter} unless ($max);
        $min = $freqDisp{$letter} if ($freqDisp{$letter} < $min);
        $max = $freqDisp{$letter} if ($freqDisp{$letter} > $max);
        $avg += $freqDisp{$letter};
        $encounteredLettersCount++;
    }
    
    $avg = $avg/$encounteredLettersCount;
    
    return [abs (100 - $max),abs (100 - $min),abs (100 - $avg)];
}

1;