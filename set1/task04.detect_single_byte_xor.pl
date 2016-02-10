#!/usr/bin/perl

use strict;

# Task 4: Detect single-character XOR

use List::MoreUtils qw(first_index);

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    
    require "$PATH/task03.single_byte_xor.pl";
    require "$PATH/task02.fixed_xor.pl";

    # Read file from 1st param
    my $file = $ARGV[0];
    open(my $fh, '<', $file) or print "bams\n";
    
    my @strings;
    my $stringIndex = 0;
    while (<$fh>) {
        chomp;
        $strings[$stringIndex] = $_;
        $stringIndex++;
    }
    
    my %dispStat;
    my $stringNumber = 0;
    my $i = 0;
    foreach my $string (@strings) {
        #For this task its useless to calc char statistics, at least my implementation :p
        #due to very short strings in file letter frequency is incorrect
        #So better way for this task to check if all chars are printable ascii + spaces + new line
        $dispStat{$string} = break_single_byte_xor_with_ascii($string);
    }
    
    my %asciiStatCandidates;
    foreach my $string (keys %dispStat) {
        my $stringLength = (length $string) / 2;
        my $key = expand_key($dispStat{$string},$stringLength);
        my $output = pack('H*',rox($string,$key));
        my $asciiPrintable = calc_printable_ascii($output);
        $asciiStatCandidates{$string} = $asciiPrintable if ($asciiPrintable > 0);
    }
    
    # Sort dispStat by values and print the decrypted message with highest matches
    my @sortedValues = sort {$a <=> $b} values %asciiStatCandidates;
    my $maxValue = $sortedValues[$#sortedValues];
    # Get encrypted message appropriate to matches
    my ($stringCandidate) = grep {$asciiStatCandidates{$_} eq $maxValue} keys %asciiStatCandidates;
    my $correctKey = $dispStat{$stringCandidate};
    # Decrypt candidate
    my $finalResult = pack('H*',rox($stringCandidate,expand_key($correctKey,(length $stringCandidate)/2)));
    #print "$finalResult\n";
    my $correctResult = "Now that the party is jumping\n";
    ($finalResult eq $correctResult) ? print 'correct' : print 'fail';
}

# Function for breaking single byte XOR encryption for encrypted English text (based in number of ascii characters in text)
# Input: Cipher string
# Return: best key candidate byte
sub break_single_byte_xor_with_ascii {
    my $input = shift;
    my $inputLength = (length $input) / 2;
    my $regex = shift;
    
    my %asciiStat;
    foreach my $byte (0..255) {
        # Expand single byte key to message length
        my $key = expand_key(sprintf('%.2x',$byte),$inputLength);
        # Decrypt message
        my $output = pack('H*',rox($input,$key));
        my $asciiPrintable = calc_printable_ascii($output,$regex);
        $asciiStat{$byte} = $asciiPrintable if ($asciiPrintable > 0);
    }
    
    # Sort stat by values and print the decrypted message with highest matches
    my @sortedValues = sort {$a <=> $b} values %asciiStat;
    my $maxValue = $sortedValues[$#sortedValues];
    # Return best candidate
    my ($correctKey) = grep {$asciiStat{$_} eq $maxValue} keys %asciiStat;
    return sprintf('%.2x',$correctKey);
}

# Func for calculation printable ascii chars in string, useful for breaking repeating key XOR
sub calc_printable_ascii {
    my $input = shift;
    my $regEx = shift;
    my @text = split('',$input);
    
    my $asciiPrintable = 0;
    foreach (@text) {
        if ($regEx) {
            $asciiPrintable++ if ($_ =~ m/$regEx/);
        } else {
            # Check if each character is matched with alphabet/space/newline
            $asciiPrintable++ if ($_ =~ m/[[:alpha:]]|\s|\n/);
        }
    }
    return $asciiPrintable;
}

1;