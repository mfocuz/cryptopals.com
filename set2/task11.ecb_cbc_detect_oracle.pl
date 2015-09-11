#!/usr/bin/perl -w
use strict;

# Task: 11. An ECB/CBC detection oracle

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/../set1/task08.ecb_mode_detector.pl";
    require "$PATH/task10.implement_cbc_mode.pl";
    
    # Jibber Jubber to encrypt, we will send 0x41 x 16 x 3
    # -for ECB we detect it by counting similar blocks
    # -for CBC we will change one byte in 1st block and see changes in 2nd block
    my $userInput = "A" x 16 x 3;
    
    # Encrypt data with random mode
    #   0 - ECB
    #   1 - CBC
    my $tests = 500;
    my $successTests = 0;
    foreach(1..$tests) {
        my $mode = int rand(2);
        
        my $cipher_function;
        my $modeDetected = -1;
        
        # Generate key
        my $key = gen_rand_bytes(16);
        # Generate random IV for CBC
        my $iv = gen_rand_bytes(16);
    
        # define encryption function
        if ($mode == 0) {
            $cipher_function = \&ecb_encrypt;
        } elsif ($mode == 1) {
            $cipher_function = \&cbc_encrypt;
        }
        
        # Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
        my $beforePT = gen_rand_bytes((int rand(5)) + 5);
        my $afterPT = gen_rand_bytes((int rand(5)) + 5);
        my $pt = $beforePT.$userInput.$afterPT;
        
        # Encrypt plaintext with choosen mode
        my $ct = $cipher_function->($pt,$key,$iv);
        
        # Try to detect both modes even if first return true

        # Detect ECB
        if (detect_ecb_mode($ct) eq 'true') {
            $modeDetected = 0;
        }

        # Detect CBC       
        # Encrypt plain text
        my $ct1 = $cipher_function->($pt, $key, $iv);
        #print "Debug ct1: ".unpack('H*',$ct1)."\n";
        #print "Debug pt1: $pt\n";
        
        # Change last byte of 1st block and encrypt
        my $changedPt = change_block_byte($pt,0,0);
        my $ct2 = $cipher_function->($changedPt, $key, $iv);
        #print "Debug pt2: ".pack('H*',join('',@pt))."\n";
        #print "Debug ct2: ".unpack('H*',$ct2)."\n";

        # Now check if its CBC mode
        if (detect_cbc_mode($ct1,$ct2) eq 'true') {
            $modeDetected = 1;
        }
        
        # Output result
        if ($modeDetected == $mode and $mode != -1) {
            my $modeStr = "";
            $successTests++;
            ($mode) ? ($modeStr = "CBC") : ($modeStr = "ECB");
            #print "Success! Mode: ".$modeStr."\n";
        } else {
            ##Debug only
            #print "Mode: $mode\n";
            #print unpack('H*',$ct1)."\n";
            #print unpack('H*',$ct2)."\n";
            #print detect_cbc_mode($ct1,$ct2)."\n";
            #print "Epic Fail!\n";
        }
    }
    
    ($tests == $successTests) ? print 'correct' : print 'fail';
}

# Change byte of input, required for CBC detect and oracle CBC attack
sub change_block_byte {
    my ($input,$block,$index) = @_;
    # Change plain text, split PT into 16 byte blocks
    my @input = unpack('(H32)*',$input);
    # change  byte in $index of $block with xor 0xff to opposite byte
    my @bytes = unpack('(A2)*',$input[$block]);
    $bytes[$index] = sprintf('%.2x', hex($bytes[0]) ^ 0xff);
    # compile PT back into string and send to encryption func
    $input[$block] = join('',@bytes);
    
    return pack('H*',join('',@input));
}


# CBC AES detection function
# Input: Cipher text
# Output: true or false
sub detect_cbc_mode {
    my ($ct1, $ct2) = @_;
    
    # Compare last block of both ct1 and ct2, if last block is differ, that it CBC, if the same, then ECB
    my @ct1 = unpack('(A16)*',$ct1);
    my @ct2 = unpack('(A16)*',$ct2);
    
    my $diff = 0;
    map {$diff++ if $ct1[$_] eq $ct2[$_]} (0..$#ct2);
    
    my $isCBC = ($diff == 0) ? 'true':'false';
    return $isCBC;
    
}

# Generate random bytes
# Input: number of bytes to generate
sub gen_rand_bytes {
    my $length = shift;
    
    srand();
    my $key = "";
    $key .= chr(int rand(255)) foreach (0..$length-1);
    
    return $key;
}

1;