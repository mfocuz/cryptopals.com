#!/usr/bin/perl -w
use strict;

# Task: 12. Byte-at-a-time ECB decryption (Simple)

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/../set1/task08.ecb_mode_detector.pl";
    require "$PATH/task11.ecb_cbc_detect_oracle.pl";
    
    # Generate random key
    my $key = gen_rand_bytes(16);
    
    # INPUT
    my $unknownString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg";
    $unknownString .= "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq";
    $unknownString .= "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg";
    $unknownString .= "YnkK";

    # decode but dont cheat, it should be secret
    $unknownString = base64_decode($unknownString);

    # Detect block size
    my $blockSize = detect_block_size(\&ecb_encrypt,$key);

    # Detect if its ECB mode
    my $string = "A" x ($blockSize * 2);
    my $ct = ecb_encrypt($string.$unknownString,$key);
    my $mode = detect_ecb_mode($ct);

    my $pt;
    if ($mode eq 'true') {
        $pt = break_ecb_byte_shift($key,$unknownString,16);
        #print "$pt";
    }
    
    # TEST
    $pt =~ s/\n//g;
    ($pt =~ /Rollin.*drove/) ? print 'correct': print 'fail';
}



sub break_ecb_byte_shift {
    my ($key, $ct, $blockSize) = @_;
    
    my $blockSizeHex = $blockSize * 2;
    # Make a dictionary of every possible last byte by feeding different strings to the ECB encrypt func
    my $string1ByteShorter = "A" x ($blockSize - 1);
    my %dict;
    foreach (0..255)  {
        my $fullBlock = $string1ByteShorter.chr($_);
        $fullBlock = ecb_encrypt($fullBlock,$key);
        my $fullBlockHex = unpack('H*',substr($fullBlock,0,16));
        $dict{$fullBlockHex} = $_;
    }
    
    # Take unknown message, and shift byte by byte to the left, so that each byte of unknown text will be places as last byte of AAAA... sequence
    # Due to we know all 256 variants of encrypted block AAAA....x we can get PT byte
    my @ct = split('',$ct);
    my $pt = "";
    my $s = length $ct;
    for(my $i = 0; $i <= length $ct; $i++) {
        my $currentPt = pack('(A)*',@ct);
        my $currentCt = ecb_encrypt($string1ByteShorter.$currentPt,$key);
        
        # take 0th block and unpack to readable hex
        my @blocks = unpack("(H$blockSizeHex)*",$currentCt);
        
        # match block to dictionaty and find PT byte!
        my $ptByte = $dict{$blocks[0]};
        
        $pt .= chr($ptByte);
        
        shift @ct;
    }
    
    return $pt;
}

sub detect_block_size {
    my $cipher_function = shift;
    my $key = shift;
    my $iv = shift;
    
    # encrypt one byte, block cipher should fullfill with padding to blocksize
    my $pt = "A";
    my $ct = $cipher_function->($pt,$key,$iv);
    
    # Block size is
    my $blockSize = length $ct;
    
    # Just to be sure, send message with size = blockSize + 1 byte, result should be equals = 2 blockSizes
    $pt = "A" x ($blockSize + 1);
    $ct = $cipher_function->($pt,$key,$iv);
    
    if (length $ct == 2 * $blockSize) {
        return $blockSize;
    } else {
        die "Don't know what to do here for now...\n";
    }
}

1;