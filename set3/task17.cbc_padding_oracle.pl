#!/usr/bin/perl

use strict;

# Task 17: The CBC padding oracle
# Attack description can be found here:
# (in Rus) http://habrahabr.ru/post/247527/
# (in Eng) https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
# As for me, this one is best explanation - https://class.coursera.org/crypto-preview/lecture/38

use Crypt::OpenSSL::AES;

my $KEY;
# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/../set2/task10.implement_cbc_mode.pl";
    require "$PATH/../set2/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/../set2/task15.pkcs7_padding_validation.pl";
    
    # Run 100 test
    my $tests = 10;
    my $successTests = 0;
    foreach (1..$tests) {
        # Generate new key for each test
        $KEY = gen_rand_bytes(16);
        
        # Get a cipher text from "server"
        my $ff = first_function();
        my $ct = $ff->[0];
        my $string = $ff->[1];
        
        my $pt = padding_oracle($ct);
        $pt =~ s/[^[:print:]]//g;
        ($pt eq $string) ? $successTests++ : next;
    }   
    ($successTests eq $tests) ? print 'correct' : print 'fail';
}

sub padding_oracle {
    my $ct = shift;
    
    # Break CT to blocks
    my @ctBlocks = unpack('(H32)*',$ct);
    my @result;
    
    # Decrypt blocks one by one from the end
    for (my $i = $#ctBlocks;$i > 0;$i--) {
        # block to decrypt
        my $ctBlock = $ctBlocks[$i];
        # block to use as payload
        my $payloadBlock = $ctBlocks[$i-1];
    
        # block size should point to last index, so sub 1
        my $blockSize = (length $ctBlock)/2 - 1;
        my @payloadBlock = unpack('(A2)*',$payloadBlock);
        # Foreach block from the end:
        for(my $j=$blockSize;$j>=0;$j--) {
            # We are going to xor i bytes from the end with correct pad according to position of byte
            # and xor with all bytes 0-255 to find correct one
            # E.g. if we (payloadBlock[15]  xor $byte xor $0x01), result plaintext = (plaintext[15] xor $byte xor 0x01),
            # if plaintext[15] = $byte, then plaintext[15] = 0x01, this is correct pad, and server will not return padding error
            # that means $byte - already guessed byte of plaintext
            foreach my $byte (0..255) {
                # For last block(due to padding) skip step if byte is equals to required padding,
                # in other case we can get clear last block with correct padding and will be confused for futher attack
                next if ($j == $blockSize) and (($byte ^ ($blockSize - $j + 1)) == 0);
                
                my @localPayloadBlock = @payloadBlock;
                # xor i bytes from the end with correct pad (appropriate to current i posision)
                $localPayloadBlock[$j] = sprintf('%.2x',$byte ^ hex($localPayloadBlock[$j]));
                map {$localPayloadBlock[$_] = sprintf("%.2x",($blockSize - $j + 1) ^ hex($localPayloadBlock[$_]))} $j..$blockSize;
                # concat payloadBlock || ctBlock and send to "server"
                my $isByteCorrect = second_function(join('',@localPayloadBlock) . $ctBlock);
                
                # if byte is correct
                if ($isByteCorrect eq 'true') {
                    # save it to payloadBlock to appropriate position
                    $payloadBlock[$j] = sprintf("%.2x",hex($payloadBlock[$j]) ^ $byte);
                    $result[$i*($blockSize+1) + $j] = sprintf("%.2x",$byte);
                    # we need it for futher breaking
                    last;
                } else {next;}
            }
        }
    }
    return pack('H*',join('',@result));
}


# First function provide an encrypted string
sub first_function {
    my @strings = (
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    );
    # Get random string and generate key
    my $string = $strings[int rand($#strings+1)];
    #my $string = "0123456789ABCDEF"."0123456789ABCD";
    #print unpack('H*',$string)."\n";
    my $iv = gen_rand_bytes(16);
    #my $iv = pack('H*',"14" x 16);
    
    my $ct = cbc_encrypt($string,$KEY,$iv);
    #print unpack('H*',$ct)."\n";
    
    my $test = cbc_decrypt($ct,$KEY,$iv);
    
    return [$iv.$ct,$string];
}

# Second function emulates server, which checking padding, and return 2 different errors in case of correct and incorrect pad
sub second_function {
    my $input = shift;
    
    my $iv = substr($input,0,32,'');
    my $pt = cbc_decrypt(pack('H*',$input),$KEY,pack('H*',$iv));
    #my @pt = unpack('(A16)*',$pt);
    
    my $isPadValid = validate_pad($pt);
    ($isPadValid eq 'true') ? return 'true' : return 'false';
}

















