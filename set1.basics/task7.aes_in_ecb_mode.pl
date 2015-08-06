#!/usr/bin/perl -w
use strict;

# Task 7: AES in ECB mode

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    require './task1.hex_to_base64.pl';
    my $file = $ARGV[0];

    my $key = "YELLOW SUBMARINE";

    # Read encrypted file
    open(my $fh, '<:raw', $file) or die "Can not open file $file\n";
    my $text;
    while (<$fh>) {
        chomp;
        $text .= $_;
    }
    # Base64 decode data
    my $encryptedData = base64_decode($text);

    # AES ECB Decrypt
    my $pt = ecb_decrypt($encryptedData,$key);
    print "$pt\n";
    
    # Test ECB encryption function, encrypt result and decrypt again
    my $testEncryption = ecb_encrypt($pt,$key);
    my $testResult = ecb_decrypt($testEncryption,$key);
    (($pt ^ $testResult) == 0) ? print "Test success" : print "Test failed";
}

# AES ECB encryption func
# Input: PT, key
sub ecb_encrypt {
    my $pt = shift;
    my $key = shift;
    
    # Unpack plain text into 16 byte blocks
    my @pt = unpack('(H32)*',$pt);
    
    my $cipher = new Crypt::OpenSSL::AES($key);
    my $ct = "";
    
    # Encrypt all blocks except last one
    for(my $i=0;$i<$#pt;$i++) {
        $ct .= $cipher->encrypt(pack('H*',$pt[$i]));
    }
    
    # Add padding to last block if required and encrypt
    my $lastBlock = $cipher->encrypt(pack('H*',add_pad($pt[$#pt])));
    
    return $ct.$lastBlock;
}

# AES ECB decryption func
# Input: CT, key
sub ecb_decrypt {
    my $ct = shift;
    my $key = shift;
    
    # Unpack cipher text into 16 byte blocks
    my @ct = unpack("(H32)*",$ct);

    my $cipher = new Crypt::OpenSSL::AES($key);
    my $pt = "";
    
    # Decrypt all blocks except last one
    for(my $i=0;$i<$#ct;$i++) {
        $pt .= $cipher->decrypt(pack("H*",$ct[$i]));
    }
    
    # Decrypt last block and cut padding
    my $lastBlock = $cipher->decrypt(pack('H*',$ct[$#ct]));
    my $lastBlockUnpad = pack('H*',del_pad($lastBlock));
    
    # Add last block to already decrypted plain text and return
    return $pt.$lastBlockUnpad;
}

# Add padding bytes to block(required when encrypt)
# Input: block as HEX string
sub add_pad {
    my $block = shift;
    
    my $pad = 32 - (length $block);  
    return if ($pad == 0);
    
    my $padding;
    $padding = sprintf("%.2x",hex($pad/2)) x ($pad/2);
    
    return $block.$padding;
}

# Remove padding bytes from block(required when decrypt)
# Input: block as HEX string
sub del_pad {
    my $block = shift;
    
    my @block = unpack('(H2)*',$block);
    my $pad = $block[$#block];
    splice(@block,$#block-$pad+1,$pad);
    return join('',@block);
}

1;

