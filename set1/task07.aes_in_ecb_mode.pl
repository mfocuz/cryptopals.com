#!/usr/bin/perl -w
use strict;

# Task 7: AES in ECB mode

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/task01.hex_to_base64.pl";
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
    #print "$pt\n";
    
    # Test ECB encryption function, encrypt result and decrypt again
    my $testEncryption = ecb_encrypt($pt."AAAA",$key);
    my $testResult = ecb_decrypt($testEncryption,$key);
    #print "\n\nDecrypted text after ecb_ecnrypt function\n\n$testResult\n";
    ($testResult eq $pt."AAAA") ? print 'correct' : print 'Fail';
}

# AES ECB encryption func
# 1) Plain Text as ASCII
# 2) Key as ASCII
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
    
    # Check if last block less than AES block size
    my $lastBlock;
    if (length $pt[$#pt] < 16 * 2 ) {
        # Add padding to last block and encrypt
        $lastBlock = $cipher->encrypt(add_pad(pack('H*',$pt[$#pt]),16));
    } elsif (length $pt[$#pt] == 16 * 2) {
        # Encrypt last block, then add empty block with 0x10 x16 bytes padding
        $lastBlock = $cipher->encrypt(pack('H*',$pt[$#pt]));
        $lastBlock .= $cipher->encrypt(pack('H*',"10" x 16));
    } else {
        die "Fatal error!\n";
    }
    
    return $ct.$lastBlock;
}

# AES ECB decryption func
# Input:
# 1) Cipher Text as byte array (string)
# 2) Key
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

# Add PKCS#7 padding bytes to block(required when encrypt)
# Input:
# 1) block as byte array
# 2) block length in bytes to fullfill
sub add_pad {
    my $block = shift;
    my $blockLen = shift;
    
    my $pad = $blockLen - (length $block);
    # If pad = 0, that means we have to add additional padded block with 0x16 x 16
    return $block if ($pad == 0);
    
    my $padding;
    $padding = sprintf("%.2x",hex($pad)) x ($pad);
    
    return $block.pack('H*',$padding);
}

# Remove padding bytes from block(required when decrypt)
# Input: block as byte array
sub del_pad {
    my $block = shift;
    
    my @block = unpack('(H2)*',$block);
    my $pad = hex($block[$#block]);
    splice(@block,$#block-$pad+1,$pad);
    return join('',@block);
}

1;

