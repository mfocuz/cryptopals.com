#!/usr/bin/perl -w
use strict;

use Crypt::OpenSSL::AES;

# Task 10: Implement CBC mode

# Detect if we are included
if (!caller) {
    require '../set1.basics/task1.hex_to_base64.pl';
    require '../set1.basics/task2.fixed_xor.pl';
    require '../set1.basics/task7.aes_in_ecb_mode.pl';
    
    my $file = $ARGV[0];
    
    # Read file
    open(my $fh, '<', $file) or die "Can not open file $file\n";
    my $DATA = "";
    while (<$fh>) {
        chomp;
        $DATA .= $_;
    }

    my $KEY = "YELLOW SUBMARINE";
    my $IV = "00" x 16;

    my $encryptedData = base64_decode($DATA);

    # Decrypt data
    my $pt = cbc_decrypt($encryptedData,$KEY,$IV);
    print "Result:\n\n$pt\n";
    
    # Test encryption function, encrypt text and decrypt again, compare results
    my $testEncryption = cbc_encrypt($pt,$KEY,$IV);
    my $testResult = cbc_decrypt($testEncryption,$KEY,$IV);
    print "\n\nDecrypted text after cbc_ecnrypt function\n\n$testResult\n";
    (($pt ^ $testResult) == 0) ? print "Test success" : print "Test failed";
}

# AES CBC ecnryption function
# Input:
# 1) Plain text
# 2) Key
# 3) IV
sub cbc_encrypt {
    my $pt = shift;
    my $key = shift;
    my $iv = shift;
    
    my $aes = Crypt::OpenSSL::AES->new($key);
    
    my @blocks = unpack('(H32)*',$pt);
    my $input4xor = $iv;
    my $cipher = "";
    
    # Go through all blocks except last one, xor each block with previous CT, the ecnrypt with AES
    for(my $i=0;$i<$#blocks;$i++) {
        my $block = $blocks[$i];
        # XOR block with previosly encrypted one, or with IV for first block
        $block = rox($block,$input4xor);
        # AES ecnrypt resulted block
        my $encryptedBlock = $aes->encrypt(pack('H*',$block));
        # Set current block as block to be XORed with next one
        $input4xor = unpack('H*',$encryptedBlock);
        # Append cipher text to result cipher
        $cipher .= $encryptedBlock;
    }
    
    # Apply padding for last block, xor with previous encrypted one, then ecnrypt
    my $lastBlock = add_pad(pack('H*',$blocks[$#blocks]),16);
    $lastBlock = rox(unpack('H*',$lastBlock),$input4xor);
    $lastBlock = $aes->encrypt(pack('H*',$lastBlock));

    return $cipher.$lastBlock;
}

# AES CBC decryption function
# Input:
# 1) Cipher text
# 2) Key
# 3) IV
sub cbc_decrypt {
    my $ct = shift;
    my $key = shift;
    my $iv = shift;
    
    my $aes = Crypt::OpenSSL::AES->new($key);
    
    my @blocks = unpack('(H32)*',$ct);
    my $input4xor = $iv;
    my $plainText = "";
    
    for(my $i=0;$i<$#blocks;$i++){
        my $block = $blocks[$i];
        # Save previously block to be xored with current
        my $c_input4xor = $input4xor;
        # Set current ciphered block as to block to be xored with next one
        $input4xor = $block;
        # AES decrypt block
        my $decryptedBlock = $aes->decrypt(pack('H*',$block));
        # XOR decrypted block with previous ciphered one, or IV for first block
        $block = rox(unpack('H*',$decryptedBlock),$c_input4xor);
        # Save decrypted plain text
        $plainText .= $block;
    }
    
    # Decrypt last block
    my $lastBlock = $blocks[$#blocks];
    $lastBlock = $aes->decrypt(pack('H*',$lastBlock));
    # XOR with previous ecnrypted one
    $lastBlock = rox(unpack('H*',$lastBlock),$input4xor);
    # Remove padding
    $lastBlock = del_pad(pack('H*',$lastBlock));
    
    return pack('H*',$plainText.$lastBlock);
}

1;