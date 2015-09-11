#!/usr/bin/perl -w
use strict;

use Crypt::OpenSSL::AES;

# Task 10: Implement CBC mode

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    
    my $file = $ARGV[0];
    
    # Read file
    open(my $fh, '<', $file) or die "Can not open file $file\n";
    my $DATA = "";
    while (<$fh>) {
        chomp;
        $DATA .= $_;
    }

    my $KEY = "YELLOW SUBMARINE";
    my $IV = pack('H*',"00" x 16);

    # Base64 decode input
    my $encryptedData = base64_decode($DATA);

    # Decrypt data
    my $pt = cbc_decrypt($encryptedData,$KEY,$IV);
    #print "Result:\n\n$pt\n";
    
    # Test section
    
    # Test encryption function, encrypt text and decrypt again, compare results
    my $testEncryption = cbc_encrypt($pt.("A" x 15),$KEY,$IV);
    my $testResult = cbc_decrypt($testEncryption,$KEY,$IV);
    #print "\n\nDecrypted text after cbc_ecnrypt function\n\n$testResult\n";

    ($testResult eq $pt.("A" x 15).pack('H*','01')) ? print "correct" : print "fail";
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
    my $input4xor = unpack('H*',$iv);
    my $cipher = "";
    
    # Go through all blocks except last one, xor each block with previous CT, the ecnrypt with AES
    # Check if last block length equals to AES block size, if true, empty padding block is required, if false, last block should be padded
    my $lastBlockIndex = (length $blocks[$#blocks] == 16 * 2) ? $#blocks : $#blocks-1;
    for(my $i=0;$i<=$lastBlockIndex;$i++) {
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
    
    # If last block should be padded (check if last encrypted block index is last or last but one)
    if ($lastBlockIndex ne $#blocks) {
        my $lastBlock;
        # Add padding to last block
        $lastBlock = add_pad(pack('H*',$blocks[$#blocks]),16);
        # XOR block with previosly encrypted one, or with IV for first block
        $lastBlock = rox(unpack('H*',$lastBlock),$input4xor);
        # AES ecnrypt resulted block
        $lastBlock = $aes->encrypt(pack('H*',$lastBlock));
        # Add last block to cipher
        $cipher .= $lastBlock;
    }
    # If last block equals to AES block size, add empty padded block 0x10 x 16
    elsif ($lastBlockIndex eq $#blocks ) {
        # Xor empty padded block with previous one
        my $lastBlock = rox("10" x 16,$input4xor);
        # Encrypt last block and add to cipher
        $lastBlock = $aes->encrypt(pack('H*',$lastBlock));
        $cipher .= $lastBlock;
    } else {
        die "Fatal error!\n";
    }

    return $cipher;
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
    my $input4xor = unpack('H*',$iv);
    my $plainText = "";
    
    for(my $i=0;$i<=$#blocks;$i++){
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
    #my $lastBlock = $blocks[$#blocks];
    #$lastBlock = $aes->decrypt(pack('H*',$lastBlock));
    # XOR with previous ecnrypted one
    #$lastBlock = rox(unpack('H*',$lastBlock),$input4xor);

    return pack('H*',$plainText);
}

1;