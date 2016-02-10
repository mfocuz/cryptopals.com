#!/usr/bin/perl
use strict;

# Task 18: Implement CTR, the stream cipher mode
use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    
    my $targetStr = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    my $key = "YELLOW SUBMARINE";
    my $nonce = 0;
    
    my $pt = ctr_decrypt(base64_decode($targetStr),$key,$nonce);
    my $ct = ctr_encrypt($pt,$key,$nonce);
    my $ptTest = ctr_decrypt($ct,$key,$nonce);
    ($ptTest eq $pt) ? print 'correct' : print 'fail';
}


# CTR enc/dec functions
sub ctr_encrypt {
    my $input = shift;
    my $key = shift;
    my $nonce = shift;
    
    my $aes = Crypt::OpenSSL::AES->new($key);
    
    # Write nonce as little endian 64 bit unsinged int:
    # This string do the following:
    # 1) sprintf("%.16x",$nonce) - prints nonce as byte string length 16
    # 2) (sprintf("%.16x",$nonce) =~ /../g) - break nonce to array of 1 byte elements
    # 3) reverse (sprintf("%.16x",$nonce) =~ /../g) - reverse array (present nonce as little endian)
    # 4) join('',.... - join all above to new string
    $nonce = join('',reverse (sprintf("%.16x",$nonce) =~ /../g));
    
    # Break plain text into blocks of blocksize 16 bytes
    my @ptBlocks = unpack('(H32)*',$input);
    
    # Result cipher text
    my $output;
    # CTR counter
    my $ctr = 0;
    for(my $i=0; $i<=$#ptBlocks; $i++) {
        # Write counter as little endian 64 bit unsigned int
        my $ctrLittleEnd = join('',reverse (sprintf("%.16x",$ctr) =~ /../g));
        # Encrypt nonce || counter
        my $xorBlock = $aes->encrypt(pack('H*',$nonce.$ctrLittleEnd));
        # XOR result of above with plain text block
        my $ctBlock = rox(unpack('H*',$xorBlock),$ptBlocks[$i]);
        # Concat to result
        $output .= $ctBlock;
        # increase CTR counter
        $ctr++;
    }
    
    return pack('H*',$output);
}

sub ctr_decrypt {
    my $ct = shift;
    my $key = shift;
    my $nonce = shift;
    
    # Due to decryption is identical to encryption, just call encryption again
    my $pt = ctr_encrypt($ct,$key,$nonce);
    return $pt;
}

1;