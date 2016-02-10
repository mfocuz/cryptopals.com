#!/bin/perl
use strict;

# Task 25: Break "random access read/write" AES CTR
use Crypt::OpenSSL::AES;

if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/../set2/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/../set3/task18.implement_ctr_stream_cipher_mode.pl";
    
    my $file = $ARGV[0];
    
    # Read encrypted file
    open(my $fh, '<:raw', $file) or die "Can not open file $file\n";
    my $text;
    while (<$fh>) {
        chomp;
        $text .= $_;
    }
    
    # Generate random key
    my $key = gen_rand_bytes(16);
    my $nonce = gen_rand_bytes(16);
    my $edit = edit($key,$nonce);
    
    # Encrypt secret data
    my $secretCipherStr = ctr_encrypt($text,$key,$nonce);
    my @secretCipher = split//,$secretCipherStr;
    
    # Decrypt data byte by byte with using of edit function
    my $PT = "";
    foreach my $byte (0..$#secretCipher) {
        # For each byte replace byteon position $byte with char A(hex:0x41, dec:65)
        my $modifiedCipher = $edit->($secretCipherStr,$byte,"A");
        # Now XOR original cipher with modified data and 65
        # c1 ^ c2 = m1 ^ m2, but m2 = 65, so m1 ^ m2 ^ m2 = m1
        my $ptByte = ord($secretCipher[$byte]) ^ ord(substr($modifiedCipher,$byte,1)) ^ 65;
        $PT .= chr($ptByte);
    }
    
    ($PT eq $text) ? print 'correct' : print 'fail';
}

# Edit function, emulates server API
sub edit {
    my ($key,$nonce) = @_;
    
    my $edit = sub {
        my ($cipher,$offset,$newData) = @_;
        my $emptyData = "A" x $offset;
        my $newCipherData = ctr_encrypt($emptyData.$newData,$key,$nonce);
        $newCipherData = substr($newCipherData,$offset);
        my $length = length $newCipherData;
        
        substr $cipher,$offset,$length,$newCipherData;
        return $cipher;
    };
    
    return $edit;
}

1;