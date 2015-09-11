#!/usr/bin/perl -w
use strict;

# Task 14: Byte-at-a-time ECB decryption (Harder)

use Crypt::OpenSSL::AES;
use MIME::Base64;

my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
require "$PATH/../set1/task01.hex_to_base64.pl";
require "$PATH/../set1/task02.fixed_xor.pl";
require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
require "$PATH/../set1/task08.ecb_mode_detector.pl";
require "$PATH/task11.ecb_cbc_detect_oracle.pl";
require "$PATH/task12.byte_at_time_ecb_decr_simple.pl";

my $key = gen_rand_bytes(16);

# INPUT
my $string = "Hello, this is my string!";
my $unknownString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg";
$unknownString .= "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq";
$unknownString .= "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg";
$unknownString .= "YnkK";

# decode but dont cheat, it should be secret
$unknownString = decode_base64($unknownString);

# 1. Generate random prefix 0-48 bytes
my $length = int rand(48);
my $randPrefix = gen_rand_bytes($length);
my @randPrefix = unpack('(H2)*',$randPrefix);

# 2. Detect cipher block size
my $blockSize = detect_block_size(\&ecb_encrypt,$key);
my $blockSizeHex = $blockSize * 2;

# 3. Detect prefix padded part and complete it with attacker controlled data to have one byte shorter block
my $toPaddLength = $length % $blockSize;
my $randPrefixLastBlock = int ($length / $blockSize);
my @toPadd = splice(@randPrefix,-($toPaddLength),$toPaddLength);

# 4. Make a dictionary of every possible variants with diff lastbyte and with first bytes from @toPadd
my $padData1byteShorter = "A" x ($blockSize - $toPaddLength - 1);
my $s = pack('H*',join('',@toPadd));
my $string1ByteShorter = pack('H*',join('',@toPadd)).$padData1byteShorter;

my %dict;
foreach (0..255)  {
    my $fullBlock = $string1ByteShorter.chr($_);
    
    $fullBlock = ecb_encrypt($fullBlock,$key);
    # unpack to readable hex
    my $fullBlockHex = unpack('H*',substr($fullBlock,0,16));
    $dict{$fullBlockHex} = $_;
}

# 5. Take unknown message, and shift byte by byte to the left, so that each byte of unknown text will be places as last byte of @toPadd."AAA...?" sequence
my @unknownString = split('',$unknownString);
my $pt = "";

for(my $i = 0; $i <= length $unknownString; $i++) {
    my $currentString = pack('(A)*',@unknownString);
    my $fullMessage = $randPrefix.$padData1byteShorter.$currentString;
    my $ct = ecb_encrypt($fullMessage,$key);
    
    # take i-th block and unpack to readable hex
    my @blocks = unpack("(H$blockSizeHex)*",$ct);
    
    # match block to dictionaty and find PT byte!
    my $ptByte = $dict{$blocks[$randPrefixLastBlock]};
    
    $pt .= chr($ptByte);
    
    shift @unknownString;
}

# TEST
$pt =~ s/\n//g;
($pt =~ m/Rollin/) ? print 'correct' : print 'fail';





