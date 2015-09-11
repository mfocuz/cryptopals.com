#!/usr/bin/perl -w
use strict;

# Task 16: CBC bitflipping attacks

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/task10.implement_cbc_mode.pl";
    require "$PATH/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/task15.pkcs7_padding_validation.pl";
    
    # Generate random AES key and IV
    my $key = gen_rand_bytes(16);
    my $iv = gen_rand_bytes(16);
    
    # Compile hacker input, full encrypted string consists of:
    # 1. prepend = 'comment1=cooking%20MCs;userdata=' - is 2 blocks of input (2 x 16 bytes)
    # 2. Controlled input of ANY size
    # 3. append = ';comment2=%20like%20a%20pound%20of%20bacon' - is 2 blocks (2 x 16 bytes) + 10 bytes
    # Conlcusion:
    #       2 blocks of prepend         2 blocks os user controlled input         3 blocks of append
    # |<--prepend--><---prepend-->|<--controlled input--><--controlled input-->|<--append--><--append--><--append + padding-->|
    # We need to insert 2 blocks, 1st for bitflipping and 2nd with payload
    # 0000000000000000 00000:admin@true
    # 0123456789ABCDEF 0123456789ABCDEF
    # first is for bitflipping attack
    my $hackerInput1stBlock = "0" x (16 + 5);
    # second is for required input ';admin=true'
    # due to chars ; and = are filtered, we replace with with any other, e.g. +
    my $hackerInput2ndBlock = "+admin+true";
    
    # Get CT of compiled hacker data
    my $ct = first_func($hackerInput1stBlock.$hackerInput2ndBlock,$key,$iv);
    
    # Here we have CT of 7 blocks,
    # 1,2 - prepend data
    # 3,4 - hacker data
    # 4,5,6 - append data
    # Now perform bitflipping attack in 3rd block to affect decrypted data in 4th block
    # We need to change 5 and 11 bytes until second func return true
    foreach my $bitflip1 (0..255) {
        foreach my $bitflip2 (0..255) {
            my @blocks = unpack('(H32)*',$ct);
            my @bitFlipBlock = unpack('(A2)*',$blocks[2]);
            $bitFlipBlock[5] = sprintf('%02x',$bitflip1);
            $bitFlipBlock[11] = sprintf('%02x',$bitflip2);
            $blocks[2] = join('',@bitFlipBlock);
            my $hackerInput = pack('H*',join('',@blocks));
            (second_func($hackerInput,$key,$iv) eq 'true') ? (print 'correct' and exit 0) : next;
        }
    }
    print 'fail';
}


sub first_func {
    my ($input,$key,$iv) = @_;
    
    my $prepend = "comment1=cooking%20MCs;userdata=";
    my $append = ";comment2=%20like%20a%20pound%20of%20bacon";
    
    $input =~ s/\=|\;//;
    
    my $ct = cbc_encrypt($prepend.$input.$append,$key,$iv);
    return $ct;
}

sub second_func {
    my ($ct,$key,$iv) = @_;
    
    my $pt = cbc_decrypt($ct,$key,$iv);
    # Debug:
    #print "$pt\n";
    
    my @keyValuePair = split(';',$pt);
    my %keyValuePair;
    
    foreach (@keyValuePair) {
        my ($key,$value) = split('=',$_);
        $keyValuePair{$key} = $value;
    }
    
    if (defined $keyValuePair{admin} and $keyValuePair{admin} eq 'true') {
        # Debug step
        #print "$pt\n";
        return 'true';
    }
    
    return 'false';
}

sub strip_padding {
    my $block = shift;
    
    my @block = ();
    
}