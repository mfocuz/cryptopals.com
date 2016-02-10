#!/bin/perl
use strict;

# Task 26: CTR bitflipping
use Crypt::OpenSSL::AES;

if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set2/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/../set3/task18.implement_ctr_stream_cipher_mode.pl";
    
    
    # Generate random AES key and Nonce
    my $key = gen_rand_bytes(16);
    my $nonce = gen_rand_bytes(16);
    
    my $hackerInput = "+admin+true";
    
    my $first_func = first_func($key,$nonce);
    my $second_func = second_func($key,$nonce);
    
    # 
    my $ct = $first_func->($hackerInput);
    my @ctArr = split//,$ct;
    # XOR result ciphered bytes on position where '+' is placed with required bytes
    # ';' == ord("+") ^ ord(";") = 16
    # '=' == ord("+") ^ ord("=") = 22
    $ctArr[32] = chr(ord($ctArr[32]) ^ 16);
    $ctArr[38] = chr(ord($ctArr[38]) ^ 22);
    my $result = $second_func->(join '',@ctArr);
    ($result eq 'true') ? print 'correct' : print 'fail';
}


sub first_func {
    my ($key,$nonce) = @_;
    
    my $first_func = sub {
        my $input = shift;
        my $prepend = "comment1=cooking%20MCs;userdata=";
        my $append = ";comment2=%20like%20a%20pound%20of%20bacon";
    
        $input =~ s/\=|\;//;
    
        my $ct = ctr_encrypt($prepend.$input.$append,$key,$nonce);
        return $ct;
    };
    
    return $first_func;
}

sub second_func {
    my ($key,$nonce) = @_;
    
    my $second_func = sub {
        my $ct = shift;
        my $pt = ctr_decrypt($ct,$key,$nonce);
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
    };
    
    return $second_func;
}

1;