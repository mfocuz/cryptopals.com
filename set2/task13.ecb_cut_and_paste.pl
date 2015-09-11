#!/usr/bin/perl -w
use strict;

# Task: 12. ECB cut-and-paste

use Crypt::OpenSSL::AES;
use JSON;
use Data::Dumper;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task07.aes_in_ecb_mode.pl";
    require "$PATH/../set1/task08.ecb_mode_detector.pl";
    require "$PATH/task11.ecb_cbc_detect_oracle.pl";
    
    # JSON obj
    my $json = JSON->new();
    $json->canonical('enable');
    $json->ascii(1);
    $json->relaxed(1);
    
    # generate key and create aes obj
    my $key = gen_rand_bytes(16);
    
    # test funcs
    my $profileParams = profile_for('max@mail.bams');
    my $profileObj = parse_url_params($profileParams);
    
    #print "url: $profileParams\n";
    #print "obj: $profileObj\n";
    
    # we have profile url like:
    # email=max@mail.bams&uid=10&role=user
    # lets cipher our profile
    my $encodedProfile = ecb_encrypt($profileParams,$key);
    
    # This is how it looks in hex, output is 3 blocks of 16 bytes
    #print unpack('H*',$encodedProfile)."\n";
    
    # We can perorm CCA (Choosen ciphertext attack)
    # lets break PT profile into 16 bytes blocks (| - separator)
    # |email=max@mail.b|ams&uid=10&role=|user + 0xc x 12 padding|
    # we have email field control, so we can give func such input: email=max@mail.badmin\x00(x11)ams (here 2 blocks 16 bytes each)
    my $emailForCCA = 'max@mail.b'.'admin'.pack('H*',"00" x 11).'ams';
    
    # Let see what is going on when we break profile into 16 byte blocks now
    # |email=max@mail.b|admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|ams&uid=10&role=|user + 0xc x 12 padding (PKSC7)|
    my $profileForCCA = profile_for($emailForCCA);
    
    # Prepare encoded data for CCA, then copy 2nd block and paste it instead of last one.
    my $encodedCCA = ecb_encrypt($profileForCCA,$key);
    
    # Change 2nd and 4th block, not last one because due to we have exaclty 16 x 4 bytes, additional padding block will be added
    my @blocks = unpack('(H32)*', $encodedCCA);
    my $lastBlock = $blocks[3];
    $blocks[3] = $blocks[1];
    $blocks[1] = $lastBlock;
    
    # check
    my $result = decode_profile(pack('H*',join('',@blocks)),$key);
    #print $result;
    
    # TEST
    $result =~ s/\n//g;
    ($result =~ m/admin/)? print 'correct': print 'fail';
    #print $result;
    
    # Result shows nullbytes after admin, so behavior will differe on back-end depending on particular back-end implentation
    # Main purpose of task to show how its possible to change field's values
}

#
# Funcs
#
sub decode_profile {
    my $ctprofile = shift;
    my $key = shift;
    
    my $pt = ecb_decrypt($ctprofile,$key);
    my $url = parse_url_params($pt);
    
    return return $url;
}

sub profile_for {
    my $email = shift;
    return -1 if $email =~ m/\=|\&/;

    my $url = "email=$email&uid=10&role=user";
    
    return $url;
}

sub parse_url_params {
    my $url_params = shift;
    my @params = split('&',$url_params);
    
    my %hash;
    
    foreach my $param (@params) {
        my ($key, $value) = split ('=',$param);
        $hash{$key} = $value;
    }
    
    my $userObj = Dumper(\%hash);

    return $userObj;
}


