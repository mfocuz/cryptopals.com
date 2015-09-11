#!/usr/bin/perl

use strict;

# Task: 15. PKCS#7 padding validation

use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    
    my $correctPadString = "ICE ICE BABY".pack('H*',"04040404");
    my $incorrectPadStr1 = "ICE ICE BABY".pack('H*',"05050505");;
    my $incorrectPadStr2 = "ICE ICE BABY".pack('H*',"01020304");;
    print 'fail' if (validate_pad($correctPadString) ne 'true');
    print 'fail' if (validate_pad($incorrectPadStr1) eq 'true');
    print 'fail' if (validate_pad($incorrectPadStr2) eq 'true');
    print 'correct'; 
}

#Input: string as ASCII
sub validate_pad {
    my $block = shift;
    
    my @block = unpack('(H2)*',$block);
    my $pad = $block[$#block];
    
    return 'false' if (hex($pad) == 0x00);
    return 'false' if (hex($pad) > ($#block+1));
    
    for(my $i=0; $i < hex($pad); $i++) {
        ($block[$#block - $i] eq $pad) ? next : return 'false';
    }
    
    return 'true';
}
1;