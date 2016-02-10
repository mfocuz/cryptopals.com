#! /usr/bin/perl
use strict;

# Task 19: Break fixed-nonce CTR mode using sunstitutions
# TBD, decrypts input, but % of recovered data is too low, chech task19.py, probably can help
use Crypt::OpenSSL::AES;
use List::Util qw(max min);

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task03.single_byte_xor.pl";
    require "$PATH/../set1/task04.detect_single_byte_xor.pl";
    require "$PATH/../set1/task06.break_reapeating_key_xor.pl";
    require "$PATH/../set2/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/task18.implement_ctr_stream_cipher_mode.pl";
    
    # all strings from task are in tests.input/20.txt
    my $file = $ARGV[0];
    open(my $fh, '<', $file) or print "bams\n";
    
    my @strings;
    my $stringIndex = 0;
    while (<$fh>) {
        chomp;
        $strings[$stringIndex] = $_;
        $stringIndex++;
    }
    
    
    # Generate random key and set fixed rand nonce
    #my $key = gen_rand_bytes(16);
    my $key = "41424344454647484950515253545556";
    #my $nonce = int (rand(255));
    my $nonce = 0;
    # tmp
    my $aes = Crypt::OpenSSL::AES->new($key);
    my $kk = "";
    $nonce = join('',reverse (sprintf("%.16x",$nonce) =~ /../g));
    for (my $i=0; $i<=1; $i++) {
        my $ctrLittleEnd = join('',reverse (sprintf("%.16x",$i) =~ /../g));
        $kk .= $aes->encrypt(pack('H*',$nonce.$ctrLittleEnd));
    }
    #print unpack('H*',$kk)."\n";
    
    # Encrypt all strings separately and save plaintexts to @pts  # 496620616e2045746865726e6574206672616d6520636f6d657320757020a
    my @ciphers; # = map {pack('H*',$_)} @strings;
    my @pts;
    foreach my $string (@strings) {
        my $ct = ctr_encrypt(base64_decode($string),$key,$nonce);
        push @ciphers,$ct;
        push @pts,base64_decode($string);
    }
    
    # $pts will be used after break encryption to compare results of decryption with original PT
    my $pts = unpack('H*',join('',@pts));
    #print join('',@pts)."\n";
    my $ptsLength = (length $pts) / 2;
    
    # Determine shortest and longest string
    my $minLength = length($ciphers[0]);
    my $maxLength = length($ciphers[0]);
    my $shortestIndex;
    for(my $i=0; $i<=$#ciphers; $i++) {
        if (length($ciphers[$i]) < $minLength) {
            $minLength = length($ciphers[$i]);
            $shortestIndex = $i;
        }
        $maxLength = length($ciphers[$i]) if (length($ciphers[$i]) > $maxLength);
    }

    # Truncate all strings to length of shortest string
    map {$ciphers[$_] = substr($ciphers[$_],0,$minLength)} 0..$#ciphers;
    #map {$ciphers[$_] = $ciphers[$_].("\x00" x ($maxLength - length($ciphers[$_])))} 0..$#ciphers;
    my $keyCandidate = decrypt_multiple_xor_with_space_detection(\@ciphers);
    #print $keyCandidate."\n";
    #print join('',@pts)."\n";
    #my $temp1 = unpack('H*',join('',@ciphers));
    #print "$temp1\n";
    #my $temp2 = expand_key($keyCandidate,($minLength * ($#ciphers+1)));
    #print "$temp2\n";
    my $ptResult = rox(expand_key($keyCandidate,($minLength * ($#ciphers+1))),unpack('H*',join('',@ciphers)));
    my @R = map {(pack('H*',$_) =~ /[[:alpha:]]|\s/) ? $_ : '2e'} ($ptResult =~ /(..)/g);
    print pack('H*',join('',@R));
}

# Function recover key for OTP encryption with one key used for multiple encryptions
# Method used: comparing result of cipher1 ^ cipher2 with 0x40, means = detect positions of space(0x20)
# Input: array of ciphers
# Return: key as ascii string with hex codes
sub decrypt_multiple_xor_with_space_detection {
    my $ciphers = shift;
    my $cipherCount = scalar @$ciphers;
    
    my %keyCandidate;

    # Xor ciphers with each other and build space appearence statistic
    for (my $i=0;$i<=$cipherCount;$i++) {
        my %spaceStat;
        for (my $j=0;$j<=$cipherCount;$j++) {
            next if $i == $j;
            my $c1 = unpack('H*',$ciphers->[$i]);
            my $c2 = unpack('H*',$ciphers->[$j]);
            
            my @c1xorc2 = rox($c1,$c2) =~ /(..)/g;
            my @spacesIndex = grep {hex($c1xorc2[$_]) >= 0x40} 0..$#c1xorc2;
            map {$spaceStat{$_}++} @spacesIndex;
        }
        
        my $max = max values %spaceStat;
        my $min = min values %spaceStat;
        my $pivot = int (($max - $min) * 0.95 + $min);
        my @keyByteCandidatesIndex = grep {$spaceStat{$_} > $pivot} keys %spaceStat;
        
        my @c1 = unpack('(H2)*',$ciphers->[$i]);
        map {$keyCandidate{$_} = rox($c1[$_],"20")} @keyByteCandidatesIndex;
    }
    my @hashKeys = sort {$a <=> $b} keys %keyCandidate;
    return join('',map {(defined $keyCandidate{$_}) ? $keyCandidate{$_} : '00' } 0..$hashKeys[$#hashKeys]);
}

1;