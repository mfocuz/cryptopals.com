#! /usr/bin/perl
use strict;

# Task 20: Break fixed-nonce CTR mode with statistc
use Crypt::OpenSSL::AES;

# Detect if we are included
if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set1/task01.hex_to_base64.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    require "$PATH/../set1/task03.single_byte_xor.pl";
    require "$PATH/../set1/task04.detect_single_byte_xor.pl";
    require "$PATH/../set2/task11.ecb_cbc_detect_oracle.pl";
    require "$PATH/task18.implement_ctr_stream_cipher_mode.pl";
    
    # all strings from task are in tests.input/19.txt
    my $file = $ARGV[0];
    open(my $fh, '<', $file) or print "bams\n";
    
    # Read all inputs to array
    my @strings;
    my $stringIndex = 0;
    while (<$fh>) {
        chomp;
        $strings[$stringIndex] = $_;
        $stringIndex++;
    }
    
    # Generate random key and set fixed rand nonce
    my $key = gen_rand_bytes(16);
    my $nonce = int (rand(255));
    # Set nonce as little-endian 8 byte
    my $n = join('',reverse (sprintf("%.16x",$nonce) =~ /../g));
    my $aes = Crypt::OpenSSL::AES->new($key);
        
    # Encrypt all strings separately and save plaintexts to @pts
    my @ciphers;
    my @pts;
    foreach my $string (@strings) {
        my $ct = ctr_encrypt(base64_decode($string),$key,$nonce);
        push @ciphers,unpack('H*',$ct);
        push @pts,base64_decode($string);
    }
    
    # $pts will be used after break encryption to compare results of decryption with original PT
    my $pts = unpack('H*',join('',@pts));
    my $ptsLength = (length $pts) / 2;
    
    # Due to nonce is fixed, CTR mode becomes a stream cipher with the same key
    # After that we can find plain text based on single xor detection method solved in task 4
    
    # Determine shortest and longest string, actually not sure if we need shortest one, just in case:)
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

    # Now go through each 1st byte of each cipher, then each 2nd byte, and so on
    # Union these bytes on the same positions to strings, and break with ASCII chars detection from task4
    my $guessedKey = "";
    my @ciphersCopy = @ciphers;
    # Due to we take longest string == we try to break longest possible key for our inputs,
    # But keep in mind, the less inputs with appropriate length we have =>
    # then more probabilty of success guess will be reduced
    #
    # That means if we have string with length 30-40 chars, and for instance one string with 41 chars =>
    # guess for this string 41 byte of key would be impossible
    for (my $i=0; $i<=$maxLength; $i++) {
        my $singleXorStr;
        foreach my $cipher (@ciphersCopy) {
            $singleXorStr .= substr($cipher,0,2,'');
        }
        $guessedKey .= break_single_byte_xor_with_ascii($singleXorStr,'[[:alpha:]]|\s');
    }
    # Now XOR all ciphers with guessed key and join to final PT after break
    my @pt = map {rox($guessedKey,$_)} @ciphers;
    my $ptsAfterBreak = join('',@pt);
    
    # Compare decrypted text with original, to do this we XOR both plain texts
    my $diff = rox($pts,$ptsAfterBreak);
    
    # Then calculate number of null bytes
    my $p;
    map {$p++ if $_ eq '00'} ($diff =~ /../g);
    
    # Handle diff as percent
    my $percentOfIdent = ($p / $ptsLength) * 100;
    ($percentOfIdent > 90) ? print 'correct' : print 'fail';
}

1;