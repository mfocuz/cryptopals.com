#!/bin/perl
use strict;

# Task 24: Create the MT19937 stream cipher and break it
use Math::Random::MT;

if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set3/task21.implement_mt19937_rng.pl";
    require "$PATH/../set3/task23.clone_mt19937_rng_from_its_output.pl";
    require "$PATH/../set1/task02.fixed_xor.pl";
    
    my $bit16 = 2**16;
    my $seed = int rand($bit16 );
    
    # Test encryption and decryption functions
    my $enc_test = stream_mt19937_encrypt($seed);
    my $dec_test = stream_mt19937_decrypt($seed);
    
    my $ct = $enc_test->("AAAA");
    my $pt = $dec_test->($ct);
    
    print 'fail' and exit if ($pt ne "AAAA");

    # Encrypt known plain text prefixed with random chars
    my $AA = "A" x 14;
    my $prefix;
    $prefix .= chr(int(rand(57)) + 65) foreach (0..rand(100));
    
    my $enc = stream_mt19937_encrypt($seed);
    my $cipher = unpack('H*',$enc->($prefix.$AA));

    # Use Math::Random::MT module but w/o seed=0 due to bug in module
    my $dec = Math::Random::MT->new;
    # Brute all possible values for 16 bit seed
    foreach my $testedSeed (1..$bit16) {
        #print "Current: $testedSeed\n" if ($testedSeed % 1000 == 0);
        
        $dec->set_seed($testedSeed);
        my $key;
        my $length = (length $cipher)/2;
        $key .= chr((int $dec->irand()) % 256) foreach (1..$length);
        
        # Decrypt cipher and compare plain text with original "user input" (A x 14)
        my $pt = pack('H*',rox(unpack('H*',$key),$cipher));
        if ($pt =~ /$AA$/) {
            ($testedSeed == $seed) ? print 'correct' : next;
            exit;
        }
    }
    
    # If no seed found, something went wrong...
    print 'fail';
}



# Enc/Dec funcs
sub stream_mt19937_encrypt {
    my $seed = shift;
    
    my $gen = mt19937_gen($seed);

    my $encrypt = sub {
        my $input = shift;
        my $ct;
        foreach (split //,$input) {
            $ct .= chr(ord($_) ^ ($gen->() % 256));
        }
        
        return $ct;
    };
    
    return $encrypt;
}

sub stream_mt19937_decrypt {
    my $seed = shift;
    
    my $gen = mt19937_gen($seed);
    
    my $decrypt = sub {
        my $input = shift;
        my $pt;
        foreach (split //,$input) {
            $pt .= chr(ord($_) ^ ($gen->() % 256));
        }
        
        return $pt;
    };
    
    return $decrypt;
}
