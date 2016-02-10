#!/usr/bin/perl
use strict;

# Task 21: Implement the MT19937 Mersenne Twister PRNG

# Include module for tests
use Math::Random::MT;
use Math::Random::MT::Perl;

if (!caller) {
    # Test generator
    my $rand = mt19937_gen(0x00000001);
    #100% correct PRNG
    my $gen = Math::Random::MT->new(0x00000001);
    # Compare results for first 100 numbers
    foreach (0..623) {
        if ($rand->() != $gen->irand()) {
            print 'fail';
            exit 0;
        }
    }
    print 'correct';
}

# Functional style
sub mt19937_gen {
    my $seed = shift;
    
    my $index;
    my @mt;
    
    my $_int32 = sub {
        my $x = shift;
        return int(0xffffffff & $x);
    };
    
    my $init = sub {
        my $seed = shift;
        $index = 624;
        @mt = (0) x 624;
        $mt[0] = $seed;
        foreach my $i (1..623) {
            my $tmp = $_int32->(1812433253 * ($mt[$i-1] ^ $mt[$i-1] >> 30) + $i);
            $mt[$i] = $tmp;
            #print "state index:$i value :$tmp\n";
        }
        #print join("\n",@mt);
    };
    
    my $twist = sub {
        foreach my $i (0..623) {
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            my $y = $_int32->($_int32->(($mt[$i] & 0x80000000)) + $_int32->(($mt[($i+1)%624] & 0x7fffffff)));
            $mt[$i] = $mt[($i + 397) % 624] ^ $y >> 1;
            if ($y % 2) {
                $mt[$i] ^= 0x9908b0df;
            }
            #print "Last state: ".$mt[$i]."\n";
        }
        $index = 0;
    };
    
    my $extract_number = sub {
        $twist->() if ($index >= 624);
        
        my $y = $mt[$index];
        #print 'my $y = $mt[$index] --->'."$y\n";
        $y ^= $y >> 11;
        #print '$y ^= $y >> 11 --->'."$y\n";
        $y ^= ($y << 7) & 2636928640;
        #print '$y ^= ($y << 7) & 2636928640 --->'."$y\n";
        $y ^= ($y << 15) & 4022730752;
        #print '$y ^= ($y << 15) & 4022730752 --->'."$y\n";
        $y ^= $y >> 18;
        #print '$y ^= $y >> 18 --->'."$y\n";
        
        $index++;
        #print "next value: ".$_int32->($y)."\n";
        return $_int32->($y);
    };
    
    $init->($seed);
    
    return $extract_number;
}

1;