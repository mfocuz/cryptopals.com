#!/usr/bin/perl
use strict;

# Task 23: Clone an MT19937 RNG from its output

if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set3/task21.implement_mt19937_rng.pl";
    
    my $gen = mt19937_gen(0x00000001);
    my $reverse = reverse_mt19937();
    # generate some values to perform twist in the original generator in the middle of its state(index)
    $gen->(2**32) foreach (0..300);
    my @initState;
    foreach(0..623) {
        my $rand = $gen->();
        my $ret = $reverse->($rand);
        push @initState,@$ret if ($ret != -1 and ref $ret == 'ARRAY');
    }
    
    my $reverseGen = mt19937_gen_from_state(\@initState);
    
    # Test
    my $tests = 100;
    my $successTests = 0;
    foreach (1..$tests) {
        my $rand = $gen->();
        my $reverseRand = $reverseGen->();
        $successTests++ if ($rand == $reverseRand);
    }
    
    ($tests == $successTests) ? print 'correct' : print 'fail';
}

sub reverse_mt19937 {

    my @mt;
    my $index = 0;
    
    my $_int32 = sub {
        my $x = shift;
        return int(0xffffffff & $x);
    };
    
    my $reverse_right_shift = sub {
        my ($value,$shift) = @_;
        
        my $i = 0;
        my $result = 0;
        
        while ($i * $shift < 32) {
            my $partMask = $_int32->($_int32->(-1 << (32 - $shift)) >> ($shift * $i));
            my $part = $value & $partMask;
            $value ^= $part >> $shift;
            $result |= $part;
            $i++;
        }
        return $result;
    };
    
    my $reverse_left_shift = sub {
        my ($value,$shift,$mask) = @_;
        
        my $i = 0;
        my $result = 0;

        while ($i * $shift < 32) {
            my $partMask = $_int32->($_int32->(-1) >> (32 - $shift) << ($shift * $i));
            my $part = $value & $partMask;
            $value ^= ($part << $shift) & $mask;
            $result |= $part;
            $i++;
        }
        return $result;
    };
    
    my $reverse = sub {
        my $y = shift;
        
        # Perform extract_number func steps in reverse order
        $y = $reverse_right_shift->($y,18);
        $y = $reverse_left_shift->($y,15,4022730752);
        $y = $reverse_left_shift->($y,7,2636928640);
        $y = $reverse_right_shift->($y,11);
        
        $mt[$index] = $_int32->($y);
        $index++;
        
        if ($#mt >=623) {
            return \@mt;
        }

        return -1;
    };
    
    return $reverse;
}

sub mt19937_gen_from_state {
    my $mt = shift;
    
    my $index = 624;
    
    my $_int32 = sub {
        my $x = shift;
        return int(0xffffffff & $x);
    };
        
    my $twist = sub {
        foreach my $i (0..624) {
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            my $y = $_int32->($_int32->(($mt->[$i] & 0x80000000)) + $_int32->(($mt->[($i+1)%624] & 0x7fffffff)));
            $mt->[$i] = $mt->[($i + 397) % 624] ^ $y >> 1;
            if ($y % 2) {
                $mt->[$i] ^= 0x9908b0df;
            }
        }
        $index = 0;
    };
    
    my $extract_number = sub {
        $twist->() if ($index >= 624);
        
        my $y = $mt->[$index];
        $y ^= $y >> 11;
        $y ^= ($y << 7) & 2636928640;
        $y ^= ($y << 15) & 4022730752;
        $y ^= $y >> 18;
        
        $index++;
        return $_int32->($y);
    };
        
    return $extract_number;
}
1;