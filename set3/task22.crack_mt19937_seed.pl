#!/usr/bin/perl -w
use strict;

# Task 22: Crack an MT19937 seed

if (!caller) {
    my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
    require "$PATH/../set3/task21.implement_mt19937_rng.pl";

    my $seedCandidates = mt19937_unixtime_breaker(time,100,3600);
    my $tests = 5;
    my $successTests = 0;
    foreach(1..$tests) {
        sleep (int rand(2) + 1);
        my $time = time;
        my $gen = mt19937_gen($time);
        sleep (int rand(2) + 1);
        my $rand = $gen->(2**32);
        if (defined $seedCandidates->{$rand}) {
            ($seedCandidates->{$rand} == $time) ?
                $successTests++:
                print "seed is not correct!\n";
        } else {
            print "crack failed\n";
        }
    }

    ($successTests == $tests)? print 'correct' : print 'fail';
}

# seed breaker based on 1st generated value, useful for break seeds based on unix timestamps
sub mt19937_unixtime_breaker {
    my ($seed,$lowerBound,$upperBound) = @_;
    
    my %seedHash;
    use Math::Random::MT;
    my $gen = Math::Random::MT->new();
    
    foreach my $s (($seed-$lowerBound)..($seed+$upperBound)) {
        $gen->set_seed($s);
        my $rand = $gen->irand();
        $seedHash{$rand} = $s;
    }
    
    return \%seedHash;
}