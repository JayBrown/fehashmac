#! /usr/bin/perl
use strict;

    my %algotime;
    my %algobytes;
    my $lines = 0;

    my $loops = $ENV{"NLOOPS"};
    my $bytesperloop = $ENV{"NBYTES"};

    while (<>) {
        my ($algo, $t, $bytes) = split;
        push @{$algotime{$algo}}, $t;
        # push @{$algobytes{$algo}}, $bytes; ## not needed here
    }
    #print %algotime ,"\n";
    foreach my $key (sort keys %algotime) {
        #print "key $key\n";
        #print "@{$algotime{$key}}\n";
        my $tot = 0.0;
        my $n = 0.0;
        foreach my $t (@{$algotime{$key}}) {
            #print "time $t\n";
            $tot += $t;
            $n++;
        }
        $tot /= $n;
        my $btot = $loops*$bytesperloop/$tot;
        printf "%-10s %6.3f  %10d\n", $key, $tot, $btot
    }
