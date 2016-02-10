#!/usr/bin/perl

use strict;
use Test::Simple;
use IPC::System::Simple qw(system capture);

# Due to I have to changed functions in previous tasks while completing a new one,
# and this functions can be used through other tasks,
# this tool will check if all other tasks are not broken after changes
my ($PATH,$SCRIPTNAME) = $0 =~ /(.*)\/(.*\.pl)$/;
my $TESTINPUTDIR = "test.inputs";
# Open root dir and find all task .pl files
opendir(my $dh, './');
my @taskSets = grep {/set\d/} readdir($dh);
close $dh;

my @allTasks;
foreach my $dir (@taskSets) {
    opendir(my $dh,$dir);
    my @tasks = grep {/task/} readdir($dh);
    push @allTasks,map {"$dir/$_"} @tasks;
}

# Run all files and perform tests
my @sorted = sort {$a cmp $b} @allTasks;
foreach my $task (sort @allTasks) {
    my ($taskNum) = $task =~ m/task(\d+)\..*/;
    my $taskInput = (-e "$PATH/$TESTINPUTDIR/".sprintf("%d",$taskNum).".txt") ? "$PATH/$TESTINPUTDIR/".sprintf("%d",$taskNum).".txt" : '';
    my $res = capture("perl ./$task $taskInput 2>/dev/null");
    ok($res eq 'correct', $task);
}