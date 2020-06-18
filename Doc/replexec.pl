#! /usr/bin/perl
# replaces lines starting with $exec by the output
# of the command after $exec
# that means that a line containing
# $exec command parameters
# is first echoed (without $exec), and then executed,
# and the resulting output is printed (with a leading tab)
#
# hvf 17.05.2015

use strict;

	while (<>) {
		/^\$exec/i && do { 		# line starts with $exec
			s/^\$exec\s*//i;	# delete $exec and leading white space
			print "\t\$ $_";	# print command, parameters
			my $out = qx/$_/;	# execute command
			$out =~ s/\n/\n\t/g;# insert a tab for each line
			print "\t".$out;	# print the output
			next;
		};
		print $_;				# not $exec, just print
	}
