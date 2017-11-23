##
# $Id: NBlookup.pl,v 1.67 2012-01-28 09:15:15-02 nbrito Exp $
##
#!/bin/sh -- # -*- perl -*-
eval 'exec `which perl` -x -S $0 ${1+"$@"} ;'
	if 0;
###########################################################################
#        _______ __________.__                 __                         #
#        \      \\______   \  |   ____   ____ |  | ____ ________          #
#        /   |   \|    |  _/  |  /  _ \ /  _ \|  |/ /  |  \____ \         #
#       /    |    \    |   \  |_(  <_> |  <_> )    <|  |  /  |_> >        #
#       \____|__  /______  /____/\____/ \____/|__|_ \____/|   __/         #
#               \/       \/                        \/     |__|            #
#                                                                         #
###########################################################################
# Author:         Nelson Brito <nbrito@sekure.org>                        #
# First Release:  October 17th, 2000                                      #
# Review Release: January 15th, 2012                                      #
# Supported OS:   N/A                                                     #
###########################################################################
# Copyright(c) 2000-2012 Nelson Brito. All rights reserved worldwide.     #
#                                                                         #
# This program is free software: you can redistribute it and/or modify it #
# under  the terms of the GNU General Public License  as published by the #
# Free Software Foundation,  either version 3 of the License, or (at your #
# option) any later version.                                              #
#                                                                         #
# This program  is  distributed in  the hope that  it will be useful, but #
# WITHOUT  ANY  WARRANTY;   without   even  the   implied   warranty   of #
# MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See the GNU #
# General Public License for more details.                                #
#                                                                         #
# You  should have  received a copy of the  GNU  General  Public  License #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.   #
###########################################################################
use strict;
use Getopt::Long qw(:config gnu_getopt no_ignore_case);
use Pod::Usage;
use Pod::Select;
use POSIX qw(strftime);
use Socket;
use Switch 'Perl5', 'Perl6';

##
# Really, really old hack...
##
{(($^O=~/^[M]*$32/i) and ($0=~s!.*\\!!)) or ($0=~s!^.*/!!)};

##
# This script was only tested on Perl v5.12.3 and v5.10.1.
##
BEGIN {
	my $subname = (caller(0))[3];
	eval("require 5.012003;");
	eval("require 5.010001;") if $@;
	die "$subname\{\}: Unsupported Perl version ($]). Please, install Perl v5.10.1 or v5.12.3!\n" if $@;
}

##
# RCS identification.
##
my $rcsid  = q($Id: NBlookup.pl,v 1.67 2012-01-28 09:15:15-02 nbrito Exp $);

##
# Version and build information.
##
my $major_version   = (split (/\./, (split(/ /, $rcsid))[2]))[0];
my $minor_version   = (split (/\./, (split(/ /, $rcsid))[2]))[1];
my $build_revision  = 12;
my $build_version   = 120115;
my $build_date      = "Jan 15 2012 20:35:44";

##
# Program variables.
##
my $program_version = "$major_version.$minor_version.$build_revision-$build_version";
my $program_name    = "(Reverse) Name Block Lookup Next Generation [Version $program_version]";
my $program_author  = "Nelson Brito <nbrito\@sekure.org>";

##
# Command Line Interface user's input arguments.
##
my($reverse, $timeout, $filename, $help, $manpage);
GetOptions(
	"r|reverse"    =>  \$reverse,
	"t|timeout=i"  =>  \$timeout,
	"f|filename=s" =>  \$filename,
	"h|?|help"     =>  \$help,
	"m|manpage"    =>  \$manpage
) or die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n";

##
# $ARGV[0] handles the "host[/CIDR]".
##
my $arguments = $#ARGV + 1;

##
# CIDR configuration tiny C algorithm (Perl version).
##
sub cidr {
	my($subname, $address, $bits) = ((caller(0))[3], shift, shift);
	my($all_bits_on, $netmask, $__1st_addr, $hostid) = (0xffffffff, 0, 0, 0);

	(($bits >= 0) and ($bits <= 32))
		or die "$subname\{\}: \"/$bits\" does not seem to be a valid CIDR!\n";
    
	$netmask    = ~($all_bits_on >> $bits);
	$hostid     = (1 << (32 - $bits)) - 1;
	$__1st_addr = ($address & $netmask);

	return($__1st_addr, $hostid, $netmask);
}

##
# IP address/Integer conversion subroutine.
##
sub convert {
	my($subname, $address, $conversion) = ((caller(0))[3], shift, shift);

	given($conversion){
		when("integer") { return(join(".", unpack("C4", (pack("N", $address))))) }
		when("address") { return(unpack("N", pack("C4", split(/\./, $address)))) }
		default         { die "$subname\{\}: \"$conversion\" does not seem to be a valid conversion!\n" }
	}
}

##
# Control-C handler subroutine.
##
sub ctrlc {
	my $subname = (caller(0))[3];
	my $format_time = strftime("%b %e %Y %H:%M:%S", localtime());
	my $message = "$0 command interrupted on $format_time.\n";
    
	store($message) if ($filename);
    
	(close(FILENAME) or die "$subname\{\}: \"$filename\" does not seem to be a valid file!\n") if ($filename);

	die "\b\r" . $message;
}

##
# Main lookup subroutine.
##
sub lookup {
	my($subname, $target, $counter, $found) = ((caller(0))[3], shift, 0, 0);

	((my($target, $bits) = split(/\//, $target)) == 2)
		or pod2usage(1);

	$SIG{"HUP"}  = "IGNORE";
	$SIG{"PIPE"} = "IGNORE";
	$SIG{"INT"}  = "ctrlc";
	$SIG{"ILL"}  = "ctrlc";
	$SIG{"QUIT"} = "ctrlc";
	$SIG{"ABRT"} = "ctrlc";
	$SIG{"TRAP"} = "ctrlc";
	$SIG{"KILL"} = "ctrlc";
	$SIG{"TERM"} = "ctrlc";
	$SIG{"STOP"} = "ctrlc";
	$SIG{"TSTP"} = "ctrlc";
	$SIG{"SEGV"} = "ctrlc";

	my $address = (gethostbyname($target))[4]
		or die "$subname\{\}: \"$target\" does not seem to be a valid IPv4 address!\n";

	my($__1st_addr, $hostid, $netmask) = cidr(convert(inet_ntoa($address), "address"), $bits);

	my @difference = multiple($target, $__1st_addr, $bits);

	($0 =~s/.pl$//) if ($0 =~ /.pl$/);

	my $format_time = strftime("%b %e %Y %H:%M:%S", localtime());
	my $message = "$0 version $program_version built on $build_date.\n" .
		"$0 successfuly launched on $format_time.\n";

	if(@difference > 0){
		$message .= "$0 found {MULTIPLE} IPv4 addresses while resolving \"$target\".\n";
		$message .= "$0 should also be launched for CIDR: ";
		($message .= $_ . "/" . $bits . ", ") foreach(@difference);
		$message =~ s/,\s+$//;
		$message .= ".\n";
	}

	$message .= "$0 using CIDR " . inet_ntoa($address) . "/$bits ["                   .
		convert($__1st_addr, "integer") . "/" . convert($netmask, "integer") . "].\n" .
		"$0 resolving reverse DNS names from \"" . convert($__1st_addr, "integer")     .
		"\" to \"" . convert($__1st_addr + $hostid, "integer") . "\".\n";

	$timeout = $timeout ? $timeout/1000 : 0;

	(open(FILENAME, ">" . $filename) or die "$subname\{\}: \"$filename\" does not seem to be a valid file!\n") if ($filename);

	store($message) if ($filename);

	print $message;

	foreach($__1st_addr .. ($__1st_addr + $hostid)){
		select(undef, undef, undef, $timeout);

		$found++ if (resolve($_));

		$counter++;
	}

	$format_time = strftime("%b %e %Y %H:%M:%S", localtime());
	$message = "$0 found $found reverse DNS names for $counter IP addresses.\n" .
		"$0 successfuly finished on $format_time.\n";

	store($message) if ($filename);

	print $message;

	(close(FILENAME) or die "$subname\{\}: \"$filename\" does not seem to be a valid file!\n") if ($filename);
}

##
# Multiple addresses find sbroutine.
##
sub multiple {
	my($subname, $target, $__1st_addr, $bits) = ((caller(0))[3], shift, shift, shift);
	my @difference;

	my(undef, undef, undef, undef, @addresses) = gethostbyname($target)
		or die "$subname\{\}: \"$target\" does not seem to be a valid IPv4 address!\n";

	foreach(@addresses){
		my($temporary, undef, undef) = cidr(convert(inet_ntoa($_), "address"), $bits);
		push(@difference, inet_ntoa($_)) if not (convert($__1st_addr, "integer") eq convert($temporary, "integer"));
	}

	return(@difference);
}

##
# Reverse DNS name resolve subroutine.
##
sub resolve {
	my($subname, $address, $reverse_only, $status) = ((caller(0))[3], shift, 0, 0);

	my $message = sprintf("%-15s", convert($address, "integer"));

	if(my($reverse_name, undef, undef, undef) = gethostbyaddr(inet_aton($address), PF_INET)){
		$reverse_only = 1 if (($reverse) and not ((gethostbyname($reverse_name))[4]));

		$message .= sprintf(" -> %-40s", $reverse_name);
		$message .= sprintf("%15s", "{REVERSE_ONLY}") if ($reverse_only);
		$message .= sprintf("%s", "\n");

		store($message) if ($filename);
		$status = 1;
	} else {
		$message .= sprintf("%s", "\b\r");
	}

	print $message;

	return($status);
}

##
# Reverse DNS name lookup store subroutine.
##
sub store {
	my $message = shift;

	($message =~ s/$0/# $0/g) if ($message =~ /$0/);

	select(FILENAME); $|=1;
	print $message;

	select(STDOUT); $|=1;
}

##
# Usage and help message.
##
#pod2usage(
#	-message  => "$program_name\n$program_author\n",
#	-verbose  => 1
#) if $help;
pod2usage(
	-message => "$program_name\n$program_author\n",
	-verbose => 99,
	-sections => ["USAGE|OPTIONS|COPYRIGHT"]
) if $help;
##
# Manual page.
##
pod2usage(-verbose => 2) if $manpage;

##
# Missing arguments.
##
die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n" if ($arguments < 1);

##
# Launch main subroutine.
##
select(STDOUT); $|=1;
lookup($ARGV[0]);

##
# POD (Plain Old Documentation) for NBlookup.pl.
##
=pod

=head1 NAME
 
B<NBlookup.pl - (I<Reverse>) Name Block Lookup Next Generation>

=head1 VERSION
 
This document describes B<NBlookup.pl> Version 1.67.12-120115.

=head1 USAGE

C<NBlookup.pl host[E<sol>CIDR] [options]>

=head1 DESCRIPTION
 
B<NBlookup.pl> builds a list of the reverse DNS names based on given DNS name or IPv4 address and given B<CIDR>, by invoking the C<gethostbyaddr()>.

=head2 IPv4 address CIDR

To resolve and build a list of reverse DNS names based on DNS name or IPv4 address,  B<NBlookup.pl> requires to lookup the reverse DNS names for a whole network. To achieve this goal, B<NBlookup.pl> supports CIDR.

"E<sol>CIDR" B<MUST> be appended to an IPv4 address or DNS name, and B<NBlookup.pl> will lookup the reverse DNS name of every IPv4 address for which the first IPv4 address is the same as for the reference given IPv4 address or DNS name.

For example, C<192.168.10.0E<sol>24> would resolve the 256 reverse DNS names between C<192.168.10.0>  (binary notation: C<11000000 10101000 00001010 00000000>) and C<192.168.10.255> (binary notation: C<11000000 10101000 00001010 11111111>). The C<192.168.10.40E<sol>24> would resolve exactly the same reverse DNS names.

The smallest allowed value is C<E<sol>0>, which resolves the whole Internet reverse DNS names, and the largest value is C<E<sol>32>, which resolves a single reverse DNS name.
 
To support this feature B<NBlookup.pl> applies the same B<algorithm> used by L<T50|http://t50.sourceforge.net>, and this B<algorithm> is based on three code lines which are explained below:

=over 4

=item 1) C<$netmask = ~($all_bits_on E<gt>E<gt> $bits);>

Calculate the network mask.

=over 4

=item * Bitwise B<SHIFT RIGHT> (E<gt>E<gt>) C<0xffffffff> using given B<CIDR>, resulting in the number of bits to calculate the network mask.

=item * Bitwise logic B<NOT> (~) turns off the bits that are on and turns on the bits that are off, resulting in the network mask.

=back

=item 2) C<$hostid = (1 E<lt>E<lt> (32 - $bits)) - 1;>

Calculate the number of available IPv4 addresses.

=over 4

=item * Subtract given B<CIDR> from 32, resulting in the host identifier's (bits) portion for the given IPv4 address.

=item * Bitwise B<SHIFT LEFT> (E<lt>E<lt>) C<1> and decrementing C<1>, resulting in the total number of IPv4 addresses available for the given B<CIDR>.

=back

=item 3) C<$__1st_addr = ($address & $netmask);>

Calculate the first available IPv4 address.

=over 4

=item * Bitwise logic B<AND> (&) given IPv4 address and network mask, resulting in the first available IPv4 address for given B<CIDR>.

=back

=back

=head2 C<{REVERSE_ONLY}> warning

Once the reverse DNS name has been found, B<NBlookup.pl> invokes the C<gethostbyname()> to determine if the DNS name is also available (defined by C<-r,--reverse> option).

If the DNS name has not been found by C<gethostbyname()>, it means that only the reverse DNS name is available, and, in this case, B<NBlookup.pl> will trigger the C<{REVERSE_ONLY}> warning message.

This behavior is not so unusual, and often happens when the DNS Server's administrator has deleted the DNS name entry without deleting the reverse DNS name entry.

=head2 C<{MULTIPLE}> IPv4 addresses

In some environments, a single DNS name may have multiple IPv4 addresses, and, in this case, B<NBlookup.pl> will test whether these multiple IPv4 addresses are in the same B<CIDR>, alerting any and all other IPv4 addresses for a single DNS name which are out of the given B<CIDR>.

=head1 OPTIONS

=over 4
 
=item C<host>
 
Configure the DNS name or IPv4 address.
 
=item C<[E<sol>CIDR]>
 
Configure the B<CIDR> (I<Classless Inter-Domain Routing>) to build IPv4 addresses.
 
See section L</"IPv4 address CIDR"> for further information.

=item C<-r,--reverse> B<(default OFF)>
 
Enable the C<{REVERSE_ONLY}> warning message, i.e., during the reverse DNS name lookup, for each IPv4 address, the B<NBlookup.pl> is capable to test whether the DNS name is only available through the reverse DNS name lookup.

See section L</"{REVERSE_ONLY} warning"> for further information.

=item C<-t,--timeout NUM> B<(default 0)>

Configure a specific timeout (milliseconds) allowing B<NBlookup.pl> to wait until execute the next reverse DNS name lookup.

B<I<IT IS STRONGLY RECOMMENDED TO AVOID DNS FLOOD AND/OR DENIAL-OF-SERVICE.>>

=item C<-f,--filename FILE> B<(default NONE)>

Save all the reverse DNS name lookup results to a text file.

=item C<-m,--manpage>

Display the manual page embedded in B<NBlookup.pl>, being the manual page in POD (Plain Old Documentation) format.

=item C<-h,-?,--help>

Display the help and usage message.

=back

=head1 EXAMPLES

=over 4

=item C<NBlookup.pl www.example.comE<sol>24> 

B<NBlookup.pl> will resolve reverse DNS names from C<192.0.43.0> to C<192.0.43.255>.

=item C<NBlookup.pl www.example.comE<sol>24 --filename example.txt> 

B<NBlookup.pl> will resolve reverse DNS names from C<192.0.43.0> to C<192.0.43.255>, saving all the reverse DNS name lookup results to a text file.

=item C<NBlookup.pl www.example.comE<sol>24 --filename example.txt --reverse> 

B<NBlookup.pl> will resolve reverse DNS names from C<192.0.43.0> to C<192.0.43.255>, saving all the reverse DNS name lookup results to a text file and warning C<{REVERSE_ONLY}>.

=item C<NBlookup.pl www.example.comE<sol>24 --timeout 500> 

B<NBlookup.pl> will resolve reverse DNS names from C<192.0.43.0> to C<192.0.43.255>, waiting 500 milliseconds to perform the next reverse DNS name lookup.

=back

=head1 DEPENDENCIES

=over 4

=item C<Getopt::Long(3)>

See "L<Getopt::Long's Perl Documentation|Getopt::Long/"DESCRIPTION">" for further information.

=item C<POSIX(1)>
 
See "L<POSIX's Perl Documentation|POSIX/"DESCRIPTION">" for further information.

=item C<Pod::Usage(3)>
 
See "L<Pod::Usage's Perl Documentation|Pod::Usage/"DESCRIPTION">" for further information.
 
=item C<Socket(3)>

See "L<Socket's Perl Documentation|Socket/"DESCRIPTION">" for further information.

=item C<Switch(3)>

See "L<Switch's Perl Documentation|Switch/"DESCRIPTION">" for further information.

=item C<PERL(1)> v5.10.1 or v5.12.3

B<NBlookup.pl> has been widely tested under Perl v5.10.1 (Ubuntu 10.04 LTS) and Perl v5.12.3 (Mac OS X Lion). Due to this, B<NBlookup.pl> requires one of the mentioned versions to be executed. The following tests will be performed to ensure its capabilities:

BEGIN {

	my $subname = (caller(0))[3];

	eval("require 5.012003;");
	eval("require 5.010001;") if $@;
	die "$subname\{\}: Unsupported Perl version ($]).\n" if $@;

}

If you are confident that your Perl version is capable to execute the B<NBlookup.pl>, please, remove the above tests and send an update message to the L<author|"AUTHOR">.

=back

=head1 SEE ALSO

GETHOSTBYNAME(3), L<Getopt::Long(3)|Getopt::Long>, L<Pod::Usage(3)|Pod::Usage>, L<POSIX(1)|POSIX>, L<Socket(3)|Socket>, L<Switch(3)|Switch>, PERL(1)

=head1 HISTORY

B<NBlookup.pl> was first developed as part of the unpublished "I<Penetration Test Toolkit>", in early 2000s, by B<Nelson Brito>.

=head1 BUGS AND LIMITATIONS

Report B<NBlookup.pl> bugs and limitations directly to the L<author|"AUTHOR">.

=head1 AUTHOR

B<Nelson Brito> L<mailto:nbrito@sekure.org>.

=head1 COPYRIGHT

Copyright(c) 2000-2012 B<Nelson Brito>. All rights reserved worldwide.

=head1 LICENSE

This program is free software: you can redistribute it and/or modify it under the terms of the I<GNU General Public License> as published by the B<Free Software Foundation>, either version 3 of the License, or (at your option) any later version.

You should have received a copy of the I<GNU General Public License> along with this program. If not, see L<http://www.gnu.org/licenses/>.  

=head1 DISCLAIMER OF WARRANTY

This program is distributed in the hope that it will be useful, but B<WITHOUT ANY WARRANTY>; without even the implied warranty of B<MERCHANTABILITY> or B<FITNESS FOR A PARTICULAR PURPOSE>. See the I<GNU General Public License> for more details.

=cut
