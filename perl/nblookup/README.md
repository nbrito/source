```
NBLOOKUP(1)           User Contributed Perl Documentation          NBLOOKUP(1)



NAME
       NBlookup.pl - (Reverse) Name Block Lookup Next Generation

VERSION
       This document describes NBlookup.pl Version 1.67.12-120115.

USAGE
       "NBlookup.pl host[/CIDR] [options]"

DESCRIPTION
       NBlookup.pl builds a list of the reverse DNS names based on given DNS
       name or IPv4 address and given CIDR, by invoking the "gethostbyaddr()".

   IPv4 address CIDR
       To resolve and build a list of reverse DNS names based on DNS name or
       IPv4 address,  NBlookup.pl requires to lookup the reverse DNS names for
       a whole network. To achieve this goal, NBlookup.pl supports CIDR.

       "/CIDR" MUST be appended to an IPv4 address or DNS name, and
       NBlookup.pl will lookup the reverse DNS name of every IPv4 address for
       which the first IPv4 address is the same as for the reference given
       IPv4 address or DNS name.

       For example, "192.168.10.0/24" would resolve the 256 reverse DNS names
       between 192.168.10.0  (binary notation: "11000000 10101000 00001010
       00000000") and 192.168.10.255 (binary notation: "11000000 10101000
       00001010 11111111"). The "192.168.10.40/24" would resolve exactly the
       same reverse DNS names.

       The smallest allowed value is "/0", which resolves the whole Internet
       reverse DNS names, and the largest value is "/32", which resolves a
       single reverse DNS name.

       To support this feature NBlookup.pl applies the same algorithm used by
       T50 <http://t50.sourceforge.net>, and this algorithm is based on three
       code lines which are explained below:

       1) "$netmask = ~($all_bits_on >> $bits);"
           Calculate the network mask.

           o   Bitwise SHIFT RIGHT (>>) 0xffffffff using given CIDR, resulting
               in the number of bits to calculate the network mask.

           o   Bitwise logic NOT (~) turns off the bits that are on and turns
               on the bits that are off, resulting in the network mask.

       2) "$hostid = (1 << (32 - $bits)) - 1;"
           Calculate the number of available IPv4 addresses.

           o   Subtract given CIDR from 32, resulting in the host identifier's
               (bits) portion for the given IPv4 address.

           o   Bitwise SHIFT LEFT (<<) 1 and decrementing 1, resulting in the
               total number of IPv4 addresses available for the given CIDR.

       3) "$__1st_addr = ($address & $netmask);"
           Calculate the first available IPv4 address.

           o   Bitwise logic AND (&) given IPv4 address and network mask,
               resulting in the first available IPv4 address for given CIDR.

   "{REVERSE_ONLY}" warning
       Once the reverse DNS name has been found, NBlookup.pl invokes the
       "gethostbyname()" to determine if the DNS name is also available
       (defined by "-r,--reverse" option).

       If the DNS name has not been found by "gethostbyname()", it means that
       only the reverse DNS name is available, and, in this case, NBlookup.pl
       will trigger the "{REVERSE_ONLY}" warning message.

       This behavior is not so unusual, and often happens when the DNS
       Server's administrator has deleted the DNS name entry without deleting
       the reverse DNS name entry.

   "{MULTIPLE}" IPv4 addresses
       In some environments, a single DNS name may have multiple IPv4
       addresses, and, in this case, NBlookup.pl will test whether these
       multiple IPv4 addresses are in the same CIDR, alerting any and all
       other IPv4 addresses for a single DNS name which are out of the given
       CIDR.

OPTIONS
       "host"
           Configure the DNS name or IPv4 address.

       "[/CIDR]"
           Configure the CIDR (Classless Inter-Domain Routing) to build IPv4
           addresses.

           See section "IPv4 address CIDR" for further information.

       "-r,--reverse" (default OFF)
           Enable the "{REVERSE_ONLY}" warning message, i.e., during the
           reverse DNS name lookup, for each IPv4 address, the NBlookup.pl is
           capable to test whether the DNS name is only available through the
           reverse DNS name lookup.

           See section "{REVERSE_ONLY} warning" for further information.

       "-t,--timeout NUM" (default 0)
           Configure a specific timeout (milliseconds) allowing NBlookup.pl to
           wait until execute the next reverse DNS name lookup.

           IT IS STRONGLY RECOMMENDED TO AVOID DNS FLOOD AND/OR DENIAL-OF-
           SERVICE.

       "-f,--filename FILE" (default NONE)
           Save all the reverse DNS name lookup results to a text file.

       "-m,--manpage"
           Display the manual page embedded in NBlookup.pl, being the manual
           page in POD (Plain Old Documentation) format.

       "-h,-?,--help"
           Display the help and usage message.

EXAMPLES
       "NBlookup.pl www.example.com/24"
           NBlookup.pl will resolve reverse DNS names from 192.0.43.0 to
           192.0.43.255.

       "NBlookup.pl www.example.com/24 --filename example.txt"
           NBlookup.pl will resolve reverse DNS names from 192.0.43.0 to
           192.0.43.255, saving all the reverse DNS name lookup results to a
           text file.

       "NBlookup.pl www.example.com/24 --filename example.txt --reverse"
           NBlookup.pl will resolve reverse DNS names from 192.0.43.0 to
           192.0.43.255, saving all the reverse DNS name lookup results to a
           text file and warning "{REVERSE_ONLY}".

       "NBlookup.pl www.example.com/24 --timeout 500"
           NBlookup.pl will resolve reverse DNS names from 192.0.43.0 to
           192.0.43.255, waiting 500 milliseconds to perform the next reverse
           DNS name lookup.

DEPENDENCIES
       Getopt::Long(3)
           See "Getopt::Long's Perl Documentation" for further information.

       POSIX(1)
           See "POSIX's Perl Documentation" for further information.

       Pod::Usage(3)
           See "Pod::Usage's Perl Documentation" for further information.

       Socket(3)
           See "Socket's Perl Documentation" for further information.

       Switch(3)
           See "Switch's Perl Documentation" for further information.

       PERL(1) v5.10.1 or v5.12.3
           NBlookup.pl has been widely tested under Perl v5.10.1 (Ubuntu 10.04
           LTS) and Perl v5.12.3 (Mac OS X Lion). Due to this, NBlookup.pl
           requires one of the mentioned versions to be executed. The
           following tests will be performed to ensure its capabilities:

           BEGIN {

                   my $subname = (caller(0))[3];

                   eval("require 5.012003;");
                   eval("require 5.010001;") if $@;
                   die "$subname\{\}: Unsupported Perl version ($]).\n" if $@;

           }

           If you are confident that your Perl version is capable to execute
           the NBlookup.pl, please, remove the above tests and send an update
           message to the author.

SEE ALSO
       GETHOSTBYNAME(3), Getopt::Long(3), Pod::Usage(3), POSIX(1), Socket(3),
       Switch(3), PERL(1)

HISTORY
       NBlookup.pl was first developed as part of the unpublished "Penetration
       Test Toolkit", in early 2000s, by Nelson Brito.

BUGS AND LIMITATIONS
       Report NBlookup.pl bugs and limitations directly to the author.

AUTHOR
       Nelson Brito <mailto:nbrito@sekure.org>.

COPYRIGHT
       Copyright(c) 2000-2012 Nelson Brito. All rights reserved worldwide.

LICENSE
       This program is free software: you can redistribute it and/or modify it
       under the terms of the GNU General Public License as published by the
       Free Software Foundation, either version 3 of the License, or (at your
       option) any later version.

       You should have received a copy of the GNU General Public License along
       with this program. If not, see <http://www.gnu.org/licenses/>.

DISCLAIMER OF WARRANTY
       This program is distributed in the hope that it will be useful, but
       WITHOUT ANY WARRANTY; without even the implied warranty of
       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
       General Public License for more details.



perl v5.18.2                      2012-01-15                       NBLOOKUP(1)

```
