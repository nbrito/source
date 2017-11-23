##
# $Id: ESF.pl,v 1.42 2012-12-24 10:21:44-02 nbrito Exp $
##
#!/bin/sh -- # -*- perl -*-
eval 'exec `which perl` -x -S $0 ${1+"$@"} ;'
    if 0;
###########################################################################
#                    ___________ _______    ________                      #
#                    \_   _____/ \      \  /  _____/                      #
#                     |    __)_  /   |   \/   \  ___                      #
#                     |        \/    |    \    \_\  \                     #
#                    /_______  /\____|__  /\______  /                     #
#                            \/         \/        \/                      #
#                      _________________  .____                           #
#                     /   _____/\_____  \ |    |                          #
#                     \_____  \  /  / \  \|    |                          #
#                     /        \/   \_/.  \    |___                       #
#                    /_______  /\_____\ \_/_______ \                      #
#                            \/        \__>       \/                      #
# ___________.__                                         .__        __    #
# \_   _____/|__| ____    ____   ________________________|__| _____/  |_  #
#  |    __)  |  |/    \  / ___\_/ __ \_  __ \____ \_  __ \  |/    \   __\ #
#  |     \   |  |   |  \/ /_/  >  ___/|  | \/  |_> >  | \/  |   |  \  |   #
#  \___  /   |__|___|  /\___  / \___  >__|  |   __/|__|  |__|___|  /__|   #
#      \/            \//_____/      \/      |__|                 \/       #
#                                                                         #
#             Powered by Exploit Next Generation Technology               #
#                                                                         #
###########################################################################
# Author:         Nelson Brito <nbrito *NoSPAM* sekure.org>               #
# Release Date:   December 25th, 2012                                     #
###########################################################################
# Copyright(c) 2010-2012 Nelson Brito. All rights reserved worldwide.     #
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
use Digest::MD5 qw (md5_hex);
use Getopt::Long qw (:config gnu_getopt no_ignore_case);
use IO::Socket;
use Pod::Usage;
use POSIX qw (strftime);
use Switch 'Perl5', 'Perl6';

{(($^O=~/^[M]*$32/i) and ($0=~s!.*\\!!)) or ($0=~s!^.*/!!)};

BEGIN {
    my $subname = (caller (0))[3];
    eval ("require 5.012004;");
    eval ("require 5.010001;")
        if $@;
    die "$subname: Unsupported Perl version ($]).\Please, install Perl v5.10.1 or v5.12.4!\n"
        if $@;
}

##
# globals
##
my $rcsid     = q ($Id: ESF.pl,v 1.42 2012-12-24 10:21:44-02 nbrito Exp $);
my $major     = (split (/\./, (split (/ /, $rcsid))[2]))[0];
my $minor     = (split (/\./, (split (/ /, $rcsid))[2]))[1];
my $build     = (split (/\-/, (split (/ /, $rcsid))[3]))[2];
my @revision  = (split (/\:/, (split (/ /, $rcsid))[4]));
$revision[2]  = (split (/-/, $revision[2]))[0];
my $record    = 0;

##
# version
##
my $version   = "$major.$minor.$build-$revision[0]$revision[1]$revision[2]";
my $script    = "SQL Fingerprint powered by ENG++ Technology [Version $version]";
my $author    = "Nelson Brito <nbrito\@sekure.org>";
##
# getoptions ()
##
my ($timeout, $TIMEOUT, $verbose, $debug, $help, $manpage, $fingerdb);
GetOptions (
    "f|fingerdb=s" => \$fingerdb,
    "t|timeout=i"  => \$timeout,
    "T|TIMEOUT=i"  => \$TIMEOUT,
    "d|debug"      => \$debug,
    "v|verbose"    => \$verbose,
    "h|?|help"     => \$help,
    "m|manpage"    => \$manpage
) or die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n";

##
# $ARGV[0]
##
my $arguments = $#ARGV + 1;

##
# major_versions[]
##
my %major_versions = (
    "11", "Microsoft SQL Server 2012",
    "10", "Microsoft SQL Server 2008",
    "9",  "Microsoft SQL Server 2005",
    "8",  "Microsoft SQL Server 2000",
    "7",  "Microsoft SQL Server 7",
);

##
# minor_versions[]
##
my %minor_versions = (
    "50", "R2"
);

##
# build_versions[]
##
my %build_versions = ();

##
# fingered[]
##
my %fingered = ();

##
# instances[]
##
my %instances = ();

##
# probabillity[]
##
my %probability = ();

##
# ping[]
##
my %ping = (
    CLNT_UCAST_EX => {
        name     => "SSRP Client Unicast Request",
        protocol => "udp",
        port     => "1434",
        packet   => "\x03"
    }
);

##
# packets[]
##
my %packets = (
    CLNT_UCAST_INST => {
        name     => "SSRP Client Unicast Instance Request",
        protocol => "udp",
        port     => "1434",
        packet   => "\x04"
    },
    PRELOGIN => {
        name     => "TDS Pre-Login Request",
        protocol => "tcp",
        port     => "1433",
        packet   => "\x12\x01\x00\x2F\x00\x00\x01\x00\x00\x00\x1A\x00\x06\x01\x00\x20" .
                    "\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04\x04\x00\x26\x00" .
                    "\x01\xFF\x09\x00\x00\x00\x00\x00\x01\x00\xB8\x0D\x00\x00\x01"
    }
);

##
# topmost[]
##
my %topmost = ();

##
# ctrlc ()
##
sub ctrlc {
    my $subname = (caller (0))[3];
    my $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());
    die "\b\r$0 command interrupted on $format_time.\n";
}

##
# database ()
##
sub database{
    my @progress = ("\\\\\\\\", "||||", "////", "====");
    my ($subname, $hash, $mapped, $fingers, $counter) = (
        (caller (0))[3],
        undef,
        undef,
        0,
        int (@progress)
    );

    print "\b\r$0 loading SQL Fingerprint Database [@_].\n"
        if ($verbose);

    open (FINGERPRINTDB, "<@_")
        or (
            print "\b\r$0::$subname: $!!\n"
                and return (0)
    );
    
    foreach (<FINGERPRINTDB>) {
        chomp; next if (/^\s*#/ or /^\s*$/);

        ((($hash, $mapped) = split (/\s+\s*\s/, $_)) == 2)
            or (
                print "\b\r$0::$subname: Corrupted or unformatted file!\n"
                    and return (0)
            );

        select (undef, undef, undef, $TIMEOUT/1000);

        print "\b\r", $progress[$fingers%$counter]
            if (not ($verbose) and not ($debug)); $|=1;

        $fingers++;

        $build_versions{$hash} = $mapped;
    }

    close(FINGERPRINTDB)
        or (
            print "\b\r$0::$subname: $!!\n"
                and return (0)
        );

    $verbose ?
        print "\b\r$0 loaded $fingers unique versions from [@_].\n"
    :
        print "\b\r..";

    return (1);
} 

##
# dumped ()
##
sub dumped {
    my ($subname, $buffer, $module, $counter, $line) = (
        (caller (0))[3],
        shift,
        shift,
        0,
        0
    );
    my %packet = (); my @bytes = split (//, $buffer);

    print "\b\r[*] $0::$subname: $module: CURRENT: ",
          length ($buffer), " BYTE",
          (length ($buffer) > 1 ? "S" : ""), "\n";
    
    foreach (@bytes) {
        $line++
            if ($counter == 0);

        $packet{$line}{hexa} .= unpack ("H*", $_) . " ";

        given ($_) {
            when (/[^\x21-\x7e]/) {
                $packet{$line}{ascii} .= ".";
            }
            default {
                $packet{$line}{ascii} .= $_;
            }
        }

        $counter++;

        $counter = 0
            if ($counter == 16);
    }

    $counter = 0;
    foreach my $byte (1 .. scalar (keys %packet)) {
        $packet{$byte}{hexa} .= " "
            while (length ($packet{$byte}{hexa}) < 48);

        print unpack ("H*", pack ("n", $counter*16)), "\t",
              $packet{$byte}{hexa}, "  ",
              $packet{$byte}{ascii}, "\n";

        $counter++;
    }
}

##
# epoch ()
##
#sub epoch {
#    my %months = (
#        1,  "Jan", 2,  "Feb", 3,  "Mar", 4,  "Apr", 5,  "May", 6,  "Jun",
#        7,  "Jul", 8,  "Aug", 9,  "Sep", 10, "Oct", 11, "Nov", 12, "Dec"
#    );
#    my @time = (split (/\-/, (split (/ /, $rcsid))[3]));
#    my @hour = (split (/\:/, (split (/ /, $rcsid))[4]));
#    $hour[2] = (split (/-/, $hour[2]))[0];
#
#    return ("$months{$time[1]} $time[2] $time[0] $hour[0]:$hour[1]:$hour[2]");
#}
##
# Xmas Release (Minor Update - 2013-01-01)
##
# An error has been found in the "epoch()" subroutine, so, please, use the
# following code instead of the previously released.
##
sub epoch {
    my %months = (
        "01", "Jan", "02", "Feb", "03", "Mar", "04", "Apr", "05", "May", "06", "Jun",
        "07", "Jul", "08", "Aug", "09", "Sep", "10", "Oct", "11", "Nov", "12", "Dec"
    );
    my @date = (split (/-/, (split (/ /, $rcsid))[3]));
    my @time = (split (/\:/, (split (/ /, $rcsid))[4]));
    
    $time[2] = (split (/-/, $time[2]))[0];
    
    $date[2] =~ s/^0/ /
        if ($date[2] =~ /^0/);
    
    return ("$months{$date[1]} $date[2] $date[0] $time[0]:$time[1]:$time[2]");
}

##
# evaluate ()
##
sub evaluate {
    my ($subname, $message, %elapsed) = (
        (caller (0))[3],
        undef,
        {}
    );

    $elapsed{EET} = {
        seconds => @_,
        minutes => 0,
        hours   => 0,
        days    => 0
    };

    ($elapsed{EET}{minutes} = int ($elapsed{EET}{seconds}/60),
     $elapsed{EET}{seconds} = int ($elapsed{EET}{seconds}%60))
        if ($elapsed{EET}{seconds} > 60);
    ($elapsed{EET}{hours}   = int ($elapsed{EET}{minutes}/60),
     $elapsed{EET}{minutes} = int ($elapsed{EET}{minutes}%60))
        if ($elapsed{EET}{minutes} > 60);
    ($elapsed{EET}{days}    = int ($elapsed{EET}{hours}/24),
     $elapsed{EET}{hours}   = int ($elapsed{EET}{hours}%24))
        if ($elapsed{EET}{hours} > 24);

    $elapsed{EET}{seconds} = "0$elapsed{EET}{seconds}"
        if ($elapsed{EET}{seconds} < 10);
    $elapsed{EET}{minutes} = "0$elapsed{EET}{minutes}"
        if ($elapsed{EET}{minutes} < 10);
    $elapsed{EET}{hours}   = "0$elapsed{EET}{hours}"
        if ($elapsed{EET}{hours} < 10);
    $elapsed{EET}{days}    = "0$elapsed{EET}{days}"
        if ($elapsed{EET}{days} < 10);
    
    $message .= "$elapsed{EET}{days}:$elapsed{EET}{hours}:";
    $message .= "$elapsed{EET}{minutes}:$elapsed{EET}{seconds}";

    return ($message);
}

##
# finger ()
##
sub finger {
    my ($subname, $buffer, $target, $succeeded, $start, $stop) = (
        (caller (0))[3],
        undef,
        shift,
        0,
        0,
        0
    );

    $SIG{"HUP"}  = "IGNORE";
    $SIG{"PIPE"} = "IGNORE";
    $SIG{"ALRM"} = "ctrlc";
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

    ($0 =~ s/.pl$//)
        if ($0 =~ /.pl$/);

    $start = time ();
    
    $timeout = defined $timeout ? $timeout : 30;
    $TIMEOUT = defined $TIMEOUT ? $TIMEOUT : 05;

    $verbose = 0
        if ($debug);

    my $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());
    print "\b\r$0 version $version built on ". epoch () . ".\n";

    if (not ($debug)) {
        print "\b\r$0 successfuly launched on $format_time.\n";
        database ($fingerdb ? $fingerdb : "ESF.db")
            or goto FAILED;
    } else {
        print "\b\r$0 successfuly launched DEBUG MODE on $format_time.\n";
    }

    foreach my $module (sort (keys %ping)) {
        $verbose ?
            print "\b\r$0 attempting $ping{$module}{name} [$module].\n"
        :
            $debug ?
                print "\b\r[+] $0::$subname: $module: $target: $ping{$module}{port}/$ping{$module}{protocol}\n"
            :
                print "..";

        $buffer = launch (
            $module,
            $ping{$module}{protocol},
            $ping{$module}{port},
            $ping{$module}{packet},
            $target,
        );

        select (undef, undef, undef, $TIMEOUT);

        given ($buffer) {
            when ("") {
                $verbose ?
                    print "\b\r$0 failed to perform version fingerprinting over [$module].\n", 
                          "\b\r$0 deleting all attempts for $packets{CLNT_UCAST_INST}{name}.\n"
                :
                    $debug ?
                        print "\b\r[-] $0::$subname: $module: $target: $ping{$module}{port}/$ping{$module}{protocol}\n"
                   :
                        print "..";

                delete $packets{CLNT_UCAST_INST};

                $instances{MSSQLServer} = {
                    port => "1433",
                };
            }
            default {
                parse (undef, $module, $buffer);

                $verbose ?
                    print "\b\r$0 finished $ping{$module}{name} [$module].\n"
                :
                    $debug ?
                        print "\b\r[-] $0::$subname: $module: $target: $ping{$module}{port}/$ping{$module}{protocol}\n"
                    :
                        print "..";
            }
        }

    }

    foreach my $module (sort (keys %packets)) {
        foreach my $instance (sort (keys %instances)) {
            my ($protocol, $port, $packet) = (
                undef,
                undef,
                undef
            );

            select (undef, undef, undef, $TIMEOUT);

            $protocol = $packets{$module}{protocol};
            $packet   = $packets{$module}{packet};
            $port     = $packets{$module}{port};

            $port = $instances{$instance}{port}
                if ($protocol eq "tcp");

            $packet .= $instance
                if ($protocol eq "udp");

            $verbose ?
                print "\b\r$0 attempting $packets{$module}{name} [$module].\n"
            :
                $debug ?
                    print "\b\r[+] $0::$subname: $module: $target: $instance: $port/$protocol\n"
                :
                    print "..";

            $buffer = launch ($module, $protocol, $port, $packet, $target);

            given ($buffer) {
                when ("") {
                    $verbose ?
                        print "\b\r$0 failed to perform version fingerprinting over [$module].\n"
                    :
                        $debug ?
                            print "\b\r[-] $0::$subname: $module: $target: $instance: $port/$protocol\n"
                        :
                            print "..";
                }
                default {
                    $succeeded++; $record++;

                    parse ($instance, $module, $buffer);

                    if ($packets{$module}{protocol} eq "tcp") {
                        given ($instances{$instance}{port}) {
                            when ($packets{$module}{port}) {
                                $verbose ?
                                    print "\b\r$0 found DEFAULT SQL Server TCP port [$instance:$instances{$instance}{port}].\n"
                                :
                                    $debug ?
                                        print "\b\r[*] $0::$subname: $module: $target: $instance: DEFAULT: $port/$protocol\n"
                                    :
                                        print "..";
                            }
                            default {
                                $verbose ?
                                    print "\b\r$0 found DYNAMIC SQL Server TCP port [$instance:$instances{$instance}{port}].\n"
                                :
                                    $debug ?
                                        print "\b\r[*] $0::$subname: $module: $target: $instance: DYNAMIC: $port/$protocol\n"
                                    :
                                    print "..";
                            }
                        }
                    }

                    $verbose ?
                        print "\b\r$0 finished $packets{$module}{name} [$module].\n"
                    :
                        $debug ?
                            print "\b\r[-] $0::$subname: $module: $target: $instance: $port/$protocol\n"
                        :
                            print "..";
                }
            }
        }
    }

    score ()
        if (($succeeded) and scalar (keys %fingered) and (not ($debug)));

    $stop = time ();

    print "\b\r$0 execution elapsed time (EET) [", evaluate ($stop - $start), "].\n";

FAILED:
    $format_time = strftime ("%b %e %Y %H:%M:%S", localtime ());
    print "\b\r$0 ",  ($succeeded ? "successfully" : "unsuccessfully") .
          " finished on $format_time.\n";

    $succeeded ?
        exit (1)
    :
        exit (0);
}

##
# launch ()
##
sub launch {
    my ($subname, $module, $protocol, $port, $packet, $address, $buffer) = (
        (caller (0))[3],
        shift,
        shift,
        shift,
        shift,
        shift,
        undef
    );
    my ($start, $stop) = (
        0,
        0
    );

    $start = time();

    print ".."
        if($verbose);

    dumped ($packet, $module)
        if ($debug);
    
    eval {
        local $SIG{"ALRM"} = sub { };
        alarm $timeout;

        my $sock = IO::Socket::INET->new (
            Proto    => $protocol,
            PeerPort => $port,
            PeerAddr => $address
        )
            or return ($@);

        $sock->autoflush (1);

        $sock->send ($packet) or return ($@);

        $sock->recv ($buffer, 1024) or return ($@);

        $sock->close ();

        alarm 0;
        1;
    };
    alarm 0;

    $stop    = time();

    print "\b\r[*] $0::$subname: $module: NO RESPONSE AFTER ",
          evaluate($stop - $start), "\n"
        if ($! and $debug);

    return ($buffer);
}

##
# match ()
##
sub match {
    my ($subname, $version, $module, $digest) = (
        (caller (0))[3],
        shift,
        shift,
        undef
    );

    $digest = md5_hex ($version);

    given ($build_versions{$digest}) {
        when (undef) {
            my ($major, $minor) = (
                undef,
                undef
            );

            ($major, $minor, undef) = split (/\./, $version);

            return ("possible $major_versions{$major} [$version]")
                if ($major_versions{$major} ne undef);

            return ("unmatched Microsoft SQL Server [$version]");
        }
        default {
            return ("$build_versions{$digest}");
        }
    }
}

##
# parse ()
##
sub parse {
    my ($subname, $version, $instance, $module, $buffer) = (
        (caller (0))[3],
        undef,
        shift,
        shift,
        shift
    );

    given ($module) {
        when ("CLNT_UCAST_EX") {
            my (@multiple, %sample, $message) = (
                undef,
                (),
                undef
            );

            @multiple = split (/\;;/, $buffer);

            if (@multiple > 1) {
                my $instances = undef;

                $message .= "\b\r$0 found MULTIPLE SQL Server instances [";
                foreach (@multiple) {
                    %sample = split (/\;/, $_);
                    $instances .= $sample{InstanceName} . ", ";
                }
                $instances =~ s/,\s+$//;
                
                $message .= $instances;
                $message .= "].\n";
                
                $verbose ?
                    print $message
                :
                    $debug ?
                        print "\b\r[*] $0::$subname: $module: $instances\n"
                    :
                        print "..";
            }

            foreach (@multiple) {
                %sample = split (/\;/, $_);

                $instances{$sample{InstanceName}} = {
                    port => $sample{tcp},
                };
            }

            dumped ($buffer, $module)
                if ($debug);
        }
        when ("CLNT_UCAST_INST") {
            my (%sample, @versions, $major, $minor, $built) = (
                undef,
                (),
                undef,
                undef,
                undef
            );

            %sample = split (/\;/, $buffer);

            @versions = split (/\./, $sample{Version});

            $major = int ($versions[0]);
            $minor = int ($versions[1]);
            $built = int ($versions[2]);

            (
                print "\b\r[*] $0::$subname: $module: VERSION: $major.$minor.$built\n"
                    and dumped ($buffer, $module)
            )
                if ($debug);

            $minor = "0$minor"
                if (length ($minor) < 2);

            $version = "$major.$minor.$built";

            $fingered{$record} = {
                instance => $instance,
                module   => $module,
                version  => $version,
                matched  => match ($version)
            }
                if (not ($debug));
        }
        when ("PRELOGIN") {
            my (@versions, $offset, $major, $minor, $built) = (
                (),
                0,
                undef,
                undef,
                undef
            );

            @versions = split (//, $buffer);
            
            foreach (@versions) {
                $offset++;
                last if (unpack ("H*", $_) eq "ff");
            }

            $major = hex (unpack ("H*", $versions[$offset++]));
            $minor = hex (unpack ("H*", $versions[$offset++]));
            $built = hex (unpack ("H*", $versions[$offset++])) * 256 +
                     hex (unpack ("H*", $versions[$offset++]));

            (
                print "\b\r[*] $0::$subname: $module: VERSION: $major.$minor.$built\n"
                    and dumped ($buffer, $module)
            )
                if ($debug);
            
            $minor = "0$minor"
                if (length ($minor) < 2);

            $version = "$major.$minor.$built";

            $fingered{$record} = {
                instance => $instance,
                module   => $module,
                version  => $version,
                matched  => match ($version)
            }
                if (not ($debug));
        }
        default {
            die "$0::$subname: Unknown $module fingerprint to parse!\n";
        }
    }
}

##
# score ()
##
sub score {
    my ($subname, $counter, $percentage, $higher) = (
        (caller (0))[3],
        0,
        0
    );

    $verbose ?
        print "\b\r$0 attempting Scoring Algorithm Mechanism [ENG_EMBEDDED].\n"
    :
        print "..";

    select (undef, undef, undef, $TIMEOUT);

    foreach my $found (sort (keys %fingered)) {
        $probability{$fingered{$found}{version}} = {
            instance => undef,
            matched  => $fingered{$found}{matched},
            module   => $fingered{$found}{module},
            score    => 0
        };

        $counter++;
    }

    foreach my $found (sort (keys %fingered)) {
        foreach my $versions (sort (keys %probability)) {
            $probability{$versions}{score}++
                if ($versions eq $fingered{$found}{version});
        }
    }

    foreach my $found (sort (keys %probability)) {
        $percentage = int (($probability{$found}{score}*100)/$counter);

        print "\b\r$0 found $probability{$found}{matched} [$percentage%].\n";
    }

    foreach my $found (keys %probability) {
        if (not (defined $higher) or ($higher < $probability{$found}{score})) {
            %topmost = ();
            $higher  = $probability{$found}{score};

            $topmost{$found} = $probability{$found}{score};
        }
        elsif ($higher == $probability{$found}{score}) {
            $topmost{$found} = $probability{$found}{score};
        }
    }

    if (not (scalar (keys %topmost) > 1) and scalar (keys %instances) > 1) {
        foreach my $found (keys %topmost) {
            print "\b\r$0 found MOST LIKELY $probability{$found}{matched}.\n";
        }
    }

    $verbose ?
        print "\b\r$0 finished Scoring Algorithm Mechanism [ENG_EMBEDDED].\n"
    :
        print "\b\r...hurts.to.be.touched...you.bet.that.hurts...\n";
}

##
# help ()
##
pod2usage (
    -message => "$script\n$author\n",
    -verbose => 99,
    -sections => ["USAGE|OPTIONS|COPYRIGHT"]
)
    if $help;

##
# man ()
##
pod2usage (-verbose => 2)
    if $manpage;

##
# usage ()
##
die "Type \"$0 --help\" or \"$0 --manpage\" for further information.\n"
    if ($arguments < 1);

##
# main ()
##
select (STDOUT); $|=1;
finger ($ARGV[0]);

##
# POD (Plain Old Documentation) for ESF.pl.
##
=pod

=head1 NAME

B<ESF.pl> - SQL Fingerprint powered by I<ENG++ Technology>

=head1 VERSION

This document describes B<ESF.pl> [Version 1].

=head1 USAGE

C<ESF.pl host [options]>

=head1 DESCRIPTION

B<Microsoft SQL Server> fingerprinting can be a time consuming process, because it involves trial and error methods to determine the exact version. Intentionally inserting an invalid input to obtain a typical error message or using certain alphabets that are unique for certain server are two of the many ways to possibly determine the version, but most of them require authentication, permissions and/or privileges on B<Microsoft SQL Server> to succeed.

Instead, B<ESF.pl> uses a combination of crafted packets for B<SQL Server Resolution Protocol> (L</"SSRP">) and B<Tabular Data Stream Protocol> (L</"TDS">) (protocols natively used by B<Microsoft SQL Server>) to accurately perform version fingerprinting and determine the exact B<Microsoft SQL Server> version. B<ESF.pl> also applies a sophisticated B<Scoring Algorithm Mechanism> (powered by I<Exploit Next Generation++ Technology>), which is a much more reliable technique to determine the B<Microsoft SQL Server> version. It is a tool intended to be used by:

=over 4
 
=item * Database Administrators

=item * Database Auditors

=item * Database Owners

=item * Penetration Testers

=back

Having over C<FIVE HUNDRED> unique versions within its fingerprint database, B<ESF.pl> currently supports fingerprinting for:

=over 4

=item * Microsoft SQL Server 2000

=item * Microsoft SQL Server 2005

=item * Microsoft SQL Server 2008

=item * Microsoft SQL Server 2012

=back

B<ESF.pl> re-invented the techniques used by several public tools (B<SQLPing Tool> by I<Chip Andrews>, I<Rajiv Delwadia> and I<Michael Choi>, and B<SQLVer Tool> by I<Chip Andrews>) (see L</"SEE ALSO"> for further information). B<ESF.pl> shows the C<MAPPED VERSION> and C<PATCH LEVEL> (i.e., B<Microsoft SQL Server 2008 SP1 (CU5)>) instead of showing only the C<RAW VERSION> (i.e., B<Microsoft SQL Server 10.0.2746>). B<ESF.pl> also has the ability to show the I<MOST LIKELY> version, based on its sophisticated B<Scoring Algorithm Mechanism>, and allows to determine C<vulnerable> and C<unpatched> B<Microsoft SQL Server> better than many of public and commercial tools.

This version is a completely rewritten version in B<Perl>, making B<ESF.pl> much more portable than the previous binary version (B<Win32>), and its original purpose is to be used as a tool to perform automated penetration test. This version also includes the following B<Microsoft SQL Server> versions to its fingerprint database:

=over 4

=item * Microsoft SQL Server 2012 SP1 (CU1)

=item * Microsoft SQL Server 2012 SP1

=item * Microsoft SQL Server 2012 SP1 CTP4

=item * Microsoft SQL Server 2012 SP1 CTP3

=item * Microsoft SQL Server 2012 SP0 (CU4)

=item * Microsoft SQL Server 2012 SP0 (MS12-070)

=item * Microsoft SQL Server 2012 SP0 (CU3)

=item * Microsoft SQL Server 2012 SP0 (CU2)

=item * Microsoft SQL Server 2012 SP0 (CU1)

=item * Microsoft SQL Server 2012 SP0 (MS12-070)

=item * Microsoft SQL Server 2012 SP0 (KB2685308)

=item * Microsoft SQL Server 2012 RTM

=back

=over 4

I<B<NOTE>: B<ESF.pl> B<C<IS NOT>> a I<SQLi> tool, and has no ability to perform such task.>

=back

=head2 Fingerprinting Steps

As described in L</"DESCRIPTION">, B<ESF.pl> uses a combination of crafted packets for L</"SSRP"> and L</"TDS"> to accurately perform version fingerprintfing. To achieve an accurate and much more reliable version fingerprinting, B<ESF.pl> employes the following steps, mimicking a valid negotiation between the B<CLIENT> and the B<SERVER>:

=over 4

=item 1) L</"SSRP"> C<Client Unicast Request> (CLNT_UCAST_EX)

This step attempts to gather the B<Microsoft SQL Server> single instance or even multiple instances (see L</"MULTIPLE SQL SERVER INSTANCES WARNING"> for further information), and the respective L</"TDS"> communication port(s) - the L</"TDS"> communication port for each instances can be dynamic or default (see L</"DYNAMIC SQL SERVER TCP PORT WARNING"> and L</"DEFAULT SQL SERVER TCP PORT WARNING"> for further information).

=over 4

I<B<NOTE>: If this step fails, the C<STEP 2> is not performed and the C<STEP 3> will use L</"TDS"> default communication port only.>

=back

=item 2) L</"SSRP"> C<Client Unicast Instance Request> (CLNT_UCAST_INST)

This step attempts to use the information gathered by I<step 1> to collect, parse and match information for a single instances or for multiple instances (see L</"MULTIPLE SQL SERVER INSTANCES WARNING"> for further information). Once the collecting, parsing and matching is done, the fingerprinting data is stored to be validated by the sophisticated B<Scoring Algorithm Mechanism> (powered by I<Exploit Next Generation++ Technology>).

=over 4
 
I<B<NOTE>: If the C<STEP 1> fails, this step is not performed.>
 
=back

=item 3) L</"TDS"> C<Pre-Login Request> (PRELOGIN)
 
This step attempts to use the information gathered by I<step 1> to collect, parse and match information for a single instances running on L</"TDS"> default coommunication port (see L</"DEFAULT SQL SERVER TCP PORT WARNING"> for further information) or for multiple instances (see L</"MULTIPLE SQL SERVER INSTANCES WARNING"> for further information) running on L</"TDS"> dynamic communication port(s) (see L</"DYNAMIC SQL SERVER TCP PORT WARNING"> for further information. Once the collecting, parsing and matching is done, the fingerprinting data is stored to be validated by the sophisticated B<Scoring Algorithm Mechanism> (powered by I<Exploit Next Generation++ Technology>).

=over 4
 
I<B<NOTE>: If C<STEP 1> fails, this step will use L</"TDS"> default communication port only.>
 
=back

=back

=head2 SSRP

As described in C<[MS-SQLR]: SQL Server Resolution Protocol> specification document (see L</"SEE ALSO"> for further information).

=over 4

=item 1) C<1.3 Overview>

C<The first case is used for the purpose of determining the communication endpoint information of a particular database instance, whereas the second case is used for enumeration of database instances in the network and to obtain the endpoint information of each instance.> (I<page 8>)

C<The SQL Server Resolution Protocol does not include any facilities for authentication, protection of data, or reliability. The SQL Server Resolution Protocol is always implemented on top of the UDP Transport Protocol [RFC768].> (I<page 8>)

=item 2) C<1.9 Standards Assignments>

C<The client always sends its request to UDP port 1434 of the server or servers.> (I<page 10>)

=item 3) C<2.2.2 CLNT_UCAST_EX>

C<The CLNT_UCAST_EX packet is a unicast request that is generated by clients that are trying to determine the list of database instances and their network protocol connection information installed on a single machine. The client generates a UDP packet with a single byte, as shown in the following diagram.> (I<page 11>)

=item 4) C<2.2.3 CLNT_UCAST_INST>

C<The CLNT_UCAST_INST packet is a request for information related to a specific instance. The structure of the request is as follows.> (I<page 12>)

=back

According to the previous quotes, the L</"SSRP"> I<is used for the purpose of determining the communication endpoint information of a particular database instance>, which I<does not include any facilities for authentication>, and both L</"SSRP"> C<CLNT_UCAST_EX Request> and L</"SSRP"> C<CLNT_UCAST_INST Request> can be used I<for the purpose of determining the communication endpoint information>.

Based on this analysis, it is possible to determine the B<Microsoft SQL Server> version  using the L</"SSRP"> C<CLNT_UCAST_EX Request> andE<sol>or L</"SSRP"> C<CLNT_UCAST_INST Request>. The version is available within the L</"SSRP"> C<CLNT_UCAST_EX Response> andE<sol>or L</"SSRP"> C<CLNT_UCAST_INST Response>, and it is a gratuitous information sent from B<SERVER> to B<CLIENT> to ensure they will establish a communication correctly, using the correct database instance and the same dialect by both B<CLIENT> and B<SERVER>.

Here is a L</"SSRP"> C<CLNT_UCAST_INST Request> and L</"SSRP"> C<CLNT_UCAST_INST Response> sample traffic dump between the B<ESF.pl> and a B<Microsoft SQL Server 2008 SP1>:

=over 4

=item L</"SSRP"> C<CLNT_UCAST_INST Request>

 0000   04 4d 53 53 51 4c 53 45 52 56 45 52              .MSSQLSERVER

=item L</"SSRP"> C<CLNT_UCAST_INST Response>

 0000   05 77 00 53 65 72 76 65 72 4e 61 6d 65 3b 53 45  .w.ServerName;SE
 0010   52 56 45 52 30 34 3b 49 6e 73 74 61 6e 63 65 4e  RVER04;InstanceN
 0020   61 6d 65 3b 4d 53 53 51 4c 53 45 52 56 45 52 3b  ame;MSSQLSERVER;
 0030   49 73 43 6c 75 73 74 65 72 65 64 3b 4e 6f 3b 56  IsClustered;No;V
 0040   65 72 73 69 6f 6e 3b 31 30 2e 30 2e 32 35 33 31  ersion;10.0.2531
 0050   2e 30 3b 74 63 70 3b 31 34 33 33 3b 6e 70 3b 5c  .0;tcp;1433;np;\
 0060   5c 53 45 52 56 45 52 30 34 5c 70 69 70 65 5c 73  \SERVER04\pipe\s
 0070   71 6c 5c 71 75 65 72 79 3b 3b                    ql\query;;

=back

As demonstrated above, the information within the L</"SSRP"> C<CLNT_UCAST_EX Response> represents the version for B<Microsoft SQL Server 2008 SP1> (I<10.0.2531>), as well as many interesting information.

=over 4
 
I<B<NOTE>: no authentication and gratuitous information.>
 
=back

=head2 TDS

As described in C<B<[MS-TDS]: Tabular Data Stream Protocol>> specification document (see L</"SEE ALSO"> for further information).

=over 4 

=item 1) C<2.2.1.1 Pre-Login>

C<Before a login occurs, a handshake denominated pre-login occurs between client and server, setting up contexts such as encryption and MARS-enabled.> (I<page 17>)

=item 2) C<2.2.2.1 Pre-Login Response>

C<The pre-login response is a tokenless packet data stream. The data stream consists of the response to the information requested by the client pre-login message.> (I<page 18>)

=item 3) C<2.2.4.1 Tokenless Stream>

C<As shown in the previous section, some messages do not use tokens to describe the data portion of the data stream. In these cases, all the information required to describe the packet data is contained in the packet header. This is referred to as a tokenless stream and is essentially just a collection of packets and data.> (I<page 24>)

=item 4) C<2.2.6.4 PRELOGIN>

C<A message sent by the client to set up context for login. The server responds to a client PRELOGIN message with a message of packet header type 0x04 and the packet data containing a PRELOGIN structure.> (I<page 59>)

C<[TERMINATOR] [0xFF] [Termination token.]> (I<page 61>)

C<TERMINATOR is a required token, and it MUST be the last token of PRELOGIN_OPTION. TERMINATOR does not include length and bits specifying offset.> (I<page 61>)

=back

According to the previous quotes, the L</"TDS"> C<Pre-Login> is just a handshake, i.e., the L</"TDS"> C<Pre-Login> is a I<tokenless packet data stream> of the I<pre-authentication state> to establish the negotiation between the B<CLIENT> and the B<SERVER> - as described in C<Figure 3: Pre-login to post-login sequence> (I<page 103>).

Based on this analysis, it is possible to determine the B<Microsoft SQL Server> version  during the L</"TDS"> C<Pre-Login> handshake. It is an undocumented feature, but it is not a bug or a leakage, in fact, it is more likely to be an C<AS IS> embedded feature that allows B<CLIENT> to establish a negotiation with B<SERVER>. The version is available within the L</"TDS"> C<Pre-Login Response> packet data stream, and it is a gratuitous information sent from B<SERVER> to B<CLIENT> to ensure they will establish a communication correctly, using the correct database instance and the same dialect by both B<CLIENT> and B<SERVER>.

Here is a I<tokenless packet data stream> sample traffic dump of a L</"TDS"> C<Pre-Login> handshake between the B<ESF.pl> and a B<Microsoft SQL Server 2008 SP1>:
 
=over 4

=item L</"TDS"> C<Pre-Login Request>
 
 0000   12 01 00 2f 00 00 01 00 00 00 1a 00 06 01 00 20
 0010   00 01 02 00 21 00 01 03 00 22 00 04 04 00 26 00
 0020   01 ff 09 00 00 00 00 00 01 00 b8 0d 00 00 01

=item L</"TDS"> C<Pre-Login Response>

 0000   04 01 00 2b 00 00 01 00 00 00 1a 00 06 01 00 20
 0010   00 01 02 00 21 00 01 03 00 22 00 00 04 00 22 00
 0020   01 ff 0a 00 09 e3 00 00 01 00 01

=back

As demonstrated above, there are four bytes following the C<TERMINATOR> (I<0xFF> at the B<OFFSET> I<34>), and they represent the version for B<Microsoft SQL Server 2008 SP1> (I<10.0.2531>):

=over 4

=item 1) B<OFFSET> I<35> represents the Major Version (0x0a = I<10>)

=item 2) B<OFFSET> I<36> represents the Minor Version (0x00 = I<0>)

=item 3) B<OFFSETS> I<37>E<sol>I<38> represent the Build Version ([0x09*256]+0xe3 = I<2531>)

=back

=over 4

I<B<NOTE>: no authentication and gratuitous information.>

=back

=head2 MULTIPLE SQL SERVER INSTANCES WARNING

Warns the availability of multiple instances (C<Default Instances> as well as C<Named Instances>). This information is collected and parsed by C<STEP 1> and used and validated by C<STEP 3> (see L</"Fingerprinting Steps"> for further information).

=over 4

I<B<NOTE>: Only in C<verbose> mode (see L</"OPTIONS"> for further information).>

=back

=head2 DYNAMIC SQL SERVER TCP PORT WARNING

Warns the availability of multiple instances (C<Default Instances> as well as C<Named Instances>) running on L</"TDS"> dynamic communication port(s). This information is collected and parsed by C<STEP 1> and used and validated by C<STEP 3> (see L</"Fingerprinting Steps"> for further information).

=over 4
 
I<B<NOTE>: Only in C<verbose> mode (see L</"OPTIONS"> for further information).>
 
=back
 
=head2 DEFAULT SQL SERVER TCP PORT WARNING

Warns the availability of C<Default Instances> running on L</"TDS"> default communication port(s) . This information is collected and parsed by C<STEP 1> and used and validated by C<STEP 3> (see L</"Fingerprinting Steps"> for further information).

=over 4
 
I<B<NOTE>: Only in C<verbose> mode (see L</"OPTIONS"> for further information).>
 
=back
 
=head2 MOST LIKELY WARNING

ADD DESCRIPTION HERE

=head1 OPTIONS

=over 4

=item C<-d,--debug> B<(default OFF)>
 
Configure the debug mode, giving much more information details about the fingerprinting tasks.

=item C<-f,--fingerdb FILE> B<(default C<ESF.db>)>

Configure an optional file for SQL Fingerprint Database.

=item C<-t,--timeout NUM> B<(default 30)>

Configure a specific connection timeout (seconds), allowing B<ESF.pl> to wait until close the connection.

=item C<-T,--TIMEOUT NUM> B<(default 5)>

Configure a specific timeout (seconds), allowing B<ESF.pl> to wait until execute the next subroutine.

=item C<-v,--verbose> B<(default OFF)>

Configure the verbose mode, giving information details about the fingerprinting tasks.

=item C<-m,--manpage>

Display the manual page embedded in B<ESF.pl>, being the manual page in POD (Plain Old Documentation) format.

=item C<-h,-?,--help>

Display the help and usage message.

=back

=head1 DEPENDENCIES

=over 4

=item C<Digest::MD5(3)>

See C<L<Getopt::Long's Perl Documentation|Digest::MD5/"DESCRIPTION">> for further information.

=item C<Getopt::Long(3)>

See C<L<Getopt::Long's Perl Documentation|Getopt::Long/"DESCRIPTION">> for further information.

=item C<IO::Socket(3)>

See C<L<IO::Socket's Perl Documentation|IO::Socket/"DESCRIPTION">> for further information.

=item C<Pod::Usage(3)>

See C<L<Pod::Usage's Perl Documentation|Pod::Usage/"DESCRIPTION">> for further information.

=item C<POSIX(1)>

See C<L<POSIX's Perl Documentation|POSIX/"DESCRIPTION">> for further information.

=item C<Switch(3)>

See C<L<Switch's Perl Documentation|Switch/"DESCRIPTION">> for further information.

=item C<PERL(1)> v5.10.1 or v5.12.4

B<ESF.pl> has been widely tested under B<Perl> v5.10.1 (Ubuntu 10.04 LTS) and B<Perl> v5.12.4 (OS X Mountain Lion). Due to this, B<ESF.pl> requires one of the mentioned versions to be executed. The following tests will be performed to ensure its capabilities:

 BEGIN {
    my $subname = (caller (0))[3];
    eval ("require 5.012004;");
    eval ("require 5.010001;") if $@;
    die "$subname: Unsupported Perl version ($]).\n" if $@;
 }

=over 4

I<B<NOTE>: If you are confident that your B<Perl> version is capable to execute the B<ESF.pl>, please, remove the above tests and send feedback to the L<author|"AUTHOR">>.

=back

See C<L<PERL's Perl Documentation|PERL/"DESCRIPTION">> for further information.

=back

=head1 SEE ALSO

L<Digest::MD5(3)|Digest::MD5>, L<IO::Socket(3)|IO::Socket>, L<Getopt::Long(3)|Getopt::Long>, L<Pod::Usage(3)|Pod::Usage>, L<POSIX(1)|POSIX>, L<Switch(3)|Switch>, PERL(1), L<[RFC793]|http://www.ietf.org/rfc/rfc793.txt>, L<[RFC768]|http://www.ietf.org/rfc/rfc768.txt>, L<TDS|http://msdn.microsoft.com/en-us/library/dd304523.aspx>, L<SSRP|http://msdn.microsoft.com/en-us/library/cc219703.aspx>, L<SQLPing & SQLVer Tools|http://www.sqlsecurity.com/downloads>

=head1 HISTORY

=over 4

=item B<2008>

Private Release (B<Late 2008>)

=item B<2009>
 
H2HC Talk (B<November 28>)
 
=item B<2010>

MSSQLFP BETA-3 (B<January 5>)

MSSQLFP BETA-4 (B<January 18>)

ESF 1.00.0006 (B<February 10>)

ESF 1.10.101008/CTP (B<October 8>)

=item B<2012>

ESF 1.12.120115/RC0 (B<January 15>)

=back

=head1 BUGS AND LIMITATIONS

Report B<ESF.pl> bugs and limitations directly to the L<author|"AUTHOR">.

=head1 AUTHOR

B<Nelson Brito> L<mailto:nbrito@sekure.org>.

=head1 COPYRIGHT

Copyright(c) 2010-2012 B<Nelson Brito>. All rights reserved worldwide.

Exploit Next Generation++ Technology and/or other noted Exploit Next Generation++ and/or ENG++ related products contained herein are registered trademarks or trademarks of Nelson Brito. Any other non-Exploit Next Generation++ related products, registered and/or unregistered trademarks contained herein is only by reference and are the sole property of their respective owners.
 
I<Exploit Next Generation++ Technology>, innovating since 2010.

=head1 LICENSE

This program is free software: you can redistribute it and/or modify it under the terms of the I<GNU General Public License> as published by the B<Free Software Foundation>, either version 3 of the License, or (at your option) any later version.

You should have received a copy of the I<GNU General Public License> along with this program. If not, see L<http://www.gnu.org/licenses/>.

=head1 DISCLAIMER OF WARRANTY

This program is distributed in the hope that it will be useful, but B<WITHOUT ANY WARRANTY>; without even the implied warranty of B<MERCHANTABILITY> or B<FITNESS FOR A PARTICULAR PURPOSE>. See the I<GNU General Public License> for more details.

=cut
