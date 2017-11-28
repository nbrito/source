```
(Reverse) Name Block Lookup Next Generation [Version 1.67.12-120115]
Nelson Brito <nbrito@sekure.org>

Usage:
    "NBlookup.pl host[/CIDR] [options]"

Options:
    "host"
        Configure the DNS name or IPv4 address.

    "[/CIDR]"
        Configure the CIDR (*Classless Inter-Domain Routing*) to build IPv4
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

        *IT IS STRONGLY RECOMMENDED TO AVOID DNS FLOOD AND/OR
        DENIAL-OF-SERVICE.*

    "-f,--filename FILE" (default NONE)
        Save all the reverse DNS name lookup results to a text file.

    "-m,--manpage"
        Display the manual page embedded in NBlookup.pl, being the manual
        page in POD (Plain Old Documentation) format.

    "-h,-?,--help"
        Display the help and usage message.

Copyright:
    Copyright(c) 2000-2012 Nelson Brito. All rights reserved worldwide.
```
