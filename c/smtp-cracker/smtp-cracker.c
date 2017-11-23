/* Author(s)     :       Lucas Fontes & Nelson Brito
 * E-mail(s      :       lucasfontes@clips.com.br & nbrito@sekure.org
 * File          :       smtp-cracker.c
 * Version       :       0.2 Beta
 * CVE           :       N/A
 * Country       :       Brazil
 * Date          :       01/08/2000
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#define  VERSION  "0.2b"

void statit(int tot,int nau){
     static int a = 0;

     char zoninha[] = { '\\' , '|' , '/' , '-' };

     fprintf(stderr, "status: %d%% %c\r", ((100*nau)/tot), zoninha[a++]);
     fflush(stderr);

     if(a==4) a = 0;
}

char usage(char *p, char *v){
     #ifdef PORTUGUES
       fprintf(stderr, "SMTP Scanner de usuários v%s - por Lucas & Nelson\n", v);
       fprintf(stderr, "use:     %s [OPÇÕES] [COMANDO]\n", p);
       fprintf(stderr, "exemplo: %s -h mail.leet.org -i userlist -o leet.txt -v\n\n", p);
       fprintf(stderr, "OPÇÕES:\n\t -h, --host     Servidor SMTP para testar\n");
       fprintf(stderr, "\t -i, --infile   lista de possíveis usuários\n");
       fprintf(stderr, "\t -o, --outfile  arquivo que armazenará os usuários válidos\n\n");
       fprintf(stderr, "COMANDO:\n\t -v, --vrfy     use comando VRFY\n");
       fprintf(stderr, "\t -e, --expn     use comando EXPN\n");
       fprintf(stderr, "\t -r, --rcpt     use comando RCPT - a nova técnica\n");
     #else
       fprintf(stderr, "SMTP's User Scanner v%s - By Lucas & Nelson\n", v);
       fprintf(stderr, "use:     %s [OPTIONS] [COMMAND]\n", p);
       fprintf(stderr, "example: %s -h mail.leet.org -i userlist -o leet.txt -v\n\n", p);
       fprintf(stderr, "OPTIONS:\n\t -h, --host     SMTP Server to test\n");
       fprintf(stderr, "\t -i, --infile   list of possible users\n");
       fprintf(stderr, "\t -o, --outfile  dump file with valid usernames\n\n");
       fprintf(stderr, "COMMAND:\n\t -v, --vrfy     use VRFY command\n");
       fprintf(stderr, "\t -e, --expn     use EXPN command\n");
       fprintf(stderr, "\t -r, --rcpt     use RCPT command - the new technique\n");
     #endif
     exit(0);
}

void u_abort(int s){
      #ifdef PORTUGUES
        fprintf(stderr,"\nmatando processo %d... ", getpid());
        usleep(300000);
        fprintf(stderr,"morto\n");
      #else
        fprintf(stderr,"\nkilling process %d... ", getpid());
        usleep(300000);
        fprintf(stderr,"killed\n");
      #endif
      exit(0);
}

int main(int argc, char **argv){

     struct sockaddr_in sin;
     struct hostent *ph;
     struct timeval tm_t;

     time_t start, end;
  
     int sock;
     int latual, ltotal, fusers, passed, opt, timer;

     char buff[500], linha[125], comando[125], atualc[125], *roste = NULL;
     char fake_roste[125];

     fd_set wakeup;
     FILE *usrin = NULL, *usrout = NULL;

     extern char *optarg;
     extern int optind;

     struct option opcoes[]={
          {"host",     1, 0, 'h'},
          {"infile",   1, 0, 'i'},
          {"outfile",  1, 0, 'o'},
          {"vrfy",     0, 0, 'v'},
          {"expn",     0, 0, 'e'},
          {"rcpt",     0, 0, 'r'},
          {0,          0, 0, 0}
     };
   
     latual = ltotal = fusers = opt = 0;

     if (argc != 8) usage(argv[0], VERSION);

     start = time(NULL);
   
     signal(SIGHUP, SIG_IGN);
     signal(SIGINT, u_abort);
     signal(SIGTERM, u_abort);
     signal(SIGKILL, u_abort);
     signal(SIGQUIT, u_abort);

     while((passed=getopt_long(argc, argv, "h:i:o:ver", opcoes, NULL)) != -1)
         switch(passed){
             case 'i':
	          if(!(usrin=fopen(optarg, "r"))){
                     perror("read");
	             exit(0);
	          }
                  break;
             case 'o':
                  if(!(usrout=fopen(optarg, "w"))){
                     perror("write");
                     exit(0);
                  }
                  break;
             case 'h':
                  roste = optarg;
                  break;
             case 'v':
                  opt = 1;
                  break;
             case 'e':
                  opt = 2;
                  break;
             case 'r':
                  opt = 3;
                  break;
             default:
                  printf(".");
                  break;
         }


     ph=gethostbyname(roste);
     if(!ph){
        perror("connect");
        exit(1);
     }

     memcpy((char*)&sin.sin_addr, ph->h_addr, ph->h_length);

     sin.sin_family   =   AF_INET;
     sin.sin_port     =   htons(IPPORT_SMTP);
     sin.sin_addr     =   *((struct in_addr *)ph->h_addr);

     if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("socket");
        exit(1);
     }

     if(connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("connect");
        exit(1);
     }
     
     #ifdef PORTUGUES
       printf("conectado a %s\n",roste);
     #else
       printf("connected to %s\n",roste);
     #endif
   
     tm_t.tv_sec  =  40; /* timeout to connect */
     tm_t.tv_usec =  0;

     FD_ZERO(&wakeup);
     FD_SET(sock, &wakeup);

     if(!select(sock+1, &wakeup, NULL, NULL, &tm_t)){
        perror("connect");
        exit(0);
     }
   
     recv(sock, buff, 500, 0);
     memset(buff, 0, 500);

     while(fgets(linha, 125, usrin)) ltotal++;
   
     rewind(usrin);

     #ifdef PORTUGUES
       fprintf(usrout, "#arquivo de mail para %s\n", ph->h_name); 
     #else
       fprintf(usrout, "#mail file for %s\n", ph->h_name);
     #endif

     switch(opt){
         case 1:
              snprintf(atualc, 125, "VRFY");
              break;
         case 2:
              snprintf(atualc, 125, "EXPN");
              break;
         case 3:
              snprintf(fake_roste, 125, "HELO localhost.%s\n", ph->h_name);
              snprintf(atualc, 125, "RCPT TO:");
              send(sock, fake_roste, strlen(fake_roste), 0);
              send(sock,"MAIL FROM: root@localhost\n", 26, 0); //weaken anti-spans
              recv(sock, NULL, 600, 0);
              recv(sock, NULL, 600, 0);
              break;
     }
     
     #ifdef PORTUGUES
       printf("usando comando [%s]\n", atualc);
     #else
       printf("using [%s] command\n", atualc);
     #endif

     while(!feof(usrin)){
         if(!fgets(linha, 125, usrin)) snprintf(linha, 125, "\n");
         else latual++;
      
         snprintf(comando, 125, "%s %s", atualc, linha);
         send(sock, comando, strlen(comando), 0);  

         tm_t.tv_sec  =  20; /* timeout to command */
         tm_t.tv_usec =  0;
   
         FD_ZERO(&wakeup);
         FD_SET(sock,&wakeup);

         if(!select(sock+1, &wakeup, NULL, NULL, &tm_t)){
            perror("connect");
	    passed = 0;

          memcpy((char *)&sin.sin_addr, ph->h_addr, ph->h_length);
	    sin.sin_family =  AF_INET;
	    sin.sin_port   =  htons(IPPORT_SMTP);
	    sin.sin_addr   =  *((struct in_addr *)ph->h_addr);

          if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
             perror("socket");
             exit(1);
          }

          if(connect(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1){
             perror("connect");
             exit(1);
          }

          else{
              #ifdef PORTUGUES
                printf("reconectando em %s\n", roste);
                printf("retentando comando [%s]\n", atualc);
              #else
                printf("reconnected to %s\n", roste);
                printf("retrying [%s] command\n", atualc);
              #endif
           }

           recv(sock, buff, 500, 0);
           memset(buff, 0, 500);
           continue;
     }
    
     memset(buff, 0, 500);
     recv(sock, buff, 500, 0);
     buff[strlen(buff)+1] = 0x00;
 
/*
 * 250 = user ok
 * 550 = user unknow
 */
     if(strncmp(buff, "250", 3) == 0){
        fprintf(usrout, "%s", linha);
        fusers++;
     }

/*
 * 252 = vrfy failed
 * 502 = expn failed
 */
     if(opt == 1){
        if(strncmp(buff, "252", 3) == 0){
           #ifdef PORTUGUES
             printf("comando VRFY falhou\nfinalizando...\n");
           #else
             printf("VRFY command failed\nexiting...\n");
           #endif
           close(sock); fclose(usrin);
           fclose(usrout); exit(0);
        }
     }

     if(opt == 2){
        if(strncmp(buff, "502", 3) == 0){	 
           #ifdef PORTUGUES
             printf("comando EXPN falhou\nfinalizando...\n");
           #else
             printf("EXPN command failed\nexiting...\n");
           #endif
           close(sock); fclose(usrin);
           fclose(usrout); exit(0);
        }
     }

     statit(ltotal, latual);
     usleep(300000);
   }

   snprintf(atualc, 125, "QUIT\n");
   send(sock, atualc, strlen(atualc), 0);

   end   = time(NULL);
   timer = (int)difftime(end, start);
   
   #ifdef PORTUGUES
     printf("\nachados %i usuários em %d segundos\n", fusers, timer);
   #else
     printf("\nfound %i users in %d seconds\n", fusers, timer);
   #endif

   fclose(usrin); 
   fclose(usrout);
   
   close(sock); 

   return(1);
}

