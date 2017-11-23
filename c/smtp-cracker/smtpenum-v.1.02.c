/* Author(s)     :       Lucas Fontes & Nelson Brito
 * E-mail(s      :       lucasfontes@clips.com.br & nbrito@sekure.org
 * File          :       smtpenum-v.1.02.c
 * Version       :       0.4 Alpha
 * CVE           :       N/A
 * Country       :       Brazil
 * Date          :       11/02/2000
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
#ifdef   PORTUGUES
#define  VERSION  "0.4a(PRIVADA)" 
#else
#define  VERSION  "0.4a(PRIVATE)"
#endif

void statit(int tot, int nau, char *iuzer){
     static int a = 0;

     char zoninha[]    = { '\\' , '|' , '/' , '-' };
     int percent = ((100*nau)/tot);
     char *iuzer_atual  = strtok(iuzer, "\x0A");

     #ifdef PORTUGUES
       fprintf(stderr, "Processo : %d%% [%c]\t\t|\t\tUsuário : [%12s]\r", percent, zoninha[a++], (iuzer_atual != NULL) ? iuzer_atual : "............");
     #else
       fprintf(stderr, "Process : %d%% [%c]\t\t|\t\tUser : [%12s]\r", percent, zoninha[a++], (iuzer_atual != NULL) ? iuzer_atual : "............");
     #endif
     fflush(stderr);

     if(a==4) a = 0;
}

char usage(char *p, char *v){
     #ifdef PORTUGUES
       fprintf(stderr, "Scanner de Usuários por SMTP v%s - por Lucas & Nelson\n", v);
       fprintf(stderr, "Use:     %s [OPÇÕES] [COMANDOS]\n\n", p);
       fprintf(stderr, "OPÇÕES:\n\t -h, --host     Servidor SMTP para testar\n");
       fprintf(stderr, "\t -i, --infile   lista de possíveis usuários\n");
       fprintf(stderr, "\t -o, --outfile  arquivo que armazenará os usuários válidos\n\n");
       fprintf(stderr, "COMANDOS:\n\t -v, --vrfy     use comando VRFY\n");
       fprintf(stderr, "\t -e, --expn     use comando EXPN\n");
       fprintf(stderr, "\t -r, --rcpt     use comando RCPT - nossa nova técnica [*]\n\n[*] A nova técnica funciona contra \"O MaxRecipientPerMessage=NN\" abilitada,\nprocurando por DSN 452(too many recipients).\n");
     #else
       fprintf(stderr, "User Scanner by SMTP v%s - By Lucas & Nelson\n", v);
       fprintf(stderr, "Use:     %s [OPTIONS] [COMMANDS]\n\n", p);
       fprintf(stderr, "OPTIONS:\n\t -h, --host     SMTP Server to test\n");
       fprintf(stderr, "\t -i, --infile   list of possible users\n");
       fprintf(stderr, "\t -o, --outfile  dump file with valid usernames\n\n");
       fprintf(stderr, "COMMANDS:\n\t -v, --vrfy     use VRFY command\n");
       fprintf(stderr, "\t -e, --expn     use EXPN command\n");
       fprintf(stderr, "\t -r, --rcpt     use RCPT command - our new technique [*]\n\n[*] The new technique works against \"O MaxRecipientPerMessage=NN\" enabled,\nlooking for DSN 452(too many recipients).\n");
     #endif
     exit(0);
}

void u_abort(int s){ 
      #ifdef PORTUGUES
        fprintf(stderr,"\nProcesso %d abortado...\n", getpid());
      #else
        fprintf(stderr,"\nProcess %d aborted...\n", getpid()); 
      #endif
      exit(0);
}

int conecta(char *onde){
      struct sockaddr_in sin;
      struct hostent     *ph;

      int sock;

      ph=gethostbyname(onde);

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

      return sock;
}

int main(int argc, char **argv){

     struct timeval tm_t;
     time_t start = time(NULL), end;
  
     int sock;
     register int latual, ltotal, fusers, passed, opt, timer, op;

     char buff[500], linha[125], comando[125], atualc[125], *roste = NULL;
     char fake_roste[125];

     fd_set wakeup;
     FILE *usrin = NULL, *usrout = NULL; // Necessario a inicializacao sas variaveis
                                         // como NULL, caso contrario, varios  erros
     extern char *optarg;                // serao reportados em tempo de compilacao!
     extern int optind;

     latual = ltotal = fusers = opt = 0;

     if (argc != 8) usage(argv[0], VERSION);

     signal(SIGHUP,  SIG_IGN);
     signal(SIGINT,  u_abort);
     signal(SIGTERM, u_abort);
     signal(SIGKILL, u_abort);
     signal(SIGQUIT, u_abort);

     while(1){ 
        static struct option opcoes[]={
             {"host",     1, 0, 'h'},
             {"infile",   1, 0, 'i'},
             {"outfile",  1, 0, 'o'},
             {"vrfy",     0, 0, 'v'},
             {"expn",     0, 0, 'e'},
             {"rcpt",     0, 0, 'r'},
             {0,          0, 0, 0}
        };

        int option_index = 0;
        op = getopt_long(argc, argv, "h:i:o:ver", opcoes, &option_index);
    
        if(op == -1) break;

           switch(op){
                case 'h':
                      roste = optarg;
                      break;
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
                      usage(argv[0], VERSION);
                      break;
           }
     }

     passed = 0;

     if(!(sock = conecta(roste))){
        perror("socket");
        exit(0);
     }

     
     #ifdef PORTUGUES
       printf("Conectado a %s, ", roste);
     #else
       printf("Connected to %s, ", roste);
     #endif
   
     tm_t.tv_sec  =  40; 
     tm_t.tv_usec =  0;
     FD_ZERO(&wakeup);
     FD_SET(sock, &wakeup); 

     if(!select(sock+1, &wakeup, NULL, NULL, &tm_t)){ // timeouted(?)
        perror("connect");
        exit(0);
     }
   
     memset(buff, 0, 500);
     recv(sock, buff, 500, 0);

     while(fgets(linha, 125, usrin)) ltotal++;
   
     rewind(usrin);

     #ifdef PORTUGUES
       fprintf(usrout, "# Arquivo criado por %s v. %s - por Nelson & Lucas\n", argv[0], VERSION);
       fprintf(usrout, "# Listagem de usuários válidos para %s:\n", roste); 
     #else
       fprintf(usrout, "# File created by %s v. %s - By Nelson & Lucas\n", argv[0], VERSION);
       fprintf(usrout, "# Valid users list for %s:\n", roste);
     #endif

     /* Apenas uma recomendacao, em caso de voce estar utilizando UNIX, troque o sprintf(3) por
        snprintf(3). */
     switch(opt){
         case 1:
              snprintf(atualc, 125, "VRFY");
              break;
         case 2:
              snprintf(atualc, 125, "EXPN");
              break;
         case 3:
              snprintf(fake_roste, 125, "HELO localhost.%s\n", roste);
              snprintf(atualc, 125, "RCPT TO:");
              send(sock, fake_roste, strlen(fake_roste), 0);
              recv(sock, buff, 500, 0); 
              send(sock, "MAIL FROM: root@localhost\n", 26, 0); // anti-relay(?)
              recv(sock, buff, 500, 0); 
              memset(buff, 0, 500);
              break;
     }
     
     #ifdef PORTUGUES
       printf("usando comando [%s]!\n", atualc);
     #else
       printf("using [%s] command!\n", atualc);
     #endif

     while(!feof(usrin)){
         if(passed != 1){
            if(!fgets(linha, 125, usrin)) snprintf(linha, 125, "\n");
            else latual++;
         }

         else passed = 0;

         snprintf(comando, 125, "%s %s", atualc, linha);
         send(sock, comando, strlen(comando), 0);  

         tm_t.tv_sec  =  40; 
         tm_t.tv_usec =  0;
         FD_ZERO(&wakeup);
         FD_SET(sock, &wakeup);

         if(!select(sock+1, &wakeup, NULL, NULL, &tm_t)){ // timeouted(?)
            perror("reconnect");
            passed = 0;

          if(!(sock = conecta(roste))){
             perror("socket");
             exit(1);
          }

          else{
              #ifdef PORTUGUES
                printf("\nReconectado em %s, ", roste);
                printf("retentando comando [%s]!\n", atualc);
              #else
                printf("\nReconnected to %s, ", roste);
                printf("retrying [%s] command!\n", atualc);
              #endif
           }

           memset(buff, 0, 500);     // O memset() estava embaixo do recv(), fazendo
           recv(sock, buff, 500, 0); // com  que  o  retorno  do  comando MAIL fosse
           continue;                 // repassado pro do RCPT. Ja' corrigido.
     }
    
     memset(buff, 0, 500);           // Aqui acontecia a mesma coisa. =)
     recv(sock, buff, 500, 0);       
     buff[strlen(buff)+1] = 0x00;
 
/*
 * 250 = DSN retornado  no  caso  do  usuario existir(aliases tambem).
 * 550 = DSN retornado no caso do usuario nao existir(aliases tambem).
 * 452 = DSN retornado  no  caso  de nao podermos continuar executando 
 *       o  comando  RCPT caso a macro  MaxRecipientPerMessage  esteja 
 *       habilitada.
 */
        if(strncmp(buff, "250", 3) == 0){
           fprintf(usrout, "%s", linha);
           fusers++;
        }

        else if(strncmp(buff, "452", 3) == 0){ // 
                close(sock); passed = 1; 

                if(!(sock = conecta(roste))){  
                   perror("socket");
                   exit(0);
                }

                tm_t.tv_sec  =  40; 
                tm_t.tv_usec =  0;
                FD_ZERO(&wakeup);
                FD_SET(sock, &wakeup);

                if(!select(sock+1, &wakeup, NULL, NULL, &tm_t)){ // timeouted(?)
                   perror("reconnect");
                   passed = 0;
                }

                snprintf(fake_roste, 125, "HELO localhost.%s\n", roste);
                snprintf(atualc, 125, "RCPT TO:");
                send(sock, fake_roste, strlen(fake_roste), 0);
                recv(sock, buff, 500, 0);
                send(sock,"MAIL FROM: root@localhost\n", 26, 0); // anti-relay(?)
                recv(sock, buff, 500, 0);
                memset(buff, 0, 500);

                memset(buff, 0, 500);
                recv(sock, buff, 500, 0);
                buff[strlen(buff)+1] = 0x00;// Corrigido para nao pegar mensagens
                continue;                   // de comandos anteriores, fakes...
        }

/*
 * 252 = DSN retornado no caso de nao podermos executar o comando VRFY
 * 502 = DSN retornado no caso de nao podermos executar o comando EXPN
 */
     if(opt == 1){
        if(strncmp(buff, "252", 3) == 0){
           #ifdef PORTUGUES
             printf("Comando VRFY falhou, finalizando...\n");
           #else
             printf("VRFY command failed, exiting...\n");
           #endif
           close(sock); fclose(usrin);
           fclose(usrout); exit(0);
        }
     }

     if(opt == 2){
        if(strncmp(buff, "502", 3) == 0){        
           #ifdef PORTUGUES
             printf("Comando EXPN falhou, finalizando...\n");
           #else
             printf("EXPN command failed, exiting...\n");
           #endif
           close(sock); fclose(usrin);
           fclose(usrout); exit(0);
        }
     }

     statit(ltotal, latual, linha);
   }

   snprintf(atualc, 125, "QUIT\n"); // Nao deixando erro nos LOGS!
   send(sock, atualc, strlen(atualc), 0);

   end   = time(NULL);
   timer = (int)difftime(end, start); // Quanto tempo demorou a execucao?!?!

   #ifdef PORTUGUES
     fprintf(usrout, "# Comando executado em %d segundos, achados %d(%d%%) usuários corretos!\n", \
     timer, fusers, ((100*fusers)/ltotal));
     fprintf(stderr, "\nComando executado em %d segundos, achados %d(%d%%) usuários corretos!\n", \
     timer, fusers, ((100*fusers)/ltotal));
   #else
     fprintf(usrout, "# Command executed in %d seconds, found %d(%d%%) correct users!\n", \
     timer, fusers, ((100*fusers)/ltotal));
     fprintf(stderr, "\nCommand executed in %d seconds, found %d(%d%%) correct users!\n", \
     timer, fusers, ((100*fusers)/ltotal));
   #endif

   fclose(usrin); 
   fclose(usrout);
   
   close(sock); 

   return(1);
}

