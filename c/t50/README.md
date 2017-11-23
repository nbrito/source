```
  ___________._______________
  \__    ___/|   ____/\   _  \   T50: an Experimental Packet Injector Tool
    |    |   |____  \ /  /_\  \                 Release 5.3
    |    |   /       \\  \_/   \
    |____|  /______  / \_____  /   Copyright (c) 2001-2011 Nelson Brito
                   \/        \/             All Rights Reserved
```
# T50: an Experimental Packet Injector Tool
**T50** is an Experimental Mixed Packet Injector (based on private tools: ```b52```, ```f117``` and ```f22```), and a tool designed to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)). Its concept started in 2001, right after release [```nb-isakmp.c```](https://github.com/nbrito/research/blob/master/cve/CVE-2001-0951/nb-isakmp.c), which the main goal would be:
* Having a tool to perform TCP/IP protocol [fuzzer](https://en.wikipedia.org/wiki/Fuzzing), covering common regular protocols, such as: [ICMP](https://tools.ietf.org/rfc/rfc792.txt), [TCP](https://tools.ietf.org/rfc/rfc793.txt) and [UDP](https://tools.ietf.org/rfc/rfc768.txt).

Things have changed, and the **T50** became a good unique resource capable to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)). Some protocols were chosen to be part of its [very first release](https://github.com/nbrito/source/tree/master/c/t50/2.45r) coverage:
* [ICMP (Internet Control Message Protocol)](https://tools.ietf.org/rfc/rfc792.txt)
* [IGMP (Internet Group Management Protocol)](https://tools.ietf.org/rfc/rfc988.txt)
* [TCP (Transmission Control Protocol)](https://tools.ietf.org/rfc/rfc793.txt)
* [UDP (User Datagram Protocol)](https://tools.ietf.org/rfc/rfc768.txt)

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
**T50** was designed to perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)) on a variety of infra-structure network devices ([2.45](https://github.com/nbrito/source/tree/master/c/t50/2.45r)), using widely implemented protocols, and after some requests it was was re-designed to extend the tests ([5.3](https://github.com/nbrito/source/tree/master/c/t50/5.3) and [5.3r1](https://github.com/nbrito/source/tree/master/c/t50/5.3)), covering some regular protocols (ICMP, TCP and UDP), some infra-structure specific protocols (GRE, IPSec and RSVP), and some routing protocols (RIP, EIGRP and OSPF).

This new version ([5.3](https://github.com/nbrito/source/tree/master/c/t50/5.3) and [5.3r1](https://github.com/nbrito/source/tree/master/c/t50/5.3)) is focused on internal infra-structure, which allows people to test the availability of its resources.

### Interior Gateway Protocols (Distance Vector Algorithm)
* Routing Information Protocol
* Enhanced Interior Gateway Routing Protocol

### Interior Gateway Protocols (Link State Algorithm)
* Open Shortest Path First

### Quality-of-Service Protocols
* Resource ReSerVation Protocol

### Tunneling/Encapsulation Protocols
* Generic Routing Encapsulation

**T50** is a powerful and unique packet injector tool, which is capable to:
1. Send sequentially the following fourteen (14) protocols: ICMP, IGMPv1, IGMPv3, TCP , EGP, UDP, RIPv1, RIPv2, DCCP, RSVP, GRE, IPSec (AH/ESP), EIGRP, and OSPF.
2. It is the only tool capable to encapsulate the protocols (listed above) within Generic Routing Encapsulation (GRE).
3. Send an (quite) incredible amount of packets per second, making it a _second to none_ tool:
* More than 120,000 pps of [SYN](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#CONNECTION-ESTABLISHMENT)  (+60% of the network uplink) in a [100BASE-TX](https://en.wikipedia.org/wiki/Fast_Ethernet#100BASE-TX) network ([Fast Ethernet] (https://en.wikipedia.org/wiki/Fast_Ethernet)).
* More than 1,000,000 pps of [SYN](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#CONNECTION-ESTABLISHMENT)  (+50% of the network uplink) in a [1000BASE-T](https://en.wikipedia.org/wiki/Gigabit_Ethernet#1000BASE-T) network ([Gigabit Ethernet](https://en.wikipedia.org/wiki/Gigabit_Ethernet)).
4. Perform [stress testing](https://en.wikipedia.org/wiki/Stress_testing_(software)) on a variety of network infrastructure, network devices and security solutions in place.
5. Simulate [Distributed Denial-of-Service and Denial-of-Service](https://en.wikipedia.org/wiki/Denial-of-service_attack) attacks, validating Firewall rules, Router ACLs, Intrusion Detection System and Intrusion Prevention System policies.

The main differentiator of the **T50** is that it is able to send all protocols, sequentially, using one single [RAW(7) SOCKET](https://en.wikipedia.org/wiki/Raw_socket), besides it can be capable to modify network routes.

For current release of **T50**, please, refer to this [link](https://github.com/fredericopissarra/t50).

## Credits
[Nelson Brito](https://fnstenv.blogspot.com) (a.k.a. repository's owner)

## Disclaimer
Codes are available for research purposes only, and the repository's owner vehemently denies the malicious use, as well as the illegal purpose use, of any information, code and/or tool contained in this repository.

If you think there is any information, code and/or tool that sould not be here, please, contact the repository's owner.

## Warning
This repository does not provide you with any legal rights to any intellectual property in any information, code and/or tool, also, be aware that the use of some information, code and/or tool may be forbidden in some countries, and there may be rules and laws prohibiting any unauthorized user from use the information, code and/or tool, being these actions considered illegal.
