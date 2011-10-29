#ifndef P538PROJECT2_H
#define P538PROJECT2_H
/*PCAP*/
#include <pcap.h>
/*NETWORK HEADERS*/
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "dhcp.h"
/*TIME HEADERS*/
#include <sys/time.h>
/*IO HEADERS*/
#include <string.h>
#include <sstream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iostream>
/*DS HEADERS*/
#include <map>
/*TYPE HEADERS*/
#include <stdint.h>
/*ALGO HEADERS*/
#include <algorithm>
#include <typeinfo>

#define Project2Begin namespace PROJECT2{
#define Project2End }

struct vsarphdr
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */

    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */

  };

#endif // P538PROJECT2_H
