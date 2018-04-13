//
// Created by mkrajnak on 10.4.2018.
//

#ifndef UNTITLED1_PDS_DHCPSTARVE_H
#define UNTITLED1_PDS_DHCPSTARVE_H

#define ERR -1
#define MIN_OCTET_HEX 0x00      // MINIMUM HEX VALUE OF OCTET
#define MAX_OCTET_HEX 0xff      // MAXIMUM HEX VALUE OF OCTET
#define MAX_OCTET_DEC 255       // MAXIMUM DEC VALUE OF OCTET
#define MAC_ADDR_MAX_INDEX 5    // MAXIMUM MAC ADDRESS ARRAY INDEX
#define ETH_HEADER_LEN 14


#define IP4_BROADCAST "255.255.255.255" // DEFINE IPV4 BROADCAST ADDR
#define IP4_VERSION 4
#define IP4_MIN_HEADER_LEN 20       //
#define IP4_MIN_HEADER_IHL 5
#define IP4_MAX_TTL 255         // 8 BIT MAXIMUM
#define IP4_PRT_UDP 17          // UDP value from RFC


#include <iostream>
#include <getopt.h>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip.h>

using namespace std;

#endif //UNTITLED1_PDS_DHCPSTARVE_H
