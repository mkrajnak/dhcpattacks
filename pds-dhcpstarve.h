#include <iostream>
#include <getopt.h>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>

using namespace std;

#ifndef UNTITLED1_PDS_DHCPSTARVE_H
#define UNTITLED1_PDS_DHCPSTARVE_H

#define ERR -1
#define MIN_OCTET_HEX 0x00      // MINIMUM HEX VALUE OF OCTET
#define MAX_OCTET_HEX 0xff      // MAXIMUM HEX VALUE OF OCTET
#define MAX_OCTET_DEC 255       // MAXIMUM DEC VALUE OF OCTET
#define MAC_ADDR_MAX_INDEX 5    // MAXIMUM MAC ADDRESS ARRAY INDEX
#define MAC_ADDR_LEN 6          // MAC ADDRESS LENGTH

#define DHCP_BUFFER_SIZE 512
#define ETH_HEADER_LEN 14
#define IP4_HEADER_LEN 20
#define UDP_HEADER_LEN 8

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

const char* IP4_SRC_ADDR = "0.0.0.0";
const char* IP4_BROADCAST = "255.255.255.255";

int send_socket = 0;
int listen_socket = 0;

#endif //UNTITLED1_PDS_DHCPSTARVE_H
