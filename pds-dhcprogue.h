#ifndef DSERVER_H
#define DSERVER_H

#include <fstream>
#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <algorithm>
#include <iostream>
#include <getopt.h>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netdb.h>

using namespace std;

#define ERR -1

// DHCP MESSAGE numbers
const int DHCP_NONE = 0;
const int DHCP_DISCOVER = 1;
const int DHCP_OFFER = 2;
const int DHCP_REQUEST = 3;
const int DHCP_DECLINE = 4;
const int DHCP_ACK = 5;
const int DHCP_NAK = 6;
const int DHCP_RELEASE = 7;
const int DHCP_INFORM	 = 8;

#define DHCP_DST_PORT 68
#define DHCP_SRC_PORT 67
#define ETH_BUF_SIZE 1024
#define DHCP_BUFFER_SIZE 400

#define ETH_HEADER_LEN 14
#define IP4_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define MAC_ADDR_LEN 6

const char * IP4_BROADCAST = "255.255.255.255";

struct pool_item{
  uint8_t mac_addr[MAC_ADDR_LEN];
  uint32_t ip_addr;
  time_t lease_expiration;
}pool_item;

struct ip_pool{
  string interface;
  uint32_t int_ip_address;
  uint32_t int_ip_netmask;
  uint8_t int_mac_address[MAC_ADDR_LEN];
  uint32_t ip_first;
  uint32_t ip_last;
  uint32_t ip_next;
  uint32_t ip_gateway;
  uint32_t ip_dns;
  string domain;
  string lease_time;
  vector <uint32_t> ip_pool;
  vector <struct pool_item> leased_list;
}ip_pool;

// Global variables for cleanup purposes
int send_socket = 0;
int listen_socket = 0;
struct ip_pool* p;
#endif
