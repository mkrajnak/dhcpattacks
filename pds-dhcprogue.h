#ifndef DSERVER_H
#define DSERVER_H

#include <fstream>
#include <stdio.h>
#include <regex>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <algorithm>

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

const int BUFSIZE = 512;
const int DHCP_SRV_PORT = 67;
const char * IP4_BROADCAST = "255.255.255.255";

using namespace std;
#endif
