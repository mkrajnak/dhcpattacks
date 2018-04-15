#include "pds-dhcpstarve.h"

void help() {
  printf("HELP\n");
}

void err(string msg, int erno, short show_help){
  perror( msg.c_str());
  if (show_help) help();
  exit(erno);
}

char* checkArgs(int argc, char **argv) {
  if ((argc != 3 ) || (strcmp(argv[1], "-i") != 0)) {
    err("Wrong arguments", 1, 0);
  }
  return argv[2];
}

void increment_mac_addr (uint8_t *addr ){
  for (int i = MAC_ADDR_MAX_INDEX; i > -1; i--) {
    if (addr[i] != MAX_OCTET_HEX) { // 0xff aka 255
      addr[i]++;
      return;
    }
  }
  for (size_t i = 0; i < ETH_ALEN; i++) {
    addr[i] = 0;
  }
  addr[MAC_ADDR_MAX_INDEX] = 1;
}

/**
* Create in_addr* from string(char *) for ip header
*/
struct in_addr* str_to_ip(const char* addr){
  struct in_addr* tmp = NULL;
  tmp = (struct in_addr*) malloc(sizeof(struct in_addr));
  if (tmp == NULL) {
    err("malloc: failed to create (struct in_addr*)", ERR, 0);
  }
  int e;
  if ((e = inet_pton(AF_INET, addr, tmp)) != 1) {
    err("inet_pton: Failed to convert ip adr", e, 0);
  }
  return tmp;
}

int main(int argc, char** argv) {
  char* interface_name = checkArgs(argc, argv); // get name of the interface

  uint8_t src_mac_addr[6];  // set dst mac for broadcast
  src_mac_addr[0] = MIN_OCTET_HEX;
  src_mac_addr[1] = MIN_OCTET_HEX;
  src_mac_addr[2] = MIN_OCTET_HEX;
  src_mac_addr[3] = MIN_OCTET_HEX;
  src_mac_addr[4] = MIN_OCTET_HEX;
  src_mac_addr[5] = MAX_OCTET_HEX;

  increment_mac_addr(src_mac_addr);
  for (size_t i = 0; i < ETH_ALEN; i++) {
    printf("%d\n",src_mac_addr[i] );
  }

  struct sockaddr_ll interface;
  if ((interface.sll_ifindex = if_nametoindex (interface_name)) == 0) {
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface_name, interface.sll_ifindex);

  interface.sll_family = AF_PACKET;
  memcpy(interface.sll_addr, src_mac_addr, 6 * sizeof(uint8_t));
  interface.sll_halen = ETH_ALEN;
  interface.sll_pkttype = PACKET_BROADCAST; // Use broadcast packet
  interface.sll_protocol = ETH_P_802_3;

  struct ip header;
  header.ip_v = 4;
  header.ip_hl = 5;
  header.ip_tos = 0;
  header.ip_len =
  header.ip_ttl = IP4_MAX_TTL;
  header.ip_p = IPPROTO_UDP;
  header.ip_src = *str_to_ip("0.0.0.0");
  header.ip_dst = *str_to_ip(IP4_BROADCAST);
  //uint8_t src_mac_addr[6];  // set dst mac for broadcast
  // int sd = 0;
  // if ((sd = socket (PF_PACKET, SOCK_RAW, IPPROTO_RAW) < 0) {
  //   perror ("socket() failed to get socket descriptor for using ioctl() ");
  //   exit (EXIT_FAILURE);
  // }
  // if (close(sd) < 0) {
  //   err("Failed to close the socket", sd, 0);
  // }


}
