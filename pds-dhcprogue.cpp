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

void send_offer(unsigned char *msg);
void send_ack(unsigned char *msg);

void dhcp(struct sockaddr_ll intfc) {
  unsigned char msg[DHCP_BUF_SIZE];
  bzero(msg, DHCP_BUF_SIZE);
  socklen_t length = sizeof(intfc);

  int rcvd = 0; // receive data and decive what to do
  while((rcvd = recvfrom(listen_socket, msg, DHCP_BUF_SIZE, 0, (struct sockaddr *)&intfc, &length)) >= 0)
  {
    switch (msg[242]) {
      case (int) DHCP_DISCOVER:
        printf("DISCOVER\n");
        break;
      case (int) DHCP_REQUEST:
        //send_ack(msg);
        break;
      // case (int) DHCP_RELEASE:
      //   release(msg);
        break;
      default: break;
    }
    bzero(msg,DHCP_BUF_SIZE);
  }
}

void server_start() {
  // lets create server socket so we don't have to bother with parsing headers
  if((listen_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    err ("Failed to create SOCK_DGRAM", listen_socket, 0);
  }
  struct sockaddr_in srv;
  bzero(&srv, sizeof(srv));
  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr = INADDR_ANY;     // dont care
  srv.sin_port = htons(DHCP_SRC_PORT);  // 67

  if((bind(listen_socket, (struct sockaddr *)&srv, sizeof(srv))) != 0) {
    err ("Failed to bind listen socket", listen_socket, 0);
  }
  // setup second raw socket for sending, so we can use L2 unicast
  if ((send_socket = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    err ("Failed to create SOCK_RAW", send_socket, 0);
  }
  struct sockaddr_ll interface;
  if ((interface.sll_ifindex = if_nametoindex(p->interface.c_str())) == 0) {
    err("if_nametoindex failed, wrong network interface name ?", ERR, 0);
  }
  interface.sll_family = AF_PACKET;   // setup interface, see "man packet"
  interface.sll_protocol = htons(ETH_P_ALL);
  // all set, continue
  dhcp(interface);
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
