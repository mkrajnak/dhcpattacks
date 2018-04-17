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

int main(int argc, char **argv) {
  struct ip_pool* p = check_args(argc, argv);
  free(p);
  return 0;
}
