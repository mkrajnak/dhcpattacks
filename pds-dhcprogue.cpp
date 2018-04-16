#include "pds-dhcprogue.h"

struct params{
  string interface;
  uint32_t ip_pool_start;
  uint32_t ip_pool_end;
  uint32_t ip_gateway;
  uint32_t ip_dns_server;
  string domain;
  string lease_time;
}params;

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


uint32_t str_to_ip(const char* addr){
  struct in_addr tmp;
  if ((inet_pton(AF_INET, addr, &tmp)) != 1) {
    err("inet_pton failed", ERR, 0);
  }
  return tmp.s_addr;
}

char* ip_to_str(uint32_t addr){
  char* buffer = (char *)malloc(INET_ADDRSTRLEN);
  check_null(buffer);

  struct in_addr tmp;
  tmp.s_addr = addr;

  if (inet_ntop(AF_INET, &tmp, buffer, INET6_ADDRSTRLEN) == NULL) {
    free(buffer);
    err("inet_ntop faild", ERR, 0);
  }
  return buffer;
}

void handle_pool(struct params* p, char* arg) {
  int delim = 0;
  for (size_t i = 0; i < strlen(arg); i++) {
    if (arg[i] == '-') {
      delim = i;
      break;
    }
  }
  if (!delim) {
    err("Could not parse pool", ERR, 1);
  }
  char* start = (char*)malloc(delim);
  check_null(start);
  char* end = (char*)malloc(strlen(arg)-delim-1);
  check_null(end);

  memcpy(start, arg, delim);
  memcpy(end, arg+delim+1, strlen(arg)-delim);

  p->ip_pool_start = str_to_ip(start);
  p->ip_pool_start = str_to_ip(end);

  free(start);
  free(end);
}

struct params* check_args(int argc, char **argv){
  struct params* p = (struct params*) malloc(sizeof(struct params));
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
        handle_pool(p, optarg);
        break;
      case 'g':
        p->ip_gateway = str_to_ip(optarg);
        break;
      case 'n':
        p->ip_dns_server = str_to_ip(optarg);
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
  uint32_t lel = str_to_ip(IP4_BROADCAST);
  char * lel_to_string = ip_to_str(lel);
  printf("%s\n", lel_to_string);
  check_args(argc, argv);
  free(lel_to_string);
  return 0;
}
