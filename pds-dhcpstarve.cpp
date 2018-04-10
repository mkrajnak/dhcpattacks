#include <iostream>
#include <getopt.h>
#include <cstring>

using namespace std;

void help() {
  printf("HELP\n");
}

void err(string msg, int erno, short show_help){
  fprintf(stderr, "%s\n", msg.c_str());
  if (show_help) help();
  exit(erno);
}

string checkArgs(int argc, char **argv) {
  if ((argc != 3 ) || (strcmp(argv[1], "-i") != 0)) {
    err("Wrong arguments", 1, 0);
  }
  return argv[2];
}

int main(int argc, char** argv) {
  string interface = checkArgs(argc, argv);
  return 0;

}
