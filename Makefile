CC=g++
CXXFLAGS=-O2 -g -Wall -Wextra -pedantic -std=c++11
LDFLAGS=-Wl,-rpath=/usr/local/lib/gcc49/
SERVER=pds-dhcpstarve.cpp pds-dhcpstarve.h
all: pds-dhcpstarve

dserver: $(SERVER)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(SERVER) -o $@
clean:
	rm -f pds-dhcpstarve

