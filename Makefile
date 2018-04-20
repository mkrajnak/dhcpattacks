CC=g++
CXXFLAGS=-O2 -g -Wall -Wextra -pedantic -std=c++11
LDFLAGS=-Wl,-rpath=/usr/local/lib/gcc49/
STARVE=pds-dhcpstarve.cpp pds-dhcpstarve.h
SERVER=pds-dhcprogue.cpp pds-dhcprogue.h
all: clean pds-dhcpstarve pds-dhcprogue

starve: $(STARVE)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(STARVE) -o pds-dhcpstarve

rogue: $(SERVER)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(SERVER) -o pds-dhcprogue

clean:
	rm -f pds-dhcpstarve pds-dhcprogue
