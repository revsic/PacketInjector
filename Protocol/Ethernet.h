#ifndef ETHERNET_H
#define ETHERNET_H

#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HEAD_LEN 14
#define ETHER_TYPE_IPv4 htons(0x0800)

class Ethernet {
private:
  struct Ethernet_Header {
    u_int8_t ether_dhost[ETHER_ADDR_LEN];
    u_int8_t ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
  };

public:
  Ethernet_Header* phdr;
  Ethernet(const u_char* packet);
};

#endif
