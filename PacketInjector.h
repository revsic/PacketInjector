#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <iostream>
#include <string.h>
#include <pcap.h>
#include "Protocol/Ethernet.h"
#include "Protocol/IPv4.h"
#include "Protocol/Tcp.h"

#define BLOCK_MSG "HTTP/1.1 302 Found\nLocation: https://en.wikipedia.org/wiki/HTTP_302\n"

class PacketInjector {
private:
  pcap_t* handle;
  const unsigned char* packet;

public:
  PacketInjector(pcap_t* p_handle);

  int run(const unsigned char* p_packet);
  int setProperty(IPv4& ip, TCP& tcp, unsigned short flags, const char *msg);
  int injectForward(IPv4& ip, TCP& tcp);
  int injectBackward(Ethernet& eth, IPv4& ip, TCP& tcp);
};

#endif
