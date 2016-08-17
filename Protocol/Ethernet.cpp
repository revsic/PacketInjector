#include "Ethernet.h"

Ethernet::Ethernet(const u_char* packet) {
  phdr = (Ethernet_Header *)packet;
}
