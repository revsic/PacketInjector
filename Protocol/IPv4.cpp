#include "IPv4.h"

IPv4::IPv4(const u_char* packet) {
  phdr = (IPv4_Header *)packet;
}

void IPv4::makeChecksum() {
  int chksum = 0;
  unsigned short *shorter = (unsigned short *)phdr;
  phdr->ip_checksum = 0;

  int len = phdr->ip_header_len << 1;

  for (int i = 0; i < len; ++i) {
    chksum += shorter[i];
  }

  chksum = (chksum >> 16) + (chksum & 0xFFFF);
  chksum += (chksum >> 16);

  chksum ^= 0xFFFF;
  phdr->ip_checksum = chksum;
}
