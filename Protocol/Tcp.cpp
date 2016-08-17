#include "Tcp.h"
#include <stdio.h>

TCP::TCP(const u_char *packet, int seg_len) {
  phdr = (TCP_Header *)packet;

  int tcp_hdrlen = phdr->tcp_header_len << 2;
  pdat.length = seg_len - tcp_hdrlen;
  pdat.data = packet + tcp_hdrlen;
}

void TCP::makeChecksum(IPv4& ip) {
  int i, chksum = 0;
  int dlen = phdr->tcp_header_len << 1;
  unsigned short *shorter = (unsigned short *)phdr;

  phdr->tcp_checksum = 0;
  for (i = 0; i < dlen; ++i) {
    chksum += shorter[i];
  }

  dlen = pdat.length >> 1;
  shorter = (unsigned short *)pdat.data;

  for (i = 0; i < dlen; ++i) {
    chksum += shorter[i];
  }

  if (pdat.length & 1) {
    chksum += shorter[i]  & 0x00ff;
  }

  shorter = (unsigned short *)&ip.phdr->ip_src;
  chksum += shorter[0] + shorter[1];

  shorter = (unsigned short *)&ip.phdr->ip_dst;
  chksum += shorter[0] + shorter[1];

  chksum += htons(6);
  chksum += htons((phdr->tcp_header_len << 2) + pdat.length);

  chksum = (chksum >> 16) + (chksum & 0xFFFF);
  chksum += (chksum >> 16);

  chksum ^= 0xFFFF;
  phdr->tcp_checksum = chksum;

}
