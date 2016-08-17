#ifndef IPV4_H
#define IPV4_H

#include <sys/types.h>
#include <arpa/inet.h>
#define IP_PRTCL_TCP 6

class IPv4 {
private:
  struct IPv4_Header {
    u_int8_t ip_header_len:4;
    u_int8_t ip_version:4;
    u_int8_t ip_type;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_offset;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_checksum;
    struct in_addr ip_src, ip_dst;
  };

public:
  IPv4_Header* phdr;
  IPv4(const u_char* packet);

  void makeChecksum();
};

#endif
