#ifndef TCP_H
#define TCP_H

#include <arpa/inet.h>
#include <string.h>
#include "IPv4.h"

#define TCP_PORT_HTTP htons(80)
#define TCP_FLAG_FIN 1
#define TCP_FLAG_RST 4

class TCP {
private:
  struct TCP_Header {
    u_int16_t tcp_sport, tcp_dport;
    u_int32_t tcp_seq_num;
    u_int32_t tcp_ack_num;
    u_int8_t tcp_reserved:4;
    u_int8_t tcp_header_len:4;
    u_int8_t tcp_flags;
    u_int16_t tcp_window;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgent;
  };

  struct TCP_Data {
    u_int32_t length;
    const u_int8_t *data;
  };

public:
  TCP_Header *phdr;
  TCP_Data pdat;
  TCP(const u_char *packet, int seg_len);

  void makeChecksum(IPv4& ip);
};

#endif
