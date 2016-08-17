#include "PacketInjector.h"

PacketInjector::PacketInjector(pcap_t* p_handle) : handle(p_handle)
{}

int PacketInjector::run(const unsigned char* p_packet) {
  packet = p_packet;
  Ethernet eth = Ethernet(packet);

  if (eth.phdr->ether_type == ETHER_TYPE_IPv4) {
    IPv4 ip = IPv4(packet + ETHER_HEAD_LEN);

    if (ip.phdr->ip_protocol == IP_PRTCL_TCP) {
      int ip_len = ntohs(ip.phdr->ip_len);
      int ip_hdrlen = ip.phdr->ip_header_len << 2;

      TCP tcp = TCP(packet + ETHER_HEAD_LEN + ip_hdrlen, ip_len - ip_hdrlen);
      if (tcp.phdr->tcp_dport == TCP_PORT_HTTP) {
        if (tcp.pdat.length && !strncmp((char *)tcp.pdat.data, "GET", 3)) {
          char *tmp = strchr((char *)tcp.pdat.data, '\n');
          if (tmp) *tmp = '\0';
          std::cout << "[*] blocked : " << tcp.pdat.data << std::endl;

          injectForward(ip, tcp);
          injectBackward(eth, ip, tcp);
        }
      }
    }
  }
}

int PacketInjector::setProperty(IPv4& ip, TCP& tcp, unsigned short flag, const char* msg) {
  tcp.phdr->tcp_flags |= flag;

  int msg_len = strlen(msg);
  int tcp_hdrlen = tcp.phdr->tcp_header_len << 2;
  int ip_hdrlen = ip.phdr->ip_header_len << 2;
  int ip_len = ip_hdrlen + tcp_hdrlen + msg_len;

  ip.phdr->ip_len = htons(ip_len);
  strcpy((char *)tcp.pdat.data, msg);
  tcp.pdat.length = strlen(msg);

  ip.makeChecksum();
  tcp.makeChecksum(ip);

  return ip_len;
}

int PacketInjector::injectForward(IPv4& ip, TCP& tcp) {
  u_int32_t seqtmp = tcp.phdr->tcp_seq_num;
  tcp.phdr->tcp_seq_num = htonl(ntohl(seqtmp) + tcp.pdat.length);

  int ip_len = setProperty(ip, tcp, TCP_FLAG_RST, "");
  int total_len = ETHER_HEAD_LEN + ip_len;
  int result = pcap_sendpacket(handle, packet, total_len);

  tcp.phdr->tcp_seq_num = seqtmp;
  tcp.phdr->tcp_flags ^= TCP_FLAG_RST;

  return result;
}

int PacketInjector::injectBackward(Ethernet& eth, IPv4& ip, TCP& tcp) {
  for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
    u_int8_t etmp = eth.phdr->ether_dhost[i];
    eth.phdr->ether_dhost[i] = eth.phdr->ether_shost[i];
    eth.phdr->ether_shost[i] = etmp;
  }

  struct in_addr itmp = ip.phdr->ip_dst;
  ip.phdr->ip_dst = ip.phdr->ip_src;
  ip.phdr->ip_src = itmp;

  u_int16_t ptmp = tcp.phdr->tcp_dport;
  tcp.phdr->tcp_dport = tcp.phdr->tcp_sport;
  tcp.phdr->tcp_sport = ptmp;

  u_int32_t atmp = tcp.phdr->tcp_ack_num;
  tcp.phdr->tcp_ack_num = htonl(ntohl(tcp.phdr->tcp_seq_num) + tcp.pdat.length);
  tcp.phdr->tcp_seq_num = atmp;

  int ip_len = setProperty(ip, tcp, TCP_FLAG_FIN, BLOCK_MSG);
  int total_len = ETHER_HEAD_LEN + ip_len;
  int result = pcap_sendpacket(handle, packet, total_len);

  return result;
}
