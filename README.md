# Packet-Injection

detect certain packet and inject forward or backward

1. detect certain packet : ex) HTTP GET
```cpp
if (tcp.phdr->tcp_dport == TCP_PORT_HTTP) {
    if (tcp.pdat.length && !strncmp((char *)tcp.pdat.data, "GET", 3)) {
        char *tmp = strchr((char *)tcp.pdat.data, '\n');

        if (tmp) *tmp = '\0';
        std::cout << "[*] blocked : " << tcp.pdat.data << std::endl;

        injectForward(ip, tcp);
        injectBackward(eth, ip, tcp);
    }
}
```

2. inject packet backward or forward : ex) HTTP 302 redirect, fin or rst flag packet
```cpp
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
```
