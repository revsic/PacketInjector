#include <iostream>
#include <pcap.h>
#include "PacketInjector.h"

int main (int argc, char** argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev = pcap_lookupdev(errbuf);

  if (dev == NULL) {
    std::cout << "[*] Couldn't find default device : " << errbuf << std::endl;
    return -1;
  }

  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  if (handle == NULL) {
    std::cout << "[*] Couldn't open device : " << errbuf << std::endl;
    return -1;
  }

  struct pcap_pkthdr *header;
  const unsigned char *packet;
  PacketInjector pi = PacketInjector(handle);

  while (1) {
    int ret = pcap_next_ex(handle, &header, &packet);

    if (ret == 0) continue;
    else if (ret < 0) {
      std::cout << "[*] Couldn't receive packets." << std::endl;
      return -1;
    }

    pi.run(packet);
  }

  return 0;
}
