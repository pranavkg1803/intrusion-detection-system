#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

struct packetStruct{
  struct pcap_pkthdr *theHeader;
  const unsigned char *thePacket;
  int theVerbose;
};

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void* threadFunction(void* arg);

#endif
