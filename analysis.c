#include "analysis.h"
#include "dynamic_array.h"
#include "queue.h"

#include "sniff.h" //added

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

void analyse(struct pcap_pkthdr *header, const unsigned char *packet,
int verbose) {
  // TODO your part 2 code here
  int length = header-> len;
  //ARP detection
  struct ether_header *eth_header = (struct ether_header *) packet;
  unsigned short ethernet_type = ntohs(eth_header->ether_type);
  if(ethernet_type == ETHERTYPE_ARP){
    if(verbose){
      printf("\n Ether Type is ARP");
    }
  }
  
  const unsigned char *packetcurrent = packet + ETH_HLEN;
  struct iphdr *ip_header = (struct iphdr *) packetcurrent;
  //source ip is a 32 bit value so needs to be converted into a string
  int IP_HLEN = (ip_header->ihl) * 4;

  char source_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
  //function reads adress of source adress and writes 'INET_ADDSTRLEN' of it in a readable char 'source_ip' 
  char dest_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
  
  


  packetcurrent += IP_HLEN; //* by 4 to translate from the length in words to bytes
  struct tcphdr *tcp_header = (struct tcphdr *) packetcurrent;
  int TCP_HLEN = tcp_header->th_off *4;
  //SYN flood attacks
  //We don't use nthos on the tcp flags as they are single bit flags so are not affected by big/small endianess.
  if (tcp_header->th_flags & TH_SYN) {
    if(verbose){
      printf("\n\n === SYN Packet detected ===");
    }
  }


  int data_bytes = length - ETH_HLEN - IP_HLEN - TCP_HLEN; //amount of bytes is length of header - standard header length
  const unsigned char* payload = packet + ETH_HLEN + IP_HLEN + TCP_HLEN; 
  const char* searchString = "Host: www.google.co.uk"; //pointer to a char IS a String as a pointer to a char is an array of chars.
  const char* searchString2 = "Host: www.bbc.co.uk"; //searchString is a pointer that points to This string
  const char* match = strstr((const char*)payload, searchString); //Then by casting payload as const char*, it can be used as a string.
  //payload is a pointer to a char. StrStr treats payload as an array of chars and searches for 'searchString' within payload.
  const char* match2 = strstr((const char*)payload, searchString2);
  
  
  unsigned short dest_port = ntohs(tcp_header->th_dport);
  if (dest_port ==80){ //packet is sent to HTTP port.
    if(verbose){
      printf("\n\n === Packet with port Number 80 Detected ===");
    }
      if(match!= NULL){
        printf("\n==============================\nBlacklisted URL violation detected");
        printf("\nSource IP address: %s", source_ip);
        printf("\nDestination IP address: %s (google)", dest_ip);
        printf("\n==============================");
        

      } else if(match2!= NULL){
        //printf("\n HTTP request is from www.bbc.co.uk");
        
        printf("\n==============================\nBlacklisted URL violation detected");
        printf("\nSource IP address: %s", source_ip);
        printf("\nDestination IP address: %s (bbc)", dest_ip);
        printf("\n==============================");
      } else {
        //printf("\n HTTP request is from neither Google nor BBC!");
      }
  }


  /*The newly created thread does the code above. Once it reaches here there is a mutex lock
  to make sure no other created thread (or the origonal thread that writes the report)
  */
  pthread_mutex_lock(&myMutex);
  if(dest_port==80){
    if(match!=NULL){
      googleURLCount++;
    }
    if(match2!=NULL){
      bbcURLCount++;
    }
  }
  if (tcp_header->th_flags & TH_SYN) {
    synPackets++;
    insertAddress(myArray, source_ip);

  }
  if(ethernet_type == ETHERTYPE_ARP){
    arpResponces++;
  }
  pthread_mutex_unlock(&myMutex);



}




