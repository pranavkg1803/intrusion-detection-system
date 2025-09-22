
#include "sniff.h"
#include "dynamic_array.h"
#include "queue.h"
#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
//this includes the definitions of eth_net.
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "dispatch.h"

#include <signal.h>
#include <unistd.h>
#include <string.h> 

#define NUMTHREADS 10

pthread_t tid[NUMTHREADS];
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t myCond = PTHREAD_COND_INITIALIZER;
struct queue* work_queue;

int terminateProgram = 0;
int synPackets = 0;
int arpResponces = 0;
int googleURLCount = 0;
int bbcURLCount = 0;
DynamicArray* myArray; //this array is essentially a set as it only adds new values


struct myStructure {
  int intValue;
  pcap_t *pcap_handleValue;
  // Add more members as needed
};

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pktheader, const unsigned char *packet){ //packet is the actual data itself
  //user data is a pointer that points to the adress of verbose
  //pktheader contains data about the packet
  
  
  struct myStructure *userdataStructure = (struct myStructure *)user_data;
  int verbose = userdataStructure->intValue; //to use -> , userdataStructure needed to be a pointer to that thing
  pcap_t *pcap_handle = userdataStructure->pcap_handleValue;
  int length = pktheader-> len;

  if (terminateProgram) {
        // Perform necessary cleanup or save state before exiting the loop  
        //pcap_breakloop(pcap_handle); // Break the pcap_loop
        exit(EXIT_SUCCESS);
  }
  if (packet == NULL) {
    // pcap_next can return null if no packet is seen within a timeout
    if (verbose) { //only print stuff if we have been asked to print stuff (verbose set to a positive number)
      printf("No packet received. %s\n", pcap_geterr(pcap_handle));
    }
  } else {
    // If verbose is set to 1, dump raw packet to terminal
    if (verbose) {
      dump(packet, length);//we pass the length of the packet as its captured
    }
    // Dispatch packet for processing, (allocated to a thread at which it will be sent to analysed)
    dispatch((struct pcap_pkthdr *)pktheader, packet, verbose); //we send the header and the packet
    //packet has the ethernet header, tcp header, ip header
  }
}

void signalHandler(int sig){ //However this overrides the stopping of the program
  //We need to use signal safe functions within this, like write to sndout
  char message2[200];
  char messageARP[200];
  char messageURL[200];

  //mutex lock on the adress of the mutex
  pthread_mutex_lock(&myMutex);
  const char message[] = "\nReceived SIGINT (Ctrl+C pressed).\n\nIntrusion Detection Report:";
  write(1, message, sizeof(message) - 1);
  snprintf(message2, sizeof(message2), "\n%d SYN packets detected from %d different Ips ", synPackets, countUniqueAddresses(myArray));
  //snprintf(message2, sizeof(message2), "\nWe Caught %d SYN packets from %d unique IP adresses.\n", synPackets, countUniqueStrings(uniqueIPs));
  write(1, message2, strlen(message2));

  snprintf(messageARP, sizeof(messageARP), "\n%d ARP Responces (cache poisoning)", arpResponces);
  write(1, messageARP, strlen(messageARP));
  
  snprintf(messageURL, sizeof(messageURL), "\n%d URL Blacklist violations (%d google and %d bbc)\n", googleURLCount+bbcURLCount, googleURLCount, bbcURLCount);
  write(1, messageURL, strlen(messageURL));
  pthread_mutex_unlock(&myMutex);
  terminateProgram = 1;
  exit(EXIT_SUCCESS); //as this signal handler overrides normal SIGINT, we need to mannually kill the program.
}

void sniff(char *interface, int verbose) {
  
  signal(SIGINT, signalHandler);
  char errbuf[PCAP_ERRBUF_SIZE];

  myArray = createDynamicArray(10);
  work_queue=create_queue();
  int i;
  for(i=0; i<NUMTHREADS;i++){
    pthread_create(&tid[i], NULL, threadFunction, NULL);
  }

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }


    struct myStructure userdata;
    userdata.intValue = verbose;
    userdata.pcap_handleValue = pcap_handle; //this is a pointer to the pcap_handle
    int num_packets = -1;
    unsigned char *user_data = (unsigned char *)&userdata;
    //user data is a u_char pointer which points to the adress of verbose

    if(pcap_loop(pcap_handle, num_packets, packet_handler, user_data)<0){ //store the meta data of the next packet at adress for header, from the network
        if(verbose){
            printf("failure for one of the packets we are handling %s\n", pcap_geterr(pcap_handle));
        }
    }
  

  
}

// Utility/Debugging method for dumping raw packet data
//prints the packet data
/*
So the packet data has the data, so the ethernet header, tcp header and ip header

struct ether_header
{
  uint8_t ether_dhost[6];
  uint8_t ether_shost[6];
  uint16_t ether_type;
} 
*/
void dump(const unsigned char *data, int length) { //data is the packet
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  //ether_header is the struct we store the packet header data in
  struct ether_header *eth_header = (struct ether_header *) data;
  /* As the ethernet data is as the start of the packet we are able to
  extract this into the ether_header struct easily.*/
  //we set a new struct pointer to point to the same as the packet data is pointing to.
  //As struct has same fields, by pointing it to same data as the packet data we have extracted the data.


  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\n\n === Ethernet %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]); //we get source info from packet
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]); //we get destination info from packet
    if (i < 5) {
      printf(":");
    }
  }
  unsigned short ethernet_type = ntohs(eth_header->ether_type);
  printf("\nType: %hu\n", ethernet_type);
  if(ethernet_type == ETHERTYPE_ARP){
    printf("\n Ether Type is ARP\n");
  }

  printf("\n\n === IP %ld HEADER ===", pcount);
  const unsigned char *packetcurrent = data + ETH_HLEN;
  struct iphdr *ip_header = (struct iphdr *) packetcurrent;
  //source ip is a 32 bit value so needs to be converted into a string
  char source_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
  //function takes adress of source adress and puts it in a readable char
  printf("\nSource IP address: %s\n", source_ip);
  
  printf("\n\n === TCP %ld HEADER ===", pcount);
  int IP_HLEN = (ip_header->ihl) * 4;
  packetcurrent += IP_HLEN;  //* by 4 to translate from the length in words to bytes
  struct tcphdr *tcp_header = (struct tcphdr *) packetcurrent;
  printf("\nSyn bit: ");
  unsigned short syn_bit = ntohs(tcp_header->syn);
  printf("%02x", syn_bit);
  
  int TCP_HLEN = tcp_header->th_off *4; //th_off is the tcp hdr offset which is the size of the tcp header

  unsigned short tcp_flags = ntohs(tcp_header->th_flags);
  if (tcp_flags & TH_SYN) {
    printf("\nSyn flag is set, this is a Syn packet\n");
  } else {
    printf("\nSyn flag is NOT set, this is NOT a Syn packet\n");
  }
  printf("\nDestination Port: ");
  unsigned short dest_port = ntohs(tcp_header->th_dport);
  printf("%02x", tcp_header->th_dport);


  //Packet data might be a bit wrong :( as HLEN values may be a bit wrong.
  //may need to go back to dumping data after ether header
  printf("\n === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN - IP_HLEN - TCP_HLEN; //amount of bytes left in the body. This is total length minus the length of the headers.
  /*ETH_HLEN is pre defined from the packet library representing the size of the header  */
  const unsigned char *payload = data + ETH_HLEN + IP_HLEN + TCP_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time

  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
