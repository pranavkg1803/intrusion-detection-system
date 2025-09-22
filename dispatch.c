#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include "analysis.h"
#include "sniff.h"
//dispatch does not modify the packet, only read it so we can cast out const



//these threads are waiting for work indefinitely.
void* threadFunction(void* arg){
  
  while(1){
    pthread_mutex_lock(&queue_mutex);
		while(isempty(work_queue)){  //threads wait while it is empty
			pthread_cond_wait(&myCond,&queue_mutex);
		}
    struct packetStruct* sptr = (struct packetStruct*) work_queue->head->item; //sptr is a stuct ptr so points to the struct
		dequeue(work_queue);
		pthread_mutex_unlock(&queue_mutex);
    analyse(sptr->theHeader, sptr->thePacket, sptr->theVerbose);

  }
  
  return NULL;
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  
  struct packetStruct* threadArg = malloc(sizeof(struct packetStruct));
  //needed to dynamically allocate the threadArg struct as we pass pointers to it within the 
  //analyze function. So if we statically allocated it, then it would be automatically freed, 
  //while we still need the strcuture.
  threadArg->theHeader = header;
  threadArg->thePacket = packet;
  threadArg->theVerbose = verbose;
  
  pthread_mutex_lock(&queue_mutex);
  enqueue(work_queue, threadArg);
  pthread_mutex_unlock(&queue_mutex); //mutex unlock needs to be before condition. Proff got wrong
  //pthread_cond_broadcast(&myCond);
  pthread_cond_signal(&myCond);
	
}















