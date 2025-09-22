#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H


#include "dynamic_array.h"
#include "queue.h"
#include <pthread.h>
void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

extern int terminateProgram;
extern int synPackets; //extern allows the other files in the package to access
extern int arpResponces;


extern DynamicArray* myArray;
extern struct queue* work_queue;
extern int googleURLCount;
extern int bbcURLCount;
extern pthread_mutex_t queue_mutex;
extern pthread_mutex_t myMutex;
extern pthread_cond_t myCond;

#endif
