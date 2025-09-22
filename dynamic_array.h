#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H

typedef struct {
    unsigned int capacity;
    unsigned int size;
    char** data; // Array to store IP addresses as strings
} DynamicArray;

DynamicArray* createDynamicArray(unsigned int initialCapacity);
int contains(DynamicArray* array, const char* ipAddress);
void insertAddress(DynamicArray* array, const char* ipAddress);
unsigned int countUniqueAddresses(DynamicArray* array);
void freeDynamicArray(DynamicArray* array);

#endif /* DYNAMIC_ARRAY_H */