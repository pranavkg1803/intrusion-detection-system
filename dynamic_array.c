#include "dynamic_array.h"
#include <stdlib.h>
#include <string.h>

DynamicArray* createDynamicArray(unsigned int initialCapacity) {
    DynamicArray* array = (DynamicArray*)malloc(sizeof(DynamicArray));
    array->capacity = initialCapacity;
    array->size = 0;
    array->data = (char**)malloc(sizeof(char*) * initialCapacity);
    return array;
}

int contains(DynamicArray* array, const char* ipAddress) {
    for (unsigned int i = 0; i < array->size; ++i) {
        if (strcmp(array->data[i], ipAddress) == 0) {
            return 1; // Address exists in the array
        }
    }
    return 0; // Address doesn't exist in the array
}

void insertAddress(DynamicArray* array, const char* ipAddress) {
    if (!contains(array, ipAddress)) {
        if (array->size == array->capacity) {
            // Perform reallocation if array is full
            array->capacity *= 2;
            array->data = (char**)realloc(array->data, sizeof(char*) * array->capacity);
        }
        array->data[array->size] = strdup(ipAddress);
        array->size++;
    }
}

unsigned int countUniqueAddresses(DynamicArray* array) {
    return array->size;
}

void freeDynamicArray(DynamicArray* array) {
    for (unsigned int i = 0; i < array->size; ++i) {
        free(array->data[i]);
    }
    free(array->data);
    free(array);
}
