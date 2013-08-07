#ifndef HASH_H
#define HASH_H

#define DBUCKET_SIZE     3967 // Carol that is primes


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t hash(unsigned char *str);

#endif

