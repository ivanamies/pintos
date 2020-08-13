#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <kernel/hash.h>

typedef struct mapid_table {
  struct hash mapids;
} mapid_table_t;

int mmap(int, void *);
void munmap(int);

void destroy_mapid_table(mapid_table_t *);
void init_mapid_table(mapid_table_t *);

#endif /* vm/mmap.h */

