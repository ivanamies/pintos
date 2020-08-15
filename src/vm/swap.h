#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include "devices/block.h"

void init_swap_table(void);
void deinit_swap_table(void);

block_sector_t block_write_frame(void * p, size_t sz);
void block_fetch_frame(void * p, size_t sz, block_sector_t sector);

#endif // VM_SWAP_H
