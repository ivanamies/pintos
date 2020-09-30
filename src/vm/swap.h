#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include "devices/block.h"

void swap_init(void);
void swap_deinit(void);

block_sector_t swap_write_page(void * p_, size_t sz);
void swap_get_page(void * p_, size_t sz, block_sector_t sector);

void swap_make_page_available(block_sector_t sector);

#endif // VM_SWAP_H
