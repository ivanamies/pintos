#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

struct block;

void cache_init_early(void);
void cache_init_late(void);
void cache_block_read(struct block * block, block_sector_t target, void * buffer);
void cache_block_write(struct block * block, block_sector_t target, const void * buffer);

#endif // FILESYS_CACHE_H
