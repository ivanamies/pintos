
#include "vm/swap.h"

#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include <kernel/hash.h>
#include <stdio.h>

typedef struct swap_page {
  struct hash_elem hash_elem;
  // block sector sizes are 512
  // each page has 8 sectors
  block_sector_t sector;
} swap_page_t;

typedef struct swap_table {
  struct lock lock;
  
  struct block * block;
  struct hash available_block_pages;
  struct hash unavailable_block_pages;
  
} swap_table_t;

static swap_table_t swap_table;

static unsigned swap_page_hash(const struct hash_elem * p_,
                                     void * aux UNUSED) {
  const swap_page_t * p = hash_entry(p_, swap_page_t, hash_elem);
  unsigned res = hash_int(p->sector);
  return res;
}

static bool swap_page_less(const struct hash_elem * a_,
                           const struct hash_elem * b_,
                           void * aux UNUSED ) {
  const swap_page_t * a = hash_entry(a_, swap_page_t, hash_elem);
  const swap_page_t * b = hash_entry(b_, swap_page_t, hash_elem);
  bool res = a->sector < b->sector;
  return res;
}

void swap_init(void) {
  swap_page_t * page;
  struct hash_elem * hash_out UNUSED;
  size_t num_blocks; // number of blocks in swap
  size_t i;
  size_t num_pages;
  
  lock_init(&swap_table.lock);
  hash_init(&swap_table.available_block_pages,swap_page_hash,swap_page_less,NULL);
  hash_init(&swap_table.unavailable_block_pages,swap_page_hash,swap_page_less,NULL);

  swap_table.block = block_get_role(BLOCK_SWAP);
  num_blocks = block_size(swap_table.block);

  num_pages = num_blocks * BLOCK_SECTOR_SIZE / PGSIZE;
  
  // this SHOULD be done lazily
  // but I am too lazy to do this
  for ( i = 0; i < num_pages; ++i ) {
    page = (swap_page_t *)malloc(sizeof(swap_page_t));
    page->sector = (PGSIZE / BLOCK_SECTOR_SIZE)*i; // each page is 8 blocks in length
    hash_out = hash_insert(&swap_table.available_block_pages,&page->hash_elem);
  }
}

void swap_deinit() {
  // do nothing
  // this is a static
  // we never call destroy on statics
}

block_sector_t swap_write_page(void * p_, size_t sz) {
  uint8_t * p;
  swap_page_t * out;
  struct hash_elem * hash_out;
  block_sector_t sector;
  size_t sectors_read;
  const size_t max_sectors_read = PGSIZE / BLOCK_SECTOR_SIZE; // == 8
  struct hash_iterator i;

  ASSERT(sz == PGSIZE);
  
  ////
  lock_acquire(&swap_table.lock);
  
  ASSERT (!hash_empty(&swap_table.available_block_pages));
  
  // fill hash iterator
  hash_first(&i,&swap_table.available_block_pages);
  hash_next(&i);
  out = hash_entry(hash_cur(&i), swap_page_t, hash_elem);
  sector = out->sector;

  lock_release(&swap_table.lock);
  ////

  // write sz bytes of p to swap
  // this is synchronized for you
  for ( sectors_read = 0; sectors_read < max_sectors_read; ++sectors_read ) {
    p = p_ + sectors_read * BLOCK_SECTOR_SIZE;
    block_write(swap_table.block,sector+sectors_read,p);
  }

  ////
  lock_acquire(&swap_table.lock);
  
  // remove out from available_block_pages and send to unavailable_block_pages
  hash_out = hash_delete(&swap_table.available_block_pages,&out->hash_elem);
  ASSERT(hash_out != NULL);
  hash_out = hash_insert(&swap_table.unavailable_block_pages,&out->hash_elem);
  ASSERT(hash_out == NULL);
  
  lock_release(&swap_table.lock);
  ////
  
  return sector;
}

void swap_get_page(void * p_, size_t sz, block_sector_t sector) {
  ASSERT(sz == PGSIZE);

  uint8_t * p;
  struct hash_elem * hash_out;
  swap_page_t key;
  /* swap_page_t * out; */
  size_t sectors_read;
  const size_t max_sectors_read = PGSIZE / BLOCK_SECTOR_SIZE;
  
  key.sector = sector;  
  
  for ( sectors_read = 0; sectors_read < max_sectors_read; ++sectors_read ) {
    p = p_ + sectors_read * BLOCK_SECTOR_SIZE;
    block_write(swap_table.block, sector + sectors_read, p);
  }
  
  lock_acquire(&swap_table.lock);
  // remove from unavailable pages, add back to available pages
  hash_out = hash_delete(&swap_table.unavailable_block_pages,&key.hash_elem);
  ASSERT(hash_out != NULL);
  hash_out = hash_insert(&swap_table.available_block_pages,&key.hash_elem);
  ASSERT(hash_out == NULL);
  
}

