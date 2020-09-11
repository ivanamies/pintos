
#include "vm/swap.h"

#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include <kernel/hash.h>
#include <stdio.h>

typedef struct swap_page {
  struct list_elem list_elem;
  // block sector sizes are 512
  // each page has 8 sectors
  block_sector_t sector;
} swap_page_t;

typedef struct swap_table {
  struct lock lock;
  
  struct block * block;
  struct list available_block_pages;
  struct list unavailable_block_pages;
  
} swap_table_t;

static swap_table_t swap_table;

void swap_init(void) {
  swap_page_t * page;
  struct hash_elem * hash_out UNUSED;
  size_t num_blocks; // number of blocks in swap
  size_t i;
  size_t num_pages;
  
  lock_init(&swap_table.lock);
  list_init(&swap_table.available_block_pages);
  list_init(&swap_table.unavailable_block_pages);

  swap_table.block = block_get_role(BLOCK_SWAP);
  num_blocks = block_size(swap_table.block);

  num_pages = num_blocks * BLOCK_SECTOR_SIZE / PGSIZE;
  
  // this SHOULD be done lazily
  // but I am too lazy to do this
  for ( i = 0; i < num_pages; ++i ) {
    page = (swap_page_t *)malloc(sizeof(swap_page_t));
    page->sector = (PGSIZE / BLOCK_SECTOR_SIZE)*i; // each page is 8 blocks in length
    list_push_back(&swap_table.available_block_pages,&page->list_elem);
  }
}

void swap_deinit() {
  // do nothing
  // this is a static
  // we never call destroy on statics
}

// writes your page to swap
block_sector_t swap_write_page(void * p_, size_t sz) {
  uint8_t * p;
  swap_page_t * out;
  struct list_elem * list_out;
  block_sector_t sector;
  size_t sectors_read;
  const size_t max_sectors_read = PGSIZE / BLOCK_SECTOR_SIZE; // == 8

  ASSERT(sz == PGSIZE);
  
  ////
  lock_acquire(&swap_table.lock);
  
  ASSERT (!list_empty(&swap_table.available_block_pages));
  
  // fill hash iterator
  list_out = list_pop_front(&swap_table.available_block_pages);
  ASSERT(list_out != NULL);
  out = list_entry(list_out, swap_page_t, list_elem);
  sector = out->sector;

  lock_release(&swap_table.lock);
  ////

  // write sz bytes of p to swap
  // this is synchronized for you
  for ( sectors_read = 0; sectors_read < max_sectors_read; ++sectors_read ) {
    p = p_ + sectors_read * BLOCK_SECTOR_SIZE;
    printf("sector %zu sectors_read %zu\n",sector,sectors_read);
    block_write(swap_table.block,sector+sectors_read,p);
  }

  ////
  lock_acquire(&swap_table.lock);
  
  // remove out from available_block_pages and send to unavailable_block_pages
  list_out = list_push_back(&swap_table.unavailable_block_pages,&out->list_elem);
  
  lock_release(&swap_table.lock);
  ////
  
  return sector;
}

// gets your page from swap
void swap_get_page(void * p_, size_t sz, block_sector_t sector) {
  ASSERT(sz == PGSIZE);

  uint8_t * p;
  struct list_elem * list_out;
  swap_page_t key;
  /* swap_page_t * out; */
  size_t sectors_read;
  const size_t max_sectors_read = PGSIZE / BLOCK_SECTOR_SIZE;
  
  key.sector = sector;  
  
  for ( sectors_read = 0; sectors_read < max_sectors_read; ++sectors_read ) {
    p = p_ + sectors_read * BLOCK_SECTOR_SIZE;
    block_read(swap_table.block, sector + sectors_read, p);
  }
  
  lock_acquire(&swap_table.lock);
  // remove from unavailable pages, add back to available pages
  list_out = list_
  hash_out = hash_delete(&swap_table.unavailable_block_pages,&key.hash_elem);
  ASSERT(hash_out != NULL);
  hash_out = hash_insert(&swap_table.available_block_pages,&key.hash_elem);
  ASSERT(hash_out == NULL);
  lock_release(&swap_table.lock);
  
}

