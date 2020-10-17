#include "cache.h"

#include <stdio.h>
#include <string.h>

#include "devices/block.h"

#include "threads/rw_lock.h"

#define MAX_CACHE_ENTRIES 64

typedef struct cache_entry {
  
  bool dirty;
  bool accessed;
  
  struct rw_lock rw_lock;

  block_sector_t sector;
  uint8_t data[BLOCK_SECTOR_SIZE]; // the inode_disks size, guaranteed to be BLOCK_SECTOR_SIZE
  
} cache_entry_t;

typedef struct cache {

  struct block * block;
  block_sector_t disk_start;
  cache_entry_t cache_entries[MAX_CACHE_ENTRIES];
  
  // clock hand
  size_t clock_hand;
  struct lock clock_hand_lock;
  
} cache_t;

static cache_t cache;

/* static void get_clock_hand() { */
/*   lock_acquire(&cache.clock_hand_lock); */
/*   int clock_hand = cache.clock_hand; */
/*   ++cache.clock_hand; */
/*   cache.clock_hand &= 0x3F; // modulo 64 */
/*   lock_release(&cache.clock_hand_lock); */
/*   return clock_hand; */
/* } */

/* static int get_entry_to_evict() { */
/*    int clock_hand; */
/*    volatile bool accessed; */
/*    rw_lock_t * rw_lock = NULL; */
   
/*    while ( true ) { */
/*      clock_hand = get_clock_hand(); */
/*      rw_lock = &cache.cache_entries[clock_hand].rw_lock; */
/*      while ( rw_lock_try_write_lock(rw_lock) ) { */
/*        thread_yield(); */
/*      } */
/*      accessed = cache.cache_entries[clock_hand].accessed; */
/*      if ( accessed ) { */
/*        cache.cache_entries[clock_hand].accessed = false; */
/*      } */
/*      else { */
/*        return clock_hand; */
/*      } */
/*    } */
/*    ASSERT(false); */
/*    return -1; // submit your findings for a field medal */
/* } */

/* // this HAS to be done as a hash table */
/* // it's possible to reject block 1 then have block 1 be filled with your desired sector */
/* // as you're on block 2 */
/* static int find_entry(block_sector_t sector) { */
/*   size_t i = 0; */
/*   rw_lock_t * rw_lock = NULL; */
/*   bool found = false; */
/*   struct inode_disk * inode_disk; */
/*   for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) { */
/*     rw_lock = &cache.cache_entries[i].rw_lock; */
/*     rw_lock_read_acquire(rw_lock); */
/*     found = sector == cache.cache_entries[i].sector; */
/*     rw_lock_read_release(rw_lock); */
/*     if ( found ) { */
/*       return true; */
/*     } */
/*   } */
/*   return false; */
/* } */

/* static void cache_write_back() { */
/*   size_t i = 0; */
/*   struct rw_lock * rw_lock; */
/*   block_sector_t disk_start = cache.disk_start; */
  
/*   while ( true ) { */
/*     // sleep until the scheduler wakes us up again */
/*     // when we wake up depends on the scheduler */
/*     thread_hack_sleep(); */
    
/*     // write all sectors to cache */
/*     for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) { */
/*       rw_lock = &cache.cache_entries[i].rw_lock; */
/*       rw_lock_read_acquire(rw_lock); */
/*       if ( cache.cache_entries[i].valid && cache.cache_entries[i].dirty ) { */
/*         // writes inode_disk inside cache_entry[i] to designated filesys sector */
/*         block_write(cache.block,disk_start+i,&cache.cache_entries[i].data); */
/*         cache.cache_entries[i].dirty = false; */
/*       } */
/*       rw_lock_read_release(rw_lock); */
/*     } */
/*   } */
/* } */

static void cache_write_back_init() {
/*   tid_t tid = thread_create("cache_write_back",PRI_DEFAULT,cache_write_back,NULL); */
/*   ASSERT(tid != TID_ERROR); */
}

// unfortunately it's all wrong
// you MUST use a hash table with a global lock or it will race
// I don't see a way around it with just an array.
// Like you'd need a global lock around the array and it'd be too slow
void cache_init() {
  memset(&cache,0,sizeof(cache));
  cache.block = block_get_role(BLOCK_FILESYS);
  cache.disk_start = 75; // ??? not sure.
  
  size_t i = 0;
  for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
    rw_lock_init(&cache.cache_entries[i].rw_lock);
  }

  cache_write_back_init();
}

