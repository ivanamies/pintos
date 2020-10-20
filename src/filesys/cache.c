#include "cache.h"

#include <stdio.h>
#include <string.h>
#include <kernel/hash.h>
#include <kernel/bitmap.h>

#include "threads/thread.h"
#include "threads/rw_lock.h"

#define MAX_CACHE_ENTRIES 64

typedef struct cache_entry {

  struct hash_elem hash_elem;
  
  bool dirty;
  bool accessed;
  block_sector_t sector; // 0 if invalid
  
  rw_lock_t rw_lock;
  
  size_t idx; // where in cache.data this points. probably extraneous.
  
} cache_entry_t;

typedef struct cache {
  
  struct block * block;
  
  struct lock cache_entries_map_lock;
  struct hash cache_entries_map;
  cache_entry_t cache_entries[MAX_CACHE_ENTRIES];
  uint8_t cache_data[MAX_CACHE_ENTRIES * BLOCK_SECTOR_SIZE];
  
  // clock hand
  struct lock clock_hand_lock;
  size_t clock_hand;
  
} cache_t;

static cache_t cache;

static unsigned cache_hash_func(const struct hash_elem * e,
                                void * aux UNUSED) {
  cache_entry_t * cache_entry = hash_entry(e,cache_entry_t,hash_elem);
  return hash_int(cache_entry->sector);
}

static bool cache_less_func(const struct hash_elem * a,
                            const struct hash_elem * b,
                            void * aux UNUSED) {
  cache_entry_t * cache_entry1 = hash_entry(a,cache_entry_t,hash_elem);
  cache_entry_t * cache_entry2 = hash_entry(b,cache_entry_t,hash_elem);
  return cache_entry1->sector < cache_entry2->sector;
}

static size_t get_clock_hand(void) {
  lock_acquire(&cache.clock_hand_lock);
  int clock_hand = cache.clock_hand;
  ++cache.clock_hand;
  // static_assert(__builtin_popcount(MAX_CACHE_ENTRIES)==1); // should be a power of 2.
  cache.clock_hand &= (MAX_CACHE_ENTRIES-1); // modulo 64
  lock_release(&cache.clock_hand_lock);
  return clock_hand;
}

static int get_entry_to_evict(void) {
   int clock_hand;
   bool accessed;
   
   // hilariously races
   // the access bit does nothing
   // it doesn't even hurt the big-O complexity of the algorithm
   
   while ( true ) {
     clock_hand = get_clock_hand();
     accessed = cache.cache_entries[clock_hand].accessed;
     if ( accessed ) {
       cache.cache_entries[clock_hand].accessed = false;
     }
     else {
       return clock_hand;
     }
   }
   ASSERT(false);
   return -1; // submit your findings for a field medal
}

static void cache_write_back(void * aux UNUSED) {
  size_t i = 0;
  struct rw_lock * rw_lock;
  block_sector_t sector;
  
  while ( true ) {
    // sleep until the scheduler wakes us up again
    // when we wake up depends on the scheduler
    thread_hack_sleep();
    
    // write all sectors to cache
    for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
      rw_lock = &cache.cache_entries[i].rw_lock;
      rw_lock_read_acquire(rw_lock);
      sector = cache.cache_entries[i].sector;
      if ( sector != 0 && cache.cache_entries[i].dirty ) { // if its not valid, write it anyways
        // writes inode_disk inside cache_entry[i] to designated filesys sector
        block_write(cache.block,sector,&cache.cache_data[i]);
        cache.cache_entries[i].dirty = false;
      }
      rw_lock_read_release(rw_lock);
    }
  }
}

static void cache_write_back_init(void) {
  tid_t tid = thread_create("cache_write_back",PRI_DEFAULT,cache_write_back,NULL);
  ASSERT(tid != TID_ERROR);
}

void cache_init() {
  memset(&cache,0,sizeof(cache));
  cache.block = block_get_role(BLOCK_FILESYS);
  lock_init(&cache.cache_entries_map_lock);
  hash_init(&cache.cache_entries_map,cache_hash_func,cache_less_func,NULL);
  
  // init clock hand fields
  lock_init(&cache.clock_hand_lock);
  cache.clock_hand = 0;

  // init cache entry fields
  size_t i = 0;
  for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
    rw_lock_init(&cache.cache_entries[i].rw_lock);
    cache.cache_entries[i].idx = i;
  }
  
  cache_write_back_init();
}

static void read_ahead(block_sector_t target) {
  uint8_t random_buffer[BLOCK_SECTOR_SIZE]; // marked volatile. code MUST access this.
  cache_block_read(&random_buffer,target);
}

static void evict_cache_entry(size_t cache_entry_idx) {
  cache_entry_t * cache_entry = &cache.cache_entries[cache_entry_idx];
  // ASSERT cache entry idx's write lock is held by this thread
  
  // write cache entry to disk
  block_write(cache.block,cache_entry->sector,&cache.cache_data[cache_entry_idx]);
  // clear cache fields
  cache_entry->dirty = false;
  cache_entry->accessed = false;
  cache_entry->sector = 0;
  // clear cache data
  memset(&cache.cache_data,0,BLOCK_SECTOR_SIZE);
}

// 0 for read
// 1 for write
static void cache_block_action(void * buffer, block_sector_t target, int write) {
  struct hash_elem * hash_elem;
  // marked volatile for usage with double-checked locking
  cache_entry_t * cache_entry;
  // rw_lock_t * rw_lock;
  cache_entry_t cache_entry_key;
  cache_entry_key.sector = target;
  size_t to_evict;
  void * src;
  void * dst;
  
 cache_block_action_try_again:
  // acquire lock around hash table
  // lock_acquire(&cache.cache_entries_map_lock);
  hash_elem = hash_find(&cache.cache_entries_map,&cache_entry_key.hash_elem);
  // lock_release(&cache.cache_entries_map_lock);
  
  // we might have found the entry we're looking for
  if ( hash_elem ) {
    cache_entry = hash_entry(hash_elem,cache_entry_t,hash_elem);
    // rw_lock_read_acquire(&cache_entry->rw_lock);
    // we found the entry we're looking for
    if ( ((volatile block_sector_t)cache_entry->sector) == target ) {
      cache_entry->accessed = true;
      if ( write ) {
        src = buffer;
        dst = &cache.cache_data[cache_entry->idx];
      }
      else {
        src = &cache.cache_data[cache_entry->idx];
        dst = buffer;
      }
      memcpy(dst,src,BLOCK_SECTOR_SIZE);
      // rw_lock_read_release(&cache_entry->rw_lock);
    }
    else {
      // rw_lock_read_release(&cache_entry->rw_lock);
      // somehow try again ??
      goto cache_block_action_try_again; // ??
    }
  }
  else {
    // evict some cache entry
    to_evict = get_entry_to_evict();
    cache_entry = &cache.cache_entries[to_evict];
    
    // rw_lock = &cache_entry->rw_lock;
    // rw_lock_write_acquire(rw_lock);
    evict_cache_entry(to_evict);
    // fill in the entry
    cache_entry->accessed = true;
    cache_entry->sector = target;
    if ( write ) {
      cache_entry->dirty = true;
      memcpy(&cache.cache_data[to_evict],buffer,BLOCK_SECTOR_SIZE);
      // rw_lock_write_release(rw_lock);
    }
    else {
      cache_entry->dirty = false;
      // copy filesys block into evicted cache entry
      block_read(cache.block,target,&cache.cache_data[to_evict]);
      memcpy(buffer,&cache.cache_data[to_evict],BLOCK_SECTOR_SIZE);
      // rw_lock_write_release(rw_lock);
      read_ahead(target+1);
    }
  }
}

void cache_block_read(void * buffer, block_sector_t target) {
  cache_block_action(buffer,target,0 /*read*/);
}

void cache_block_write(void * buffer, block_sector_t target) {
  cache_block_action(buffer,target,1 /*write*/);
}
