#include "cache.h"

#include <stdio.h>
#include <string.h>
#include <kernel/hash.h>
#include <kernel/bitmap.h>

#include "threads/thread.h"
#include "threads/rw_lock.h"

#define MAX_CACHE_ENTRIES 16

typedef struct cache_data {
  uint8_t data[BLOCK_SECTOR_SIZE];
} cache_data_t;

typedef struct cache_entry {

  struct hash_elem hash_elem;
  
  int dirty;
  int accessed;
  int sector; // 0 if invalid
  
  rw_lock_t rw_lock;
  
  size_t idx; // where in cache.data this points. probably extraneous.
  
} cache_entry_t;

typedef struct cache {
  
  struct block * block;
  
  struct lock cache_entries_map_lock;
  struct hash cache_entries_map;
  cache_entry_t cache_entries[MAX_CACHE_ENTRIES];
  cache_data_t cache_data[MAX_CACHE_ENTRIES];
  
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
       cache.cache_entries[clock_hand].accessed = 0;
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
    thread_sleep_hack();
    
    // write all sectors to cache
    for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
      rw_lock = &cache.cache_entries[i].rw_lock;
      rw_lock_read_acquire(rw_lock);
      sector = cache.cache_entries[i].sector;
      if ( sector != 0 && cache.cache_entries[i].dirty ) { // if its not valid, write it anyways
        // writes inode_disk inside cache_entry[i] to designated filesys sector
        block_write(cache.block,sector,&cache.cache_data[i]);
        cache.cache_entries[i].dirty = 0;
      }
      rw_lock_read_release(rw_lock);
    }
  }
}

static void cache_write_back_init(void) {
  tid_t tid = thread_create("cache_write_back",PRI_DEFAULT,cache_write_back,NULL);
  ASSERT(tid != TID_ERROR);
}

void cache_init_early() {
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
    cache.cache_entries[i].sector = -1;
    cache.cache_entries[i].idx = i;
  }
  
}

void cache_init_late() {
  cache_write_back_init();  
}

static void evict_cache_entry(size_t cache_entry_idx) {
  cache_entry_t * cache_entry = &cache.cache_entries[cache_entry_idx];
  cache_data_t * cache_data = &cache.cache_data[cache_entry_idx];
  struct hash_elem * hash_elem;
  // ASSERT cache entry idx's write lock is held by this thread
  
  if ( cache_entry->sector != -1 ) {
    // write cache entry to disk
    if ( cache_entry->dirty != 0 ) {
      block_write(cache.block,cache_entry->sector,cache_data);
    }
    // remove it from the map
    lock_acquire(&cache.cache_entries_map_lock);
    hash_elem = hash_delete(&cache.cache_entries_map,&cache_entry->hash_elem);
    ASSERT(hash_elem != NULL);
    lock_release(&cache.cache_entries_map_lock);
    
    // clear cache fields
    cache_entry->dirty = 0;
    cache_entry->accessed = 0;
    cache_entry->sector = -1;
    // clear cache data
    memset(cache_data,0,BLOCK_SECTOR_SIZE);
  }
}

static void print_sum(void * buffer) {
  uint8_t * buffer_copy = buffer;
  size_t sum = 0;
  for ( size_t i = 0; i < BLOCK_SECTOR_SIZE; ++i ) {
    sum += buffer_copy[i];
  }
  printf("buffer %p sum %zu\n",buffer,sum);
}

static void print_cache_entry(cache_entry_t * cache_entry) {
  printf("cache entry %p dirty %d accessed %d sector %d idx %zu\n",
         cache_entry,cache_entry->dirty,cache_entry->accessed,cache_entry->sector,cache_entry->idx);
  print_sum(&cache.cache_data[cache_entry->idx]);
}

static void print_cache(void) {
  printf("===start of print cache\n");
  printf("table: \n");
  for (size_t i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
    print_cache_entry(&cache.cache_entries[i]);
  }
  printf("map: \n");
  struct hash_iterator i;

  hash_first (&i, &cache.cache_entries_map);
  while (hash_next(&i)) {
    cache_entry_t * cache_entry = hash_entry(hash_cur(&i), cache_entry_t, hash_elem);
    print_cache_entry(cache_entry);
  }
  printf("===end of print cache\n");
}

static struct hash_elem * cache_block_search(int target) {
  /* printf("===tagiamies cache block search target %d\n",target); */
  ASSERT(target != -1);
  cache_entry_t cache_entry_key;
  struct hash_elem * hash_elem;
  cache_entry_key.sector = target;
  lock_acquire(&cache.cache_entries_map_lock);
  hash_elem = hash_find(&cache.cache_entries_map,&cache_entry_key.hash_elem);
  lock_release(&cache.cache_entries_map_lock);
  return hash_elem;
}

static void rw_lock_acquire_action(rw_lock_t * lock, int write ) {
  if ( write ) {
    rw_lock_write_acquire(lock);
  }
  else {
    rw_lock_read_acquire(lock);
  }
}

static void rw_lock_release_action(rw_lock_t * lock, int write ) {
  if ( write ) {
    rw_lock_write_release(lock);
  }
  else {
    rw_lock_read_release(lock);
  }
}

// 0 for read
// 1 for write
static void cache_block_action(block_sector_t target, void * buffer, int write) {
  
  ASSERT(buffer != NULL);  
  struct hash_elem * hash_elem;
  // marked volatile for usage with double-checked locking
  cache_entry_t * cache_entry;
  cache_data_t * cache_data;
  rw_lock_t * rw_lock;
  size_t to_evict;
  void * src;
  void * dst;
  
 cache_block_action_try_again:
  // acquire lock around hash table
  hash_elem = cache_block_search(target);
  
  // check if we might have found the entry we're looking for
  if ( hash_elem ) {
    cache_entry = hash_entry(hash_elem,cache_entry_t,hash_elem);
    rw_lock = &cache_entry->rw_lock;
    
    rw_lock_acquire_action(rw_lock,write);
    
    // check if we did find the entry we're looking for
    ASSERT(cache_entry->sector != -1);
    if ( ((volatile block_sector_t)cache_entry->sector) == target ) {
      cache_entry->accessed = 1;
      if ( write ) {
        cache_entry->dirty = 1;
        src = buffer;
        dst = &cache.cache_data[cache_entry->idx];
      }
      else {
        src = &cache.cache_data[cache_entry->idx];
        dst = buffer;
      }
      memcpy(dst,src,BLOCK_SECTOR_SIZE);
      rw_lock_release_action(rw_lock,write);
    }
    else {
      rw_lock_release_action(rw_lock,write);
      goto cache_block_action_try_again; // evil goto try again ??
    }
  }
  else {
    // evict some cache entry
    to_evict = get_entry_to_evict();
    cache_entry = &cache.cache_entries[to_evict];
    rw_lock = &cache_entry->rw_lock;
    
    rw_lock_acquire_action(rw_lock,write);
    
    evict_cache_entry(to_evict);
    // fill in the entry
    cache_entry->accessed = 1;
    cache_entry->sector = target;
    cache_data = &cache.cache_data[cache_entry->idx];
    if ( write ) {
      cache_entry->dirty = 1;
      memcpy(cache_data,buffer,BLOCK_SECTOR_SIZE);
    }
    else {
      // copy filesys block into evicted cache entry
      block_read(cache.block,target,cache_data);
      memcpy(buffer,cache_data,BLOCK_SECTOR_SIZE);
    }
    
    lock_acquire(&cache.cache_entries_map_lock);
    hash_elem = hash_insert(&cache.cache_entries_map,&cache_entry->hash_elem);
    ASSERT(hash_elem == NULL);
    lock_release(&cache.cache_entries_map_lock);
    
    rw_lock_release_action(rw_lock,write);
  }
  
}

void cache_block_read(struct block * block, block_sector_t target, void * buffer) {
  // printf("===tagiamies cache block read target %u buffer %p\n",target,buffer);
  /* print_cache(); */
  
  ASSERT(block == cache.block);
  cache_block_action(target,buffer,0 /*read*/);
  // block_read(block,target,buffer);
  
  // read ahead target + 1
  uint8_t random_buffer[BLOCK_SECTOR_SIZE];
  cache_block_action(target+1,&random_buffer,0 /*read*/);
  
  // debug code
  // block_read(block,target,&random_buffer);
  /* int err = memcmp(buffer,random_buffer,BLOCK_SECTOR_SIZE); */
  /* ASSERT(err == 0); */

  /* size_t res = 0; */
  /* for ( size_t i = 0; i < BLOCK_SECTOR_SIZE; ++i ) { */
  /*   uint8_t * also_buffer = buffer; */
  /*   res += also_buffer[i]; */
  /* } */
  /* printf("===tagiamies cache block read end target %u buffer %p contents %zu\n",target,buffer,res); */
}

void cache_block_write(struct block * block, block_sector_t target, const void * buffer) {
  // printf("===tagiamies cache block write target %u buffer %p\n",target,buffer);
  /* print_cache(); */
  
  ASSERT(block == cache.block);
  ASSERT(buffer != NULL);
  // copy over buffer to tmp buffer to suppress warnings
  // this is not a real operating system
  // this shit is why templates were invented
  uint8_t tmp_buffer[BLOCK_SECTOR_SIZE];
  memcpy(&tmp_buffer,buffer,BLOCK_SECTOR_SIZE);
  
  cache_block_action(target,&tmp_buffer,1 /*write*/);

  /* // debug code */
  // block_write(block,target,buffer);
  // cache_block_read(block,target,&tmp_buffer);
  /* int err = memcmp(buffer,tmp_buffer,BLOCK_SECTOR_SIZE); */
  /* ASSERT(err == 0);   */

  /* size_t res = 0; */
  /* for ( size_t i = 0; i < BLOCK_SECTOR_SIZE; ++i ) { */
  /*   uint8_t * also_buffer = buffer; */
  /*   res += also_buffer[i]; */
  /* } */
  /* printf("===tagiamies cache block write end target %u buffer %p contents %zu\n",target,buffer,res); */

}
