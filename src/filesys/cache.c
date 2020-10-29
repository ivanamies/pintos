#include "cache.h"

#include <stdio.h>
#include <string.h>
#include <kernel/hash.h>
#include <kernel/bitmap.h>

#include "threads/thread.h"
#include "threads/rw_lock.h"
#include "threads/malloc.h"

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

typedef struct read_ahead_request {
  struct list_elem lele;
  int sector;

  // signals that request was completed
  int signal; // 0 if unfulfilled, 1 if fulfilled
  struct lock lock;
  struct condition cond;
} read_ahead_request_t;

typedef struct read_ahead_helpers {
  struct list list;
  struct lock lock;
  struct condition cond;
} read_ahead_helpers_t;

typedef struct cache {
  
  struct block * block;
  
  struct lock cache_entries_map_lock;
  struct hash cache_entries_map;
  cache_entry_t cache_entries[MAX_CACHE_ENTRIES];
  cache_data_t cache_data[MAX_CACHE_ENTRIES];
  
  // clock hand
  struct lock clock_hand_lock;
  size_t clock_hand;

  read_ahead_helpers_t read_ahead_helpers;
  // and this is where I would put my write_behind_helpers... IF I WROTE IT!!
  
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

static void cache_block_action(block_sector_t target, void * buffer, size_t buffer_size, int write);

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
   cache_entry_t * cache_entry;
   rw_lock_t * rw_lock;
   const int rw_lock_write = 1;
   
   while ( true ) {
     clock_hand = get_clock_hand();
     cache_entry = &cache.cache_entries[clock_hand];
     rw_lock = &cache_entry->rw_lock;
     // printf("get entry to evict try %p acquire %d\n",rw_lock,rw_lock_write);
     rw_lock_acquire_action(rw_lock,rw_lock_write);
     // printf("get entry to evict success %p acquire %d\n",rw_lock,rw_lock_write);
     
     if ( cache.cache_entries[clock_hand].accessed ) {
       cache.cache_entries[clock_hand].accessed = 0;
       // printf("get entry to evict try %p release %d\n",rw_lock,rw_lock_write);       
       rw_lock_release_action(rw_lock,rw_lock_write);
       // printf("get entry to evict success %p release %d\n",rw_lock,rw_lock_write);
     }
     else {
       // rw_lock is retained
       return clock_hand;
     }
   }
   ASSERT(false);
   return -1; // submit your findings for a field medal
}

static void cache_write_back(void * aux UNUSED) {
  size_t i = 0;
  struct rw_lock * rw_lock;
  int sector;
  const int rw_lock_write = 0;
  
  while ( true ) {
    // sleep until the scheduler wakes us up again
    // when we wake up depends on the scheduler
    //...
    // wait, this is stupid it should be based on number of cache hits or disk requests.
    thread_sleep_hack();

    // write all sectors to cache
    for ( i = 0; i < MAX_CACHE_ENTRIES; ++i ) {
      rw_lock = &cache.cache_entries[i].rw_lock;
      // printf("cache_write_back try acqire rw_lock %p\n",rw_lock);
      rw_lock_acquire_action(rw_lock,rw_lock_write);
      // printf("cache_write_back success acqire rw_lock %p\n",rw_lock);
      sector = cache.cache_entries[i].sector;
      if ( sector != -1 && cache.cache_entries[i].dirty ) { // skip if unwritten or clean
        // writes inode_disk inside cache_entry[i] to designated filesys sector
        block_write(cache.block,sector,&cache.cache_data[i]);
        cache.cache_entries[i].dirty = 0;
      }
      // printf("cache_write_back try release rw_lock %p\n",rw_lock);
      rw_lock_release_action(rw_lock,rw_lock_write);
      // printf("cache_write_back success release rw_lock %p\n",rw_lock);
    }
  }
}

static void cache_read_ahead(void * aux UNUSED) {
  uint8_t random_buffer[BLOCK_SECTOR_SIZE];
  int target = -1;
  const int read_action = 0;
  read_ahead_request_t * request = NULL;
  struct list_elem * lele = NULL;
  struct list * list = &cache.read_ahead_helpers.list;
  struct lock * lock = &cache.read_ahead_helpers.lock;
  struct condition * cond = &cache.read_ahead_helpers.cond;
  const size_t buffer_size = BLOCK_SECTOR_SIZE;
  
  while ( true ) {
    // condition block until list is not empty
    lock_acquire(lock);
    while ( list_empty(list) ) {
      // printf("thread %p cond wait cache read ahead\n",thread_current());
      cond_wait(cond,lock);
    }
    // pop a request off the list
    lele = list_pop_front(list);
    lock_release(lock);
    
    // get the target to read ahead
    request = list_entry(lele,read_ahead_request_t,lele);
    target = request->sector;
    free(request);
    
    cache_block_action(target,random_buffer,buffer_size,read_action);
        
    /* // signal the requesting thread to proceed */
    /* lock_acquire(&request->lock); */
    /* request->signal = 1; */
    /* cond_signal(&request->cond,&request->lock); */
    /* lock_release(&request->lock); */
  }
}

static void cache_request_read_ahead(int target) {
  struct list * list = &cache.read_ahead_helpers.list;
  struct lock * lock = &cache.read_ahead_helpers.lock;
  struct condition * cond = &cache.read_ahead_helpers.cond;
  
  read_ahead_request_t * request = (read_ahead_request_t *)malloc(sizeof(read_ahead_request_t));
  request->sector = target;
  /* request->signal = 0; */
  /* lock_init(&request->lock); */
  /* cond_init(&request->cond); */
  
  lock_acquire(lock);
  list_push_back(list,&request->lele);
  cond_signal(cond,lock);
  lock_release(lock);
}

static void cache_write_back_init(void) {
  tid_t tid = thread_create("cache_write_back",PRI_DEFAULT,cache_write_back,NULL);
  ASSERT(tid != TID_ERROR);
}

static void cache_read_ahead_init(void) {
  list_init(&cache.read_ahead_helpers.list);
  lock_init(&cache.read_ahead_helpers.lock);
  cond_init(&cache.read_ahead_helpers.cond);

  tid_t tid = thread_create("cache_read_ahead",PRI_DEFAULT,cache_read_ahead,NULL);
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
  
  cache_read_ahead_init();
}

void cache_init_late() {
  cache_write_back_init();
}

static void clear_cache_entry(size_t cache_entry_idx, int replaced_sector) {
  cache_entry_t * cache_entry = &cache.cache_entries[cache_entry_idx];
  cache_data_t * cache_data = &cache.cache_data[cache_entry_idx];
  // ASSERT cache entry idx's write lock is held by this thread
  
  // cache_entry->sector already has the correct sector
  // however all other things inside cache_entry are from the previous occupant sector    

  // write cache entry to disk
  if ( cache_entry->dirty != 0 ) {
    block_write(cache.block,replaced_sector,cache_data);
  }
  
  // clear cache fields
  cache_entry->dirty = 0;
  cache_entry->accessed = 0;
  
  // clear cache data
  memset(cache_data,0,BLOCK_SECTOR_SIZE);
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

static bool cache_block_replace(int to_replace_idx,
                                int replacing_sector) {
  // rw_lock write already obtained on to_replace
  cache_entry_t * to_replace = &cache.cache_entries[to_replace_idx];
  cache_entry_t cache_entry_key;
  cache_entry_key.sector = replacing_sector;
  struct hash_elem * hash_elem;
  bool success = false;
  
  lock_acquire(&cache.cache_entries_map_lock);
  // recheck that the replacing_sector was not already put back into map
  // printf("thread %p cache block replace try %p acquire\n",thread_current(),&cache.cache_entries_map_lock);
  hash_elem = hash_find(&cache.cache_entries_map,&cache_entry_key.hash_elem);
  // printf("thread %p cache block replace success %p acquire\n",thread_current(),&cache.cache_entries_map_lock);
  // if no, then swap the sector 
  if ( hash_elem == NULL ) {
    if ( to_replace->sector != -1 ) {
      // evict to_replace from the map
      hash_elem = hash_delete(&cache.cache_entries_map,&to_replace->hash_elem);
      ASSERT(hash_elem != NULL);
    }
    
    clear_cache_entry(to_replace_idx,to_replace->sector);
    // change to_replace's sector and put back into map
    to_replace->sector = replacing_sector;

    // don't change anything else. Leave that for the clear function.
    hash_elem = hash_insert(&cache.cache_entries_map,&to_replace->hash_elem);
    ASSERT(hash_elem == NULL);
    success = true;
  }
  // printf("thread %p cache block replace try %p release\n",thread_current(),&cache.cache_entries_map_lock);
  lock_release(&cache.cache_entries_map_lock);
  // printf("thread %p cache block replace success %p release\n",thread_current(),&cache.cache_entries_map_lock);
  return success;
}

// 0 for read
// 1 for write
void cache_block_action(block_sector_t target, void * buffer, size_t buffer_size, int write) {
  
  ASSERT(buffer != NULL);  
  ASSERT(buffer_size <= BLOCK_SECTOR_SIZE);
  ASSERT(write <= 1);
  
  struct hash_elem * hash_elem;
  // marked volatile for usage with double-checked locking
  cache_entry_t * cache_entry;
  cache_data_t * cache_data;
  rw_lock_t * rw_lock;
  size_t to_evict;
  void * src;
  void * dst;
  bool success;
  
 cache_block_action_try_again:
  // acquire lock around hash table
  hash_elem = cache_block_search(target);
  
  // check if we might have found the entry we're looking for
  if ( hash_elem ) {
    cache_entry = hash_entry(hash_elem,cache_entry_t,hash_elem);
    rw_lock = &cache_entry->rw_lock;

    // printf("thread %p cache block action try %p acquire %d\n",thread_current(),rw_lock,write);
    rw_lock_acquire_action(rw_lock,write);
    // printf("thread %p cache block action success %p acquire %d\n",thread_current(),rw_lock,write);
    
    // check if we did find the entry we're looking for
    ASSERT(cache_entry->sector != -1);
    if ( ((volatile block_sector_t)cache_entry->sector) == target ) {
      cache_entry->accessed = 1;
      if ( write ) {
        cache_entry->dirty = 1;
        src = buffer;
        dst = &cache.cache_data[cache_entry->idx];
        memset(dst + buffer_size,0,BLOCK_SECTOR_SIZE-buffer_size); // 0 the end of the cache entry data
      }
      else {
        src = &cache.cache_data[cache_entry->idx];
        dst = buffer;
      }
      memcpy(dst,src,buffer_size);
      // printf("thread %p cache block action try %p release %d\n",thread_current(),rw_lock,write);
      rw_lock_release_action(rw_lock,write);
      // printf("thread %p cache block action success %p release %d\n",thread_current(),rw_lock,write);
    }
    else {
      rw_lock_release_action(rw_lock,write);
      goto cache_block_action_try_again; // evil goto try again ??
    }
  }
  else {
    // evict some cache entry
    to_evict = get_entry_to_evict(); // rw_lock WRITE is already obtained
    cache_entry = &cache.cache_entries[to_evict];
    rw_lock = &cache_entry->rw_lock;
    
    // check that target entry wasn't inserted
    // this will do cache_entry->sector = target;
    success = cache_block_replace(to_evict,target);
    if ( !success ) {
      rw_lock_release_action(rw_lock,1/*always release write lock*/);
      goto cache_block_action_try_again; // evil goto try again ??
    }
    ASSERT(cache_entry->sector == (int)target);
    
    // fill in the entry
    cache_entry->accessed = 1;
    cache_data = &cache.cache_data[cache_entry->idx];
    if ( write ) {
      cache_entry->dirty = 1;
      dst = cache_data;
      src = buffer;
      memset(dst + buffer_size,0,BLOCK_SECTOR_SIZE-buffer_size);
    }
    else {
      // copy filesys block into evicted cache entry
      block_read(cache.block,target,cache_data);
      dst = buffer;
      src = cache_data;
    }
    memcpy(dst,src,buffer_size);
    // printf("thread %p get entry to evict try %p release %d\n",thread_current(),rw_lock,1);       
    rw_lock_release_action(rw_lock,1 /*always release write lock*/);
    // printf("thread %p get entry to evict success %p release %d\n",thread_current(),rw_lock,1);       
  }

}

void cache_block_read(struct block * block, block_sector_t target, void * buffer, size_t size) {
  // printf("thread %p cache block read target %u buffer %p\n",thread_current(),target,buffer);
  /* print_cache(); */
  ASSERT(block == cache.block);
  cache_request_read_ahead(target+1);
  cache_block_action(target,buffer,size,0 /*read*/);
  // block_read(block,target,buffer);
  // cache_request_read_ahead_wait(request);
  
  // cache_read_ahead_async(target+1);
  // debug code
  // block_read(block,target,&random_buffer);
  /* int err = memcmp(buffer,random_buffer,BLOCK_SECTOR_SIZE); */
  /* ASSERT(err == 0); */

  /* size_t res = 0; */
  /* for ( size_t i = 0; i < BLOCK_SECTOR_SIZE; ++i ) { */
  /*   uint8_t * also_buffer = buffer; */
  /*   res += also_buffer[i]; */
  /* } */
  // printf("thread %p cache block read end target %u buffer %p contents %zu\n",thread_current(),target,buffer,res);
}

void cache_block_write(struct block * block, block_sector_t target, void * buffer, size_t size) {
  // printf("thread %p cache block write target %u buffer %p\n",thread_current(),target,buffer);
  /* print_cache(); */
  
  ASSERT(block == cache.block);
  ASSERT(buffer != NULL);
  
  cache_block_action(target,buffer,size,1 /*write*/);

  /* // debug code */
  // block_write(block,target,buffer);

  /* size_t res = 0; */
  /* for ( size_t i = 0; i < BLOCK_SECTOR_SIZE; ++i ) { */
  /*   uint8_t * also_buffer = buffer; */
  /*   res += also_buffer[i]; */
  /* } */
  // printf("thread %p cache block write end target %u buffer %p contents %zu\n",thread_current(),target,buffer,res);
}
