#include "vm/mmap.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

#include "userprog/exception.h"

#include "vm/page.h"
#include "vm/frame.h"

#include <string.h>
#include <stdio.h>

// mapid for memory mapped files
// look its just an std::unordered_set man
typedef struct mapid_with_hook {
  int mapid;
  int fd;
  int sz;
  void * addr;
  struct hash_elem hash_elem;
} mapid_w_hook_t;

static unsigned mapid_hash(const struct hash_elem * p_, void * aux UNUSED) {
  const mapid_w_hook_t * p = hash_entry(p_, mapid_w_hook_t, hash_elem);
  unsigned res = hash_int(p->mapid);
  return res;
}

static bool mapid_less(const struct hash_elem * a_,
                       const struct hash_elem * b_,
                       void * aux UNUSED) {
  const mapid_w_hook_t * a = hash_entry(a_, mapid_w_hook_t, hash_elem);
  const mapid_w_hook_t * b = hash_entry(b_, mapid_w_hook_t, hash_elem);
  bool res = a->mapid > b->mapid; // we want the first elt to be the latest thing we added in
  return res;
}

static void mapid_destroy(struct hash_elem * p_, void * aux UNUSED ) {
  mapid_w_hook_t * p = hash_entry(p_, mapid_w_hook_t, hash_elem);
  free(p);
}

void init_mapid_table(mapid_table_t * mapid_table) {
  hash_init(&mapid_table->mapids, mapid_hash, mapid_less, NULL);
}

void destroy_mapid_table(mapid_table_t * mapid_table) {
  hash_destroy(&mapid_table->mapids, mapid_destroy);
}

static int alloc_mapid(int fd, size_t sz, void * p) {
  mapid_table_t * mapid_table = &thread_current()->mapid_table; // mapid's need only be unique to the process
  
  int res = -1;
  if ( hash_empty(&mapid_table->mapids) ) {
    res = 1;
  }
  else {
    struct hash_iterator i;
    hash_first(&i,&mapid_table->mapids);
    hash_next(&i);
    mapid_w_hook_t * last_mapid = hash_entry(hash_cur(&i), mapid_w_hook_t, hash_elem);
    res = last_mapid->mapid + 1;
  }
  
  mapid_w_hook_t * mapid_w_hook = (mapid_w_hook_t *)malloc(sizeof(mapid_w_hook_t));
  memset(mapid_w_hook,0,sizeof(mapid_w_hook_t));
  
  mapid_w_hook->mapid = res;
  mapid_w_hook->fd = fd;
  mapid_w_hook->sz = sz;
  mapid_w_hook->addr = p;
  
  struct hash_elem * hash_elem = hash_insert(&mapid_table->mapids,&mapid_w_hook->hash_elem);
  ASSERT(hash_elem == NULL);
  
  return res;
}

// fd is the file descriptor
// sz is the size in bytes of the file descriptor
// ofs is the current offset of the file descriptor
// note that there is no inter-process race condition, fd are unique to the process
// doesn't guard against intra-process race conditions but those don't exist here.
int mmap(int fd, int sz, int ofs, void * addr_) {
 /*  ASSERT(sz != -1); */
 /*  ASSERT(fd != 0 && fd != 1 && fd != 2); */
 /*  uint8_t * addr = addr_; */
 /*  ASSERT( addr == (uint8_t *)pg_round_down(addr)); // addr must be page aligned previously */
 /*  int err = 0; */
 /*  int res = -1; */
 /*  uint8_t * upage = NULL; */
 /*  uint8_t * kpage = NULL; */
 /*  void ** kpages = NULL; */
 /*  int i; */
 /*  int read_bytes = sz; */
 /*  int page_read_bytes; */
 /*  int page_zero_bytes; */
  
 /*  virtual_page_info_t info; */
 /*  frame_aux_info_t frame_aux_info; */
  
 /*  int num_pages = sz / PGSIZE; */

 /*  // reset file descriptor to zero */
 /*  seek_fd(fd,0); */
  
 /*  if ( sz % PGSIZE != 0 ) { */
 /*    ++num_pages; */
 /*  } */
  
 /*  // check every page needed is valid */
 /*  for ( i = 0; i < num_pages; ++i ) { */
 /*    upage = addr + i*PGSIZE; */
 /*    info = get_vaddr_info(&thread_current()->s_page_table,upage); */
 /*    if ( info.valid == 1 ) { */
 /*      err = 1; */
 /*      goto memory_map_done; */
 /*    } */
 /*  } */

 /*  // if we are not writing to the stack pointer */
 /*  // allocate memory to save kpages in */
 /*  // */
 /*  // fault in stack pages later if we are stackish */
 /*  if ( !is_stackish(addr) ) { */
 /*    kpages = (void **)malloc(num_pages * sizeof(void *)); */
 /*    memset(kpages,0,num_pages*sizeof(void *)); */

 /*    for ( i = 0; i < num_pages; ++i ) { */
 /*      upage = addr + i*PGSIZE; */
      
 /*      // why are you installing pages directly? */
 /*      // recycle the code inside the page fault handler */
 /*      // */
 /*      // this code doesn't even work, you can install here, evict the pages */
 /*      // access the pages you evicted, then the page fault handler will assert saying */
 /*      // that you never mapped these pages */
 /*      // because you didn't */
 /*      // you installed the pages directly instead of going through the page fault handler */
 /*      memset(&frame_aux_info,0,sizeof(frame_aux_info)); */
 /*      frame_aux_info.owner = thread_current(); */
 /*      frame_aux_info.addr = upage; */
 /*      kpage = frame_alloc(&frame_aux_info); */
 /*      err = !install_page(upage,kpage,1 /\*writable==true*\/); */
 /*      if ( err == 1) { */
 /*        goto memory_map_done; */
 /*      } */
 /*      page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE; */
 /*      page_zero_bytes = PGSIZE - page_read_bytes; */
 /*      read_fd(fd,upage,sz); */
 /*      memset(upage + page_read_bytes, 0, page_zero_bytes); */
 /*      // */
 /*      kpages[i] = kpages; */
 /*    } */
 /*  } */
  
 /*  if ( err == 0 ) { */
 /*    res = alloc_mapid(fd,sz,addr); */
 /*  } */
 /* memory_map_done: */
 /*  if ( res == -1 ) { */
 /*    for ( int i = 0; i < num_pages; ++i ) { */
 /*      if ( kpages[i] ) { // if kpages is not null, uninstall the page */
 /*        // it must have been the ith page we installed... */
 /*        upage = addr + i*PGSIZE; */
 /*        uninstall_page(upage); */
 /*        frame_dealloc(kpages[i]); */
 /*      } */
 /*    } */
 /*  } */
 /*  free(kpages); */
 /*  // unseek the fd to what it was */
 /*  seek_fd(fd,ofs); */
 /*  return res; */
  printf("%d %d %d %p\n",fd,sz,ofs,addr_);
  return 1;
}

void munmap(int mapid) {
  /* mapid_table_t * mapid_table = &thread_current()->mapid_table; // mapid's need only be unique to the process */
  
  /* mapid_w_hook_t mapid_w_hook = { 0 };   */
  /* mapid_w_hook.mapid = mapid; */
  
  /* struct hash_elem * hash_elem = hash_find(&mapid_table->mapids,&mapid_w_hook.hash_elem); */
  /* if ( hash_elem ) { */
  /*   return -1; // no element find */
  /* } */

  /* // write pages back to file */
  
}
