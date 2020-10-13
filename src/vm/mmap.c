#include "vm/mmap.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

#include "userprog/exception.h"
#include "userprog/syscall.h"

#include "vm/page.h"
#include "vm/frame.h"

#include "filesys/file.h"

#include <string.h>
#include <stdio.h>

// mapid for memory mapped files
// look its just an std::unordered_set man
typedef struct mapid_with_hook {
  struct hash_elem hash_elem;
  
  int mapid;
  int fd;
  struct file * file;
  void * addr;
  
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

static int alloc_mapid(int fd, struct file * file, void * p) {
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
  mapid_w_hook->file = file;
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
int mmap(int fd, void * addr_) {
  ASSERT(fd != 0 && fd != 1 && fd != 2);
  struct thread * curr = thread_current();
  uint8_t * addr = addr_;
  ASSERT( addr == (uint8_t *)pg_round_down(addr)); // addr must be page aligned previously
  int err = 0;
  int res = -1;
  bool writable = true;
  uint8_t * upage = NULL;
  int i;
  
  virtual_page_info_t info;
  
  struct file * file = fd_get_file(fd);
  ASSERT(file != NULL);
  
  size_t old_ofs = file_tell(file); // get the old file ofs
  
  int sz = file_length(file);
  size_t ofs = 0;
  
  int num_pages = sz / PGSIZE;
  if ( sz % PGSIZE != 0 ) {
    ++num_pages;
  }

  // bytes to load segment with
  size_t total_bytes = num_pages * PGSIZE;
  size_t zero_bytes = total_bytes - sz;
  
  // reset file to ofs == 0
  file_seek(file,ofs);

  // we cannot map the stack
  if ( is_stackish(addr) ) {
    err = 1;
    ASSERT(res == -1);
    goto memory_map_done;
  }
  
  // check every page needed is unmapped
  // we also cannot map executable memory
  for ( i = 0; i < num_pages; ++i ) {
    upage = addr + i*PGSIZE;
    info = get_vaddr_info(&curr->page_table,upage);
    if ( info.valid == 1 ) {
      err = 1;
      ASSERT(res == -1);
      goto memory_map_done;
    }
  }
  
  // maps ALL the upages to the file
  err = !load_segment(file,ofs,upage,sz,zero_bytes,writable,PAGE_SOURCE_OF_DATA_MMAP);
                      
  if ( err == 0 ) {
    res = alloc_mapid(fd,file,addr);
  }
 memory_map_done:
  // unseek the fd to what it was
  file_seek(file,old_ofs);
  return res;
}

void munmap(mapid_t mapping) {
  mapid_table_t * mapid_table = &thread_current()->mapid_table; // mapid's need only be unique to the process
  
  mapid_w_hook_t mapid_w_hook = { 0 };
  mapid_w_hook.mapid = mapping;
  
  struct hash_elem * hash_elem = hash_find(&mapid_table->mapids,&mapid_w_hook.hash_elem);
  if ( hash_elem == NULL ) {
    return; // no element found
  }
  
  ASSERT(false);
  
  // write pages back to file
  mapid_w_hook_t * entry = hash_entry(hash_elem, mapid_w_hook_t, hash_elem);
  struct file * file = entry->file;
  size_t sz = file_length(file);
  void * addr = entry->addr;
  file_write(file,addr,sz);

  int num_pages = sz / PGSIZE;
  if ( sz % PGSIZE != 0 ) {
    ++num_pages;
  }
  // unmap the pages in the supplemental page table
  for ( int i = 0; i < num_pages; ++i ) {
    uint8_t * upage = addr + i*PGSIZE;
    virtual_page_info_t info = { 0 };
    set_vaddr_info(&thread_current()->page_table,upage,&info);
  }
  
}
