#include "vm/mmap.h"

// mapid for memory mapped files
// look its just an std::unordered_set man
typedef struct mapid_with_hook {
  int mapid;
  int fd;
  int sz;
  void * addr;
  struct hash_elem hash_elem;
} mapid_w_hook_t;

typedef struct mapid_table {
  struct hash mapids;
  struct lock lock;
} mapid_table_t;

static unsigned mapid_hash(const struct hash_elem * p_, void * aux UNUSED ) {
  const mapid_w_hook_t * p = hash_entry(p_, mapid_w_hook_t, hash_elem);
  unsigned res = hash_int(mapid);
  return res;
}

static bool mapid_less(const struct hash_elem * a_,
                       const struct hash_elem * b_) {
  const mapid_w_hook_t * a = hash_entry(p_, mapid_w_hook_t, hash_elem);
  const mapid_w_hook_t * b = hash_entry(p_, mapid_w_hook_t, hash_elem);
  bool res = a->mapid > b->mapid; // we want the first elt to be the latest thing we added in
  return res;
}

static mapid_table_t mapid_table;

void init_mapid_table(void) {
  hash_init(&mapid_table.mapids, mapid_hash, mapid_less, NULL);
  lock_init(&mapid_table.lock);
}

static int alloc_mapid(int fd, size_t sz, void * p) {
  lock_acquire(&mapid_table.lock);
  int res = -1;
  if ( hash_empty(&mapid_table.mapids) ) {
    res = 1;
  }
  else {
    struct hash_iterator i;
    hash_first(&i,&mapid_table.mapids);
    hash_next(&i);
    mapid_w_hook_t * last_mapid = hash_entry(hash_cur(&i), mapid_w_hook_t, hash_elem);
    res = last_mapid->mapid + 1;
  }
  mapid_w_hook_t * mapid_w_hook = (mapid_w_hook_t *)malloc(sizeof(mapid_w_hook_t));
  *mapid_w_hook = { 0 };
  mapid_w_hook.mapid = res;
  mapid_w_hook.fd = fd;
  mapid_w_hook.sz = sz;
  mapid_w_hook.addr = addr;
  lock_release(&mapid_table.lock);
  return res;
}

int mmap(int fd, void * addr_) {
  uint8_t * addr = addr_;
  ASSERT ( addr == pg_round_down(addr) );
  int err = 0;
  int res = -1;
  uint8_t * upage = NULL;
  uint8_t * kpage = NULL;
  void ** kpages = NULL;
  int i;
  
  virtual_page_info_t info;
  frame_aux_info_t frame_aux_info;
  
  size_t sz = tell_fd(fd);
  size_t num_pages = sz / PGSIZE;
  
  if ( sz % PGSIZE != 0 ) {
    ++num_pages;
  }
  
  // check every page needed is valid
  for ( i = 0; i < num_pages; ++i ) {
    upage = addr + i*PGSIZE;
    info = get_vaddr_info(&thread_current()->s_page_table,upage);
    if ( info.valid == 1 ) {
      err = 1;
      goto memory_map_done;
    }
  }
  
  // allocate memory to save kpages in
  kpages = (void **)malloc(num_pages * sizeof(void *));
  memset(kpages,0,num_pages*sizeof(void *));
  
  for ( i = 0; i < num_pages; ++i ) {
    upage = addr + i*PGSIZE;
    frame_aux_info = { 0 };
    frame_aux_info.owner = thread_current();
    frame_aux_info.addr = upage;
    kpage = alloc_frame(&frame_aux_info);
    err = !install_page(upage,kpage,1 /*writable==true*/);
    if ( err == 1) {
      goto memory_map_done;
    }
    kpages[i] = kpages;
  }
  
  if ( err == 0 ) {
    res = alloc_mapid(fd,sz,addr);
  }
 memory_map_done:
  if ( res == -1 ) {
    for ( int i = 0; i < num_pages; ++i ) {
      if ( kpages[i] ) { // if kpages is not null, uninstall the page
        // it must have been the ith page we installed...
        upage = addr + i*PGSIZE;
        uninstall_page(upage);
        dealloc_frame(kpages[i]);
      }
    }
  }
  free(kpages);
  return res;
}
