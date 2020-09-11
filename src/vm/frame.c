
#include "vm/frame.h"

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"

#include "userprog/pagedir.h"

#include "vm/swap.h"


// I don't really trust bitmap since the palloc_get_multiple snafu
// but let's use it and see what it gives me
#include "lib/kernel/bitmap.h"
#include "lib/string.h"

#include <stdio.h>

#define MAX_FRAMES 128

typedef struct lock lock_t;

typedef struct frame_aux_info {
  int aux;
  struct thread * owner; // which process owns the frame, if frame is in use
  void * addr; // virtual address mapped to this frame, NULL if not mapped
               // its upage.

  // lock that pins frame data to index for I/O operations
  lock_t pinning_lock;
    
} frame_aux_info_t;

typedef struct frame_table {
  // this lock is for frames and bitmap
  // frame aux info has its own locks, pinning lock
  lock_t lock;
  
  void* frames; // MAX_FRAME total, continguous in memory, allocated from palloc_get_multiple
  frame_aux_info_t frame_aux_info[MAX_FRAMES];
  struct bitmap *bitmap;
  uint8_t bitmap_data[MAX_FRAMES];
  int clock_hand;
  
} frame_table_t;

frame_table_t frame_table_user;

static int frame_get_index_no_lock(void *);
static void * frame_get_frame_no_lock(int);

static void evict_frame(int idx) {
  ASSERT(0 <= idx && idx < MAX_FRAMES );
  // keep global lock on frame table for now for safety
  ASSERT(lock_held_by_current_thread(&frame_table_user.lock));
  // we already locked the frame, no one can reload into this frame
  //
  // prevents the pathological case:
  // 1. thread 1 evicts frame in evict_frame
  // 2. interrupt to thread 2 and reloads frame
  // 3. thread 1 thinks frame was successfully evicted and continues
  struct lock * pinning_lock = &frame_table_user.frame_aux_info[idx].pinning_lock;
  ASSERT(lock_held_by_current_thread(pinning_lock));

  struct thread * owner = frame_table_user.frame_aux_info[idx].owner;
  uint8_t * upage = frame_table_user.frame_aux_info[idx].addr;
  void * frame = frame_get_frame_no_lock(idx);

  // printf("tagiamies 4\n");
  
  // uninstall the page
  // assume it can't somehow interrupt a fault-less memory access by owner
  // It's a big assumption
  uninstall_page(owner,upage);

  // printf("tagiamies 5\n");
  
  // figure out where it goes
  virtual_page_info_t info = get_vaddr_info(&owner->page_table,upage);
  ASSERT(info.valid == 1 && "don't try to evict invalid pages");

  // printf("tagiamies 6\n");

  // printf("upage %p info.home %d info.writable %d\n",upage,info.home,info.writable);
  
  if ( info.home == PAGE_SOURCE_OF_DATA_MMAP ) {
    // call mmap things
    // worry about it later
    ASSERT(false && "don't call mmap things");
    
    // don't update the data source, we wrote it back to its file
    // we'll reload it from its file if we fault on it
  }
  else if ( info.writable == 1 ) {
    // must be one of ELF writable (bss) or stack
    ASSERT(info.home == PAGE_SOURCE_OF_DATA_ELF ||
           info.home == PAGE_SOURCE_OF_DATA_STACK ||
           info.home == PAGE_SOURCE_OF_DATA_SWAP);
    
    // printf("tagiamies 7\n");
    // write frame to swap space
    info.swap_loc = swap_write_page(frame,PGSIZE);
    // update the other process's MMU
    info.home = PAGE_SOURCE_OF_DATA_SWAP;
    info.frame = NULL;
    // printf("tagiamies 8\n");
    set_vaddr_info(&owner->page_table,upage,&info);
    // printf("tagiamies 9\n");
  }
  else {
    // printf("tagiamies 10\n");
    // assert its .text or .rodata elf segments
    ASSERT(info.writable == 0);
    ASSERT(info.home == PAGE_SOURCE_OF_DATA_ELF);
    // don't do anything else, just discard it
    
    // also don't update the data source
  }
  
  lock_release(pinning_lock);
}

static bool check_clock_finish(void * owner,
                               uint32_t * pd,
                               uint8_t * upage,
                               int frame_table_idx) {
  // the bitmap scan and flip should have found you if owner is null
  ASSERT(owner != NULL);
  bool a = pagedir_is_accessed(pd,upage);
  struct lock * lk = &frame_table_user.frame_aux_info[frame_table_idx].pinning_lock;
  bool success = lock_try_acquire(lk);
  // four cases here, explicitly laid out instead of being clever
  if ( a == 0 && success == 0 ) {
    return false;
  }
  else if ( a == 0 && success == 1 ) {
    return true;
  }
  else if ( a == 1 && success == 0 ) {
    return false;
  }
  else {
    ASSERT(a == 1);
    ASSERT(success == 1);
    lock_release(lk);
    return false;
  }
}

static void increment_clock_hand(uint32_t * pd,
                                 uint8_t * upage,
                                 int * clock_hand) {
  // maybe also do silly second clock hand thing
  pagedir_set_accessed(pd,upage,false/*not accessed*/);
  ++(*clock_hand);
  (*clock_hand) %= MAX_FRAMES;
}

static int get_frame_slot_with_eviction(void) {
  // printf("tagiamies get frame slot with eviction\n");
  ASSERT(lock_held_by_current_thread(&frame_table_user.lock));
  
  uint8_t * upage;
  struct thread * owner;
  uint32_t * pagedir;
  
  // consider a more granular lock around just clock_hand
  int clock_hand = frame_table_user.clock_hand;

  // implement clock algorithm
  while ( true ) {

    //////////////
    // you can't examine addr and owner without first acquiring the lock...
    //////////////
    
    upage = frame_table_user.frame_aux_info[clock_hand].addr;
    owner = frame_table_user.frame_aux_info[clock_hand].owner;
    
    // I don't think this lock can do anything
    // hardware is ignoring the mutex and setting the access bits
    // ... I don't even care about access bits accuracy
    // lock_acquire(&owner->page_table.pd_lock);
    pagedir = owner->page_table.pagedir;
    // printf("tagiamies 1\n");
    if ( check_clock_finish(owner,pagedir,upage,clock_hand) ) {
      break;
    }
    // printf("tagiamies 2\n");
    increment_clock_hand(pagedir,upage,&clock_hand);
    // lock_release(&owner->page_table.pd_lock);
  }

  // printf("tagiamies 3\n");
  // you acquired the lock to the frame table idx at clock_hand
  // in check_clock_finish
  evict_frame(clock_hand);
  
  // printf("tagiamies get frame slot with eviction exit\n");
  return clock_hand;
}

int frame_get_index_no_lock(void * p_in) {
  // do operations on char *
  char * first_frame = (char *)frame_table_user.frames;
  char * p = p_in;
  size_t diff = p - first_frame;
  ASSERT(diff % PGSIZE == 0); // diff must be a multiple of PGSIZE
  int idx = diff / PGSIZE;
  return idx;
}

void * frame_get_frame_no_lock(int idx) {
  char * first_frame = frame_table_user.frames;
  size_t diff = idx * PGSIZE;
  void * p = first_frame + diff;
  return p;
}

void frame_table_init(void) {
  lock_init(&frame_table_user.lock);

  // 0 all the aux info
  memset(frame_table_user.frame_aux_info,0,sizeof(frame_aux_info_t)*MAX_FRAMES);

  for ( size_t i = 0; i < MAX_FRAMES; ++i ) {
    lock_init(&frame_table_user.frame_aux_info[i].pinning_lock);
  }
  
  // let this memory leak because idgaf
  frame_table_user.frames = palloc_get_multiple(PAL_ASSERT | PAL_ZERO | PAL_USER, MAX_FRAMES);
  ASSERT(frame_table_user.frames != NULL);

  frame_table_user.clock_hand = 0;
  
  // let bitmap memory leak too
  size_t bit_cnt = MAX_FRAMES;
  void * block = &frame_table_user.bitmap_data;
  size_t block_size = bit_cnt * sizeof(uint8_t);
  frame_table_user.bitmap = bitmap_create_in_buf(bit_cnt,block,block_size);
}

static void* frame_alloc_multiple(int n, struct thread * owner, void * addr) {
  ASSERT(n==1); // only works with 1 for now
  // printf("tagiamies frame alloc multiple addr %p\n",addr);
  lock_acquire(&frame_table_user.lock);

  size_t start = 0;
  size_t val = 0;
  // I am almost entirely sure there is some bug in bitmap_scan_and_flip
  //
  // it should scan and flip left to right
  size_t idx = bitmap_scan_and_flip(frame_table_user.bitmap,start,n,val);
  void * res = NULL;
  if ( idx == BITMAP_ERROR ) {
    // evict a frame to use if bitmap is full
    idx = get_frame_slot_with_eviction();
  }
  res = frame_get_frame_no_lock(idx);
  // update aux info
  for ( size_t i = idx; i < idx+n; ++i ) {
    lock_acquire(&frame_table_user.frame_aux_info[i].pinning_lock);
    frame_table_user.frame_aux_info[i].owner = owner;
    frame_table_user.frame_aux_info[i].addr = addr;
    lock_release(&frame_table_user.frame_aux_info[i].pinning_lock);
  }
  ASSERT (res != NULL);
  lock_release(&frame_table_user.lock);
  // doesn't keep track of how many pages have been allocated yet
  // printf("tagiamies frame alloc multiple exit\n");
  return res;
}

void* frame_alloc(struct thread * owner, void * addr) {
  ASSERT (owner != NULL); //owner can't be null
  return frame_alloc_multiple(1,owner,addr);
}

void frame_dealloc(void * p) {
  ASSERT (p != NULL);
  lock_acquire(&frame_table_user.lock);
  int idx = frame_get_index_no_lock(p);
  bitmap_flip(frame_table_user.bitmap,idx);
  /* frame_table_user.frame_aux_info[idx] = { 0 }; */
  memset(&frame_table_user.frame_aux_info[idx],0,sizeof(frame_aux_info_t));
  lock_release(&frame_table_user.lock);
}

void frame_table_dump(int aux) {
  lock_acquire(&frame_table_user.lock);

  printf("===frame table dump %d===\n",aux);
  for ( int i = 0; i < MAX_FRAMES; ++i ) {
    char * p = frame_table_user.frames;
    p += (PGSIZE * i);
    printf("frame[%d]: %p\n",i,p);
  }
  bitmap_dump(frame_table_user.bitmap);
  
  lock_release(&frame_table_user.lock);  
}
