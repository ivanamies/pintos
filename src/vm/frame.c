
#include "vm/frame.h"

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"

#include "userprog/pagedir.h"


// I don't really trust bitmap since the palloc_get_multiple snafu
// but let's use it and see what it gives me
#include "lib/kernel/bitmap.h"
#include "lib/string.h"

#include <stdio.h>

#define MAX_FRAMES 128

typedef struct lock lock_t;

typedef struct frame_table {
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
  ASSERT(lock_held_by_current_thread(&frame_table_user.lock));
  ASSERT(idx != -1);
  
  // keep global lock for now on frame table for now
  // really you should global lock to get frame info
  // lock the lock inside frame info then do the eviction
  
}

static bool check_clock_finish(void * owner,
                               uint32_t * pd,
                               uint8_t * upage) {
  // the bitmap scan and flip should have found you if owner is null
  ASSERT(owner != NULL);
  bool a = pagedir_is_accessed(pd,upage);
  return a == 0;
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
  ASSERT(false);
  ASSERT(lock_held_by_current_thread(&frame_table_user.lock));
  
  uint8_t * upage;
  struct thread * owner;
  uint32_t * pagedir;
  
  // consider a more granular lock around just clock_hand
  int clock_hand = frame_table_user.clock_hand;

  // implement clock algorithm
  while ( true ) {
    upage = frame_table_user.frame_aux_info[clock_hand].addr;
    owner = frame_table_user.frame_aux_info[clock_hand].owner;
    pagedir = owner->pagedir;
    if ( check_clock_finish(owner,pagedir,upage) ) {
      break;
    }
    
    increment_clock_hand(pagedir,upage,&clock_hand);
  }
  
  evict_frame(clock_hand);
  
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

static void* frame_alloc_multiple(int n, frame_aux_info_t * info) {
  ASSERT(n==1); // only works with 1 for now
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
    frame_table_user.frame_aux_info[i] = *info;
  }
  ASSERT (res != NULL);
  lock_release(&frame_table_user.lock);
  // doesn't keep track of how many pages have been allocated yet
  return res;
}

void* frame_alloc(frame_aux_info_t * info) {
  ASSERT (info->owner != NULL); //owner can't be null
  return frame_alloc_multiple(1,info);
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
