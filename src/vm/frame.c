
#include "vm/frame.h"

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

// I don't really trust bitmap since the palloc_get_multiple snafu
// but let's use it and see what it gives me
#include "lib/kernel/bitmap.h"

#include <stdio.h>

#define MAX_FRAMES 64

typedef struct lock lock_t;

typedef struct frame_aux_info {
  int aux;
} frame_aux_info_t;

typedef struct frame_table {
  lock_t lock;
  
  void* frames; // MAX_FRAME total, continguous in memory, allocated from palloc_get_multiple
  frame_aux_info_t frame_aux_info[MAX_FRAMES];
  struct bitmap *bitmap;
  uint8_t bitmap_data[MAX_FRAMES];
  
} frame_table_t;

frame_table_t frame_table_user;

static size_t frame_get_index_no_lock(void * p_in) {
  // do operations on char *
  char * first_frame = (char *)frame_table_user.frames;
  char * p = p_in;
  size_t diff = p - first_frame;
  ASSERT(diff % PGSIZE == 0); // diff must be a multiple of PGSIZE
  int idx = diff / PGSIZE;
  return idx;
}

static void * frame_get_frame_no_lock(int idx) {
  char * first_frame = frame_table_user.frames;
  size_t diff = idx * PGSIZE;
  void * p = first_frame + diff;
  return p;
}

void frame_table_init(void) {
  lock_init(&frame_table_user.lock);

  // let this memory leak because idgaf
  frame_table_user.frames = palloc_get_multiple(PAL_ASSERT | PAL_ZERO | PAL_USER, MAX_FRAMES);
  ASSERT(frame_table_user.frames != NULL);
  
  // let bitmap memory leak too
  size_t bit_cnt = MAX_FRAMES;
  void * block = &frame_table_user.bitmap_data;
  size_t block_size = bit_cnt * sizeof(uint8_t);
  frame_table_user.bitmap = bitmap_create_in_buf(bit_cnt,block,block_size);
}

static void* frame_alloc_multiple(int n) {
  lock_acquire(&frame_table_user.lock);

  size_t start = 0;
  size_t val = 0;
  size_t idx = bitmap_scan_and_flip(frame_table_user.bitmap,start,n,val);
  printf("alloc idx: %ld n: %d\n",idx,n);
  void * res = NULL;
  if ( idx != BITMAP_ERROR ) {
    res = frame_get_frame_no_lock(idx);
  }
  ASSERT ( res != NULL );
  lock_release(&frame_table_user.lock);
  return res;
}

void* frame_alloc(void) {
  return frame_alloc_multiple(1);
}

void frame_dealloc(void * p) {
  lock_acquire(&frame_table_user.lock);
  size_t idx = frame_get_index_no_lock(p);
  printf("dealloc idx: %ld\n",idx);
  // this can't dealloc multiple, store # continguous pages in aux info
  bitmap_flip(frame_table_user.bitmap,idx);
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
