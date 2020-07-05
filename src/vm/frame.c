
#include "vm/frame.h"

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

// I don't really trust bitmap since the palloc_get_multiple snafu
// but let's use it and see what it gives me
#include "lib/kernel/bitmap.h"

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
  
} frame_table_t;

frame_table_t frame_table_user;

static int frame_get_index_no_lock(void * p_in) {
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
  frame_table_user.bitmap = bitmap_create(MAX_FRAMES);
}

static void* frame_alloc_multiple(int n) {
  lock_acquire(&frame_table_user.lock);

  size_t start = 0;
  size_t val = 0;
  size_t idx = bitmap_scan_and_flip(frame_table_user.bitmap,start,n,val);
  void * res = NULL;
  if ( idx != BITMAP_ERROR ) {
    res = frame_get_frame_no_lock(idx);
  }
  lock_release(&frame_table_user.lock);
  return res;
}

void* frame_alloc() {
  return frame_alloc_multiple(1);
}

void frame_dealloc(void * p) {
  lock_acquire(&frame_table_user.lock);
  int idx = frame_get_index_no_lock(p);
  bitmap_flip(frame_table_user.bitmap,idx);
  lock_release(&frame_table_user.lock);
}
