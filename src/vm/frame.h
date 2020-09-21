#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"

struct thread;

typedef struct frame_aux_info {
  int aux;
  struct thread * owner; // which process owns the frame, if frame is in use
  void * kpage; // actual frame which holds data
  void * upage; // virtual address mapped to this frame, NULL if not mapped
               // its upage.

  // lock that pins frame data to index for I/O operations
  struct lock pinning_lock;
  
} frame_aux_info_t;

void frame_table_init(void);
frame_aux_info_t* frame_alloc(struct thread *, void *);
void frame_dealloc(void *);

// for debugging
void frame_table_dump(int);

#endif /* vm/frame.h */
