#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"

#include <kernel/list.h>

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

typedef struct frame_aux_info_list_elem {
  struct list_elem lel;
  frame_aux_info_t * frame_aux_info;
} frame_aux_info_list_elem_t;

void frame_table_init(void);
frame_aux_info_t* frame_alloc(struct thread *, void *);
void frame_dealloc(void *);

void frame_alloc_into_list(struct list * gets, void * addr_, size_t sz);

void frame_process_exit(void);

// gets frame lock given frame
struct lock * frame_get_frame_lock(void *);

// for debugging
void frame_table_dump(int);

void evict_frame_w_kpage(void * kpage);

#endif /* vm/frame.h */
