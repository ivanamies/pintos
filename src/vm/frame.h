#ifndef VM_FRAME_H
#define VM_FRAME_H

#define SOME_FRAME_DEFINE

struct thread;

typedef struct frame_aux_info {
  int aux;
  struct thread * owner; // which process owns the frame, if frame is in use
  void * addr; // virtual address mapped to this frame, NULL if not mapped
} frame_aux_info_t;

void frame_table_init(void);
void * frame_alloc(frame_aux_info_t *);
void frame_dealloc(void *);

// for debugging
void frame_table_dump(int);

#endif /* vm/frame.h */
