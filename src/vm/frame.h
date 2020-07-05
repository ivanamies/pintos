#ifndef VM_FRAME_H
#define VM_FRAME_H

#define SOME_FRAME_DEFINE

void frame_table_init(void);
void * frame_alloc(void);
void frame_dealloc(void *);

// for debugging
void frame_table_dump(int);

#endif /* vm/frame.h */
