
#include "vm/frame.h"

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

#include "userprog/pagedir.h"

#include "vm/swap.h"

#include <string.h>
#include <stdio.h>

#define MAX_FRAMES 128

typedef struct lock lock_t;

typedef struct frame_table {
  // this lock is for frames and bitmap
  // frame aux info has its own locks, pinning lock
  lock_t lock;
  
  void* frames; // MAX_FRAME total, continguous in memory, allocated from palloc_get_multiple
  frame_aux_info_t frame_aux_info[MAX_FRAMES];
  
  int clock_hand;
  
} frame_table_t;

frame_table_t frame_table_user;

static int frame_get_index_no_lock(void *);
static void * frame_get_frame_no_lock(int);

static void evict_frame(int idx) {
  ASSERT(0 <= idx && idx < MAX_FRAMES );
  
  // we already locked the frame, no one can reload into this frame
  //
  // prevents the pathological case:
  // 1. thread 1 evicts frame in evict_frame
  // 2. interrupt to thread 2 and reloads frame
  // 3. thread 1 thinks frame was successfully evicted and continues
  struct lock * pinning_lock = &frame_table_user.frame_aux_info[idx].pinning_lock;
  ASSERT(lock_held_by_current_thread(pinning_lock));

  struct thread * owner = frame_table_user.frame_aux_info[idx].owner;
  uint8_t * upage = frame_table_user.frame_aux_info[idx].upage;
  void * frame = frame_get_frame_no_lock(idx);

  /* printf("tagiamies 4\n"); */
  
  /* // uninstall the page */
  /* // assume it can't somehow interrupt a fault-less memory access by owner */
  /* // It's a big assumption */
  /* uninstall_page(owner,upage); */
  
  // printf("tagiamies 5 thread %p requested %p uninstall %p\n",thread_current(),owner,upage);

  // go add the part where you update the other thread's page table
  // to this function....
  uninstall_request_pull(owner,upage,frame);
      
  memset(frame,0,PGSIZE);

}

static frame_aux_info_t * get_frame_slot_with_eviction(void) {
  // printf("tagiamies thread %p get frame slot with eviction\n",thread_current());

  uint32_t * pd;
  uint8_t * upage;
  struct thread * owner;
  struct lock * lk;
  bool success;
  int clock_hand;
  
  // implement clock algorithm
  while ( true ) {

    // consider a more granular lock around just clock_hand
    lock_acquire(&frame_table_user.lock);
    clock_hand = frame_table_user.clock_hand;
    lock_release(&frame_table_user.lock);

    lk = &frame_table_user.frame_aux_info[clock_hand].pinning_lock;
    success = lock_try_acquire(lk);
    if ( success == 1 ) {
      owner = frame_table_user.frame_aux_info[clock_hand].owner;
      upage = frame_table_user.frame_aux_info[clock_hand].upage;
      
      // printf("thread %p acquired pinning lk %p\n",thread_current(),lk);
      if ( owner == NULL || upage == NULL) {
        ASSERT(owner == NULL);
        ASSERT(upage == NULL);
        return &frame_table_user.frame_aux_info[clock_hand];
      }
      
      // almost entirely sure I don't need this lock
      lock_acquire(&owner->page_table.pd_lock);
      pd = owner->page_table.pagedir;
      bool a = pagedir_is_accessed(pd,upage); // save copy of accessed bit
      // set it to false
      // if I race on this bit, fuck you
      pagedir_set_accessed(pd,upage,false/*not accessed*/);
      lock_release(&owner->page_table.pd_lock);
      
      if ( a == 0 ) {
        break;
      }
      else {        
        lock_release(lk); // release the frame lock we acquired
      }
    }
    
    // increment clock hand
    lock_acquire(&frame_table_user.lock);
    ++(frame_table_user.clock_hand);
    (frame_table_user.clock_hand) %= MAX_FRAMES;
    lock_release(&frame_table_user.lock);        
  }

  /* printf("tagiamies 3\n"); */
  // you acquired the lock to the frame table idx at clock_hand
  // in check_clock_finish
  evict_frame(clock_hand);
  
  /* printf("tagiamies 15\n"); */
  // printf("tagiamies get frame slot with eviction exit\n");
  return &frame_table_user.frame_aux_info[clock_hand];
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
  void * p;
  
  lock_init(&frame_table_user.lock);

  // 0 all the aux info
  memset(frame_table_user.frame_aux_info,0,sizeof(frame_aux_info_t)*MAX_FRAMES);
  
  // let this memory leak because idgaf
  frame_table_user.frames = palloc_get_multiple(PAL_ASSERT | PAL_ZERO | PAL_USER, MAX_FRAMES);
  ASSERT(frame_table_user.frames != NULL);

  for ( size_t i = 0; i < MAX_FRAMES; ++i ) {
    lock_init(&frame_table_user.frame_aux_info[i].pinning_lock);
    p = frame_get_frame_no_lock(i);
    frame_table_user.frame_aux_info[i].kpage = p;
  }
  
  frame_table_user.clock_hand = 0;
}

static frame_aux_info_t* frame_alloc_multiple(int n, struct thread * owner, void * addr) {
  ASSERT(n==1); // only works with 1 for now
  // printf("tagiamies thread %p frame alloc multiple for upage %p\n",thread_current(),addr);

  frame_aux_info_t * res;
  
  res = get_frame_slot_with_eviction();
  
  ASSERT(res != NULL);
  ASSERT(res->kpage != NULL);
  
  res->owner = owner;
  res->upage = addr;
  
  // printf("tagiamies thread %p frame alloc multiple exit\n",thread_current());
  return res;
}

frame_aux_info_t* frame_alloc(struct thread * owner, void * addr) {
  ASSERT (owner != NULL); //owner can't be null
  return frame_alloc_multiple(1,owner,addr);
}

void frame_dealloc(void * p) {
  ASSERT (p != NULL);
  lock_acquire(&frame_table_user.lock);
  int idx = frame_get_index_no_lock(p);
  memset(&frame_table_user.frame_aux_info[idx],0,sizeof(frame_aux_info_t));
  lock_release(&frame_table_user.lock);
}

void frame_process_exit(void) {
  struct thread * cur = thread_current();
  struct lock * lk;
  size_t i;

  for ( i = 0; i < MAX_FRAMES; ++i ){
    lk = &frame_table_user.frame_aux_info[i].pinning_lock;
    // now try to write to it
    // spin while trying to acquire it
    // uninstall pages in the meanwhile
    while ( !lock_try_acquire(lk) ) {
      /* printf("tagiamies process exit thread %p trying to acquire frame %zu %p lock %p\n", */
      /*        cur,i,frame_table_user.frame_aux_info[i].kpage, */
      /*        &frame_table_user.frame_aux_info[i].pinning_lock); */
      uninstall_request_push();
      thread_yield();
    }

    if (frame_table_user.frame_aux_info[i].owner == cur) {

      uninstall_page(cur,frame_table_user.frame_aux_info[i].upage);
      
      frame_table_user.frame_aux_info[i].owner = NULL;
      frame_table_user.frame_aux_info[i].upage = NULL;      
      
    }

    // release the lock we acquired
    lock_release(lk);

  }
}

struct lock * frame_get_frame_lock(void * upage) {
  size_t idx = frame_get_index_no_lock(upage);
  struct lock * res = &frame_table_user.frame_aux_info[idx].pinning_lock;
  return res;
}

void frame_table_dump(int aux UNUSED) {
  ASSERT(false);
  /* lock_acquire(&frame_table_user.lock); */

  /* printf("===frame table dump %d===\n",aux); */
  /* for ( int i = 0; i < MAX_FRAMES; ++i ) { */
  /*   char * p = frame_table_user.frames; */
  /*   p += (PGSIZE * i); */
  /*   printf("frame[%d]: %p\n",i,p); */
  /* } */
  /* bitmap_dump(frame_table_user.bitmap); */
  
  /* lock_release(&frame_table_user.lock);   */
}
