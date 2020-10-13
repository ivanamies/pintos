
#include <stdio.h>

#include "vm/page.h"

#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/pagedir.h"

#include "vm/frame.h"
#include "vm/swap.h"

#include "filesys/file.h"

typedef struct uninstall_request {
  struct list_elem lel;
  void * upage;
  void * kpage; // lock and condition also block operations on this kpage
  
  struct lock cv_lk;
  struct condition cv;
  int signal;

} uninstall_request_t;

// hash value for virtual_page_t page
static unsigned page_hash(const struct hash_elem * p_, void * aux UNUSED) {
  const virtual_page_t * p = hash_entry(p_, virtual_page_t, hash_elem);
  unsigned res = hash_bytes(&p->addr, sizeof(p->addr));
  return res;
}

// return true if virtual_page_t a precedes b
static bool page_less(const struct hash_elem * a_,
                      const struct hash_elem * b_,
                      void * aux UNUSED) {
  const virtual_page_t * a = hash_entry(a_, virtual_page_t, hash_elem);
  const virtual_page_t * b = hash_entry(b_, virtual_page_t, hash_elem);
  bool res = a->addr < b->addr;
  return res;
}

static void page_destroy(struct hash_elem *e, void * aux UNUSED) {
  virtual_page_t * p = hash_entry(e,virtual_page_t,hash_elem);
  block_sector_t sector = p->info.swap_loc;
  if ( p->info.home == PAGE_SOURCE_OF_DATA_SWAP_IN ) {
    swap_make_page_available(sector);
  }
  free(p);
}

void init_supplemental_page_table(page_table_t * page_table) {

  hash_init(&page_table->pages, page_hash, page_less, NULL);
  lock_init(&page_table->lock);

  list_init(&page_table->uninstall_requests);
  lock_init(&page_table->pd_lock);
  // just like ignore the pde entry for now
}

void* alloc_virtual_address(page_table_t * page_table UNUSED, virtual_page_info_t * info UNUSED) {
  ASSERT(false); // probably not needed
  /* ASSERT(info->valid == 1); // you must provide a valid page info... */
  /* struct hash_elem * e; */
  /* virtual_page_t * page = (virtual_page_t *)malloc(sizeof(virtual_page_t)); */

  /* page->info = *info; // COPY BY VALUE */
  
  /* lock_acquire(&page_table->lock); */

  /* e = hash_insert(&page_table->pages,&page->hash_elem); */
  /* ASSERT ( e == NULL ); */
  
  /* lock_release(&page_table->lock); */

  /* return page->addr; */
}

static virtual_page_info_t get_vaddr_info_no_lock(page_table_t * page_table,
                                           void *  vaddr) {
  ASSERT(lock_held_by_current_thread(&page_table->lock));
         
  virtual_page_info_t info = { 0 };
  virtual_page_t page;
  virtual_page_t * discovered;
  struct hash_elem * e;

  // if we don't find anything valid is 0
  info.valid = 0;
  
  page.addr = vaddr;

  e = hash_find(&page_table->pages,&page.hash_elem);
  
  if ( e != NULL ) {
    discovered = hash_entry(e,virtual_page_t,hash_elem);
    info = discovered->info;
  }

  return info;

}

virtual_page_info_t get_vaddr_info(page_table_t * page_table,
                                   void * vaddr) {  
  lock_acquire(&page_table->lock);
  virtual_page_info_t info = get_vaddr_info_no_lock(page_table,vaddr);
  lock_release(&page_table->lock);
  return info;
}

static int set_vaddr_info_no_lock(page_table_t * page_table,
                           void * vaddr,
                           virtual_page_info_t * info) {
  ASSERT(lock_held_by_current_thread(&page_table->lock));
  virtual_page_t * page = (virtual_page_t *)malloc(sizeof(virtual_page_t));
  page->addr = vaddr;
  virtual_page_t * discovered;
  struct hash_elem * e;
  int prev = 0;

  page->addr = vaddr;

  e = hash_insert(&page_table->pages,&page->hash_elem);

  if ( e != NULL ) {
    discovered = hash_entry(e,virtual_page_t,hash_elem);
    discovered->info = *info;
    free(page);
    prev = 1;
  }
  else {
    page->info = *info;
  }
  
  return prev;
}

int set_vaddr_info(page_table_t * page_table,
                      void * vaddr,
                      virtual_page_info_t * info) {
  lock_acquire(&page_table->lock);
  int err = set_vaddr_info_no_lock(page_table,vaddr,info);
  lock_release(&page_table->lock);
  return err;
}

void page_process_exit(void) {
  struct thread * cur = thread_current();

  // it should be impossible to add more uninstall requests
  // because I own no more user frames
  
  // clear any left over uninstall requests just in case
  uninstall_request_push();
  
  ASSERT(list_empty(&cur->page_table.uninstall_requests));

  // you MUST only add hash entries to supplemental page table in the same thread
  // or else the guarantee of transaction atomicty synching hardware and software page tables is broken
  // acquire the hash table lock anyways because I'm too lazy to check and test right right now
  lock_acquire(&cur->page_table.lock);
  hash_destroy(&cur->page_table.pages,page_destroy);
  lock_release(&cur->page_table.lock);
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  uint32_t * pd = t->page_table.pagedir;

  lock_acquire(&t->page_table.pd_lock);
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool p1 = pagedir_get_page (pd, upage) == NULL;
  bool p2 = false;
  if ( p1 ) {
    p2 = pagedir_set_page (pd, upage, kpage, writable);
  }
  lock_release(&t->page_table.pd_lock);
  return p1 && p2;
}

// process 1 should not touch process 2's page table unless process 2 can't be scheduled
// if process 2 can't be scheduled, conflict is impossible
void uninstall_page(struct thread * t, void* upage) {
  ASSERT(t != NULL);
  uint32_t * pd = t->page_table.pagedir;
  
  // add back in this lock
  // other threads can uninstall other threads' pages
  // it's just fucking it up is really hard
  
  /* lock_acquire(&t->page_table.pd_lock); */
  
  // must uninstall page in software and hardware MMU under the same granularity 
  pagedir_clear_page(pd, upage);
  
  /* lock_release(&t->page_table.pd_lock); */
}

void * query_page_installed(void * upage) {
  struct thread * cur = thread_current();
  uint32_t * pd = cur->page_table.pagedir;
  // you NEED locks around this
  void * p = pagedir_get_page (pd, upage);
  //
  return p;
}

void install_pages(struct list * gets) {
  struct thread * cur = thread_current();
  struct list_elem * lel;
  frame_aux_info_list_elem_t * frame_info_lel;
  frame_aux_info_t * frame_info;
  const bool writable = true;
  uint8_t * upage;
  uint8_t * kpage;

  for ( lel = list_begin(gets); lel != list_end(gets); lel = list_next(lel) ) {
    frame_info_lel = list_entry(lel,frame_aux_info_list_elem_t,lel);
    frame_info = frame_info_lel->frame_aux_info;
    ASSERT(frame_info != NULL);
    ASSERT(lock_held_by_current_thread(&frame_info->pinning_lock));
    ASSERT(cur == frame_info->owner);
    upage = frame_info->upage;
    kpage = frame_info->kpage;
    // printf("install page upage %p pg_ofs(upage) %d kpage %p\n",upage,pg_ofs(upage),kpage);
    install_page(upage,kpage,writable);
  }
}

// should be renamed release locks or something
void release_page_locks(struct list * gets) {
  struct thread * cur = thread_current();
  struct list_elem * lel;
  frame_aux_info_list_elem_t * frame_info_lel;
  frame_aux_info_t * frame_info;

  for ( lel = list_begin(gets); lel != list_end(gets);  ) {
    frame_info_lel = list_entry(lel,frame_aux_info_list_elem_t,lel);
    frame_info = frame_info_lel->frame_aux_info;
    ASSERT(frame_info != NULL);
    ASSERT(lock_held_by_current_thread(&frame_info->pinning_lock));
    ASSERT(cur == frame_info->owner);
    
    /* kpage = frame_info->kpage; */
    
    /* printf("uninstall page thread %p kpage %p\n",cur,kpage); */
    /* evict_frame_w_kpage(kpage); // also uninstalls the upage */

    /* // release the page */
    /* // free pinning lock on kpage so it can be evicted and that upage uninstalled again */
    /* frame_info->owner = NULL; */
    /* frame_info->upage = NULL; */
    
    lock_release(&frame_info->pinning_lock);
    
    // advance list iterator
    lel = list_remove(lel);
    // free the struct that contains the previous list iterator
    free(frame_info_lel);
  }
}

// ... you can't call this with interrupts off...
static void uninstall_page_supplemental_info(struct thread * t, void * upage, void * kpage) {  
  virtual_page_info_t info = get_vaddr_info_no_lock(&t->page_table,upage);
  ASSERT(info.valid == 1 && "don't try to evict invalid pages");
  
  // printf("thread %p uninstall page supplemental info upage %p kpage %p info.home %d info.writable %d\n",thread_current(),upage,kpage,info.home,info.writable);
  
  if ( info.home == PAGE_SOURCE_OF_DATA_MMAP ) {    
    struct file * file = file_reopen(info.file); // makes a copy of the file to avoid weird races on cursor position
    size_t page_read_bytes = info.page_read_bytes;
    size_t file_ofs = info.file_ofs;
    file_seek(file,file_ofs);
    file_write(file,kpage,page_read_bytes); // can't do the entire PGSIZE
    file_close(file);
  }
  else if ( info.writable == 1 ) {
    // must be one of ELF writable (bss) or stack
    // or was changed so that it has been written to swap
    ASSERT(info.home == PAGE_SOURCE_OF_DATA_ELF ||
           info.home == PAGE_SOURCE_OF_DATA_STACK ||
           info.home == PAGE_SOURCE_OF_DATA_SWAP_OUT);
    
    /* printf("tagiamies 7\n"); */
    // write frame to swap space
    info.swap_loc = swap_write_page(kpage,PGSIZE);
    // printf("thread %p kpage %p written to %zu\n",thread_current(),kpage,info.swap_loc);
    
    /* // update the other process's MMU */
    info.home = PAGE_SOURCE_OF_DATA_SWAP_IN;
  }
  else {
    /* printf("tagiamies 15\n"); */
    // assert it is .text or .rodata elf segments
    ASSERT(info.writable == 0);
    ASSERT(info.home == PAGE_SOURCE_OF_DATA_ELF);
    // don't do anything else, just discard the info in it    
  }

  info.frame = NULL;
  set_vaddr_info_no_lock(&t->page_table,upage,&info);
}

// calling thread blocks untill OWNER calls uninstall_request_push on U_REQ
// not so sure on the naming...
void uninstall_request_pull(struct thread * owner, void * upage, void * kpage) {
  ASSERT(owner != NULL);
  ASSERT(upage != NULL);
  ASSERT(kpage != NULL);
  ASSERT(lock_held_by_current_thread(frame_get_frame_lock(kpage)));
  
  struct thread * cur = thread_current();
  
  // printf("thread %p uninstall request pull owner %p upage %p\n",thread_current(),owner,upage);
  
  if ( owner == cur ) {
    // just uninstall it
    // locks are for show
    lock_acquire(&owner->page_table.lock);
    uninstall_page(owner,upage);
    uninstall_page_supplemental_info(owner,upage,kpage);
    lock_release(&owner->page_table.lock);
    return;
  }
  
  // if a thread cannot be scheduled, assume it is blocked and uninstall for the
  // thread.
  // we can't race on anything the other thread is doing including with its
  // page directory
  // this turns off interrupts
  // the ENTIRE transaction must be done with interrupts off
  // don't do something obnoxious like
  // 1. turn off interrupts, check a thread is blocked, turn on interrupts
  // 2. the thread unblocks itself, interrupts you, reads using its pde
  // 3. you interrupt it mid read, then corrupt the pde read
  //
  // also prevent the owning thread from examining its supplemental page table
  // when the supplemental page table is unsynched with the hardware page table
  lock_acquire(&owner->page_table.lock);
  bool unscheduled_and_uninstalled = thread_uninstall_page_if_unschedulable(owner,upage);
  if ( unscheduled_and_uninstalled ) {
    uninstall_page_supplemental_info(owner,upage,kpage);
  }
  lock_release(&owner->page_table.lock);
  if ( unscheduled_and_uninstalled ) {
    return;
  }
  
  uninstall_request_t u_req;
  lock_init(&u_req.cv_lk);
  cond_init(&u_req.cv);
  u_req.upage = upage;
  u_req.kpage = kpage; // the requested thread will read from kpage without a lock
  u_req.signal = -1;
  
  // printf("thread %p request owner %p with u_req %p upage %p kpage %pstart\n",
         /* thread_current(),owner,&u_req,upage,kpage); */
  
  lock_acquire(&owner->page_table.pd_lock);
  list_push_back(&owner->page_table.uninstall_requests,&u_req.lel);  
  lock_release(&owner->page_table.pd_lock);

  lock_acquire(&u_req.cv_lk);
  while ( u_req.signal == -1 ) {
    // uninstall pages in the meanwhile
    uninstall_request_push();
    cond_wait(&u_req.cv,&u_req.cv_lk);
  }
  lock_release(&u_req.cv_lk);

// printf("thread %p request owner %p with u_req %p page %p exit\n",
/* thread_current(),owner,&u_req,upage); */

  ASSERT(u_req.signal == 1); // success
}

// calling thread fulfills all uninstall requests that are pending
void uninstall_request_push(void) {
  struct thread * cur = thread_current();
  ASSERT(cur != NULL);
  struct list * reqs;
  struct list_elem * lel;
  uninstall_request_t * u_req;
  void * upage;
  void * kpage;

  // what the fuck does this pd_lock acquire do???
  lock_acquire(&cur->page_table.pd_lock);
  
  // printf("thread %p uinstall request push tagiamies 101\n",cur);
  
  reqs = &cur->page_table.uninstall_requests;
  for ( lel = list_begin(reqs); lel != list_end(reqs); lel = list_remove(lel) /*delete list*/) {
    // printf("thread %p uinstall request push tagiamies 102\n",cur);
    u_req = list_entry(lel, uninstall_request_t, lel);
    
    // begin signalling
    lock_acquire(&u_req->cv_lk);
    upage = u_req->upage;
    // you are guaranteed that the blocked thread owns the kpage lock
    // guaranteed ASSERT(lock_owned_by_thread(frame_io_pinning_lock,blocked_thread));
    // the other thread CANNOT run until you fulfill the condition below
    kpage = u_req->kpage;
    
    // printf("thread %p uinstall request %p push upage %p tagiamies 103\n",cur,u_req,upage);
    
    lock_acquire(&cur->page_table.lock);
    uninstall_page(cur,upage);
    uninstall_page_supplemental_info(cur,upage,kpage);
    lock_release(&cur->page_table.lock);
    
    // printf("thread %p uinstall request %p push upage %p tagiamies 104\n",cur,u_req,upage);
    
    // signal that the other thread can proceed
    u_req->signal = 1;
    cond_signal(&u_req->cv,&u_req->cv_lk);
    lock_release(&u_req->cv_lk);
  }
  
  
  // printf("thread %p uinstall request push tagiamies 105\n",cur);
  lock_release(&cur->page_table.pd_lock);
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
bool
load_segment (struct file *file, uint32_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable, page_source_of_data_e home) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread * t = thread_current();
  
  ASSERT(t != NULL);
  
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      // load virtual page information
      virtual_page_info_t info = { 0 };
      info.valid = 1;
      info.home = home;
      info.owner = thread_current();
      info.file = file; // why are you using naked files? this should be done with struct thread::exec_fd.
      info.writable = writable;
      info.page_read_bytes = page_read_bytes;
      info.page_zero_bytes = page_zero_bytes;
      info.file_ofs = ofs;
      set_vaddr_info(&t->page_table,upage,&info);
      //
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

      // pretend to read file
      ofs += page_read_bytes;
    }

  return true;
}
