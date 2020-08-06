
#include "vm/page.h"

#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "lib/stdio.h"

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

void init_supplemental_page_table(s_page_table_t * page_table) {

  hash_init(&page_table->pages, page_hash, page_less, NULL);
  lock_init(&page_table->lock);
  
}

void* alloc_virtual_address(s_page_table_t * page_table UNUSED, virtual_page_info_t * info UNUSED) {
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

virtual_page_info_t get_vaddr_info(s_page_table_t * page_table,
                                   void * vaddr) {
  virtual_page_info_t info = { 0 };
  virtual_page_t page;
  virtual_page_t * discovered;
  struct hash_elem * e;

  // if we don't find anything valid is 0
  info.valid = 0;
  
  page.addr = vaddr;
  
  lock_acquire(&page_table->lock);
  e = hash_find(&page_table->pages,&page.hash_elem);
  
  if ( e != NULL ) {
    discovered = hash_entry(e,virtual_page_t,hash_elem);
    info = discovered->info;
  }
  
  lock_release(&page_table->lock);
  return info;
}

int update_vaddr_info(s_page_table_t * page_table,
                      void * vaddr,
                      virtual_page_info_t * info) {
  virtual_page_t * page = (virtual_page_t *)malloc(sizeof(virtual_page_t));
  page->addr = vaddr;
  virtual_page_t * discovered;
  struct hash_elem * e;
  int err = 0;

  page->addr = vaddr;

  lock_acquire(&page_table->lock);

  e = hash_insert(&page_table->pages,&page->hash_elem);

  if ( e != NULL ) {
    discovered = hash_entry(e,virtual_page_t,hash_elem);
    discovered->info = *info;
    free(page);
  }
  else {
    page->info = *info;
  }
  
  lock_release(&page_table->lock);
  return err;
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

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool p1 = pagedir_get_page (t->pagedir, upage) == NULL;
  bool p2 = false;
  if ( p1 ) {
    p2 = pagedir_set_page (t->pagedir, upage, kpage, writable);
  }
  return p1 && p2;
}
