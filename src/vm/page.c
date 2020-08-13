
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

// this should be called "set_vaddr_info..."
int set_vaddr_info(s_page_table_t * page_table,
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

void uninstall_page(void* upage) {
  struct thread * t = thread_current();
  pagedir_clear_page(t->pagedir, upage);
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
      info.elf_file_ofs = ofs;
      set_vaddr_info(&t->s_page_table,upage,&info);
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
