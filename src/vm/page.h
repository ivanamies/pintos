#ifndef VM_PAGE_H
#define VM_PAGE_H

// this header was included into thread.h because I am lazy

#include "threads/synch.h"
#include "lib/kernel/hash.h"

struct thread;
struct file;
struct uninstall_request;

typedef enum page_source_of_data {
  PAGE_SOURCE_OF_DATA_UNDEFINED, // 0
  PAGE_SOURCE_OF_DATA_ELF, // 1 .text/.rodata/.bss are R only, .data is R/W
  PAGE_SOURCE_OF_DATA_STACK, // 2
  PAGE_SOURCE_OF_DATA_MMAP, // 3
  PAGE_SOURCE_OF_DATA_SWAP_IN, // 4
  PAGE_SOURCE_OF_DATA_SWAP_OUT, // 5
  PAGE_SOURCE_OF_DATA_COUNT
} page_source_of_data_e;

 // info about where page lives, etc
typedef struct virtual_page_info {
  
  int valid;
  struct thread * owner;
  page_source_of_data_e home;
  void * frame; // frame that backs this virtual page. NULL if not backed
                // unfortunately useless. Use pagedir_get_page instead.
  
  // for elf file reads
  struct file * file;
  uint32_t page_read_bytes;
  uint32_t page_zero_bytes;
  int writable;
  uint32_t elf_file_ofs;

  // block_sector_t for reading back from swap, if in swap
  size_t swap_loc;
  
} virtual_page_info_t;

typedef struct virtual_page {

  struct hash_elem hash_elem; // hash table element
  void * addr; // virtual address
  virtual_page_info_t info;
  
} virtual_page_t;

typedef struct page_table {

  uint32_t * pagedir; // userprog/pagedir's pagedir
  struct list uninstall_requests;
  // pagedir's and uninstall_requests's locks
  // I am almost entirely sure that it isn't needed for pagedir
  struct lock pd_lock; 
  
  struct hash pages; // hash table of virtual_page_t
  struct lock lock; // lock for pages, not for pagedir
  
} page_table_t;


void init_supplemental_page_table(page_table_t * page_table);

// virtual_page_info_t will be COPIED
void* alloc_virtual_address(page_table_t * page_table, virtual_page_info_t * info);

// virtual_page_info_t has valid == 0 if failed
virtual_page_info_t get_vaddr_info(page_table_t * page_table, void * vaddr);

// returns 1 if the page already exists
// virtual_page_info_t will be COPIED
int set_vaddr_info(page_table_t * page_table, void * vaddr, virtual_page_info_t * info);

void page_process_exit(void);

// installs upage(arg1) to kpage(arg2) and if its writable(arg3)
bool install_page(void *, void *, bool);

void uninstall_page(struct thread *, void *);

void * query_page_installed(void * upage);

void install_pages(struct list * gets);

void uninstall_pages(struct list * gets);

void uninstall_request_pull(struct thread * owner, void * upage, void * kpage);

void uninstall_request_push(void);

bool load_segment (struct file *file, uint32_t ofs, uint8_t *upage,
                   uint32_t read_bytes, uint32_t zero_bytes, bool writable, page_source_of_data_e home);

#endif /* vm/page.h */
