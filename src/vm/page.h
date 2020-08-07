#ifndef VM_PAGE_H
#define VM_PAGE_H

// this header was included into thread.h because I am lazy

#include "threads/synch.h"
#include "lib/kernel/hash.h"

struct thread;
struct file;

typedef enum page_source_of_data {
  PAGE_SOURCE_OF_DATA_UNDEFINED,
  PAGE_SOURCE_OF_DATA_ELF, // .text/.rodata/.bss are R only, .data is R/W
  PAGE_SOURCE_OF_DATA_STACK,
  PAGE_SOURCE_OF_DATA_MMAP,
  PAGE_SOURCE_OF_DATA_COUNT
} page_source_of_data_e;

 // info about where page lives, etc
typedef struct virtual_page_info {
  
  int valid;
  struct thread * owner;
  page_source_of_data_e home;
  void * frame; // frame that backs this virtual page. NULL if not backed
  
  // for elf file reads
  struct file * file;
  uint32_t page_read_bytes;
  uint32_t page_zero_bytes;
  int writable;
  uint32_t elf_file_ofs;
    
} virtual_page_info_t;

typedef struct virtual_page {

  struct hash_elem hash_elem; // hash table element
  void * addr; // virtual address
  virtual_page_info_t info;
  
} virtual_page_t;

typedef struct supplemental_page_table {

  struct hash pages; // hash table of virtual_page_t
  struct lock lock; // intra-process lock on pages and last virtual address
  //
  // some linked list of freed virtual addresses?
  // if the list is empty get one from last_virtual address?
  // do if oom is a problem
  
} s_page_table_t;


void init_supplemental_page_table(s_page_table_t * page_table);

// virtual_page_info_t will be COPIED
void* alloc_virtual_address(s_page_table_t * page_table, virtual_page_info_t * info);

// virtual_page_info_t has valid == 0 if failed
virtual_page_info_t get_vaddr_info(s_page_table_t * page_table, void * vaddr);

// returns error code 1 if failed
// virtual_page_info_t will be COPIED
int update_vaddr_info(s_page_table_t * page_table, void * vaddr, virtual_page_info_t * info);

// installs upage(arg1) to kpage(arg2) and if its writable(arg3)
bool install_page(void *, void *, bool);

void uninstall_page(void *);

#endif /* vm/page.h */
