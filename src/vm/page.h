#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/synch.h"
#include "lib/kernel/hash.h"

 // info about where page lives, etc
typedef struct virtual_page_info {
  int valid;
  int aux;
  
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

#endif /* vm/page.h */
