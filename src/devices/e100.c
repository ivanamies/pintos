#include "devices/e100.h"

#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#include "userprog/pagedir.h"

#include <string.h>

static bool copy_of_install_page (uint32_t * pagedir, void *upage, void *kpage, bool writable)
{
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page_no_assert (pagedir, upage) == NULL
          && pagedir_set_page_no_assert (pagedir, upage, kpage, writable));
}

int pci_e100_attach(struct pci_func *pcif)
{
  pci_func_enable(pcif);
  printf("e100 device detected.\n");
  /* void *p = pcif->reg_base[0]; */
  /* printf("base %u %p size %d\n",pcif->reg_base[0],p,pcif->reg_size[0]); */

  /* void * on_device_mem = p; */
  /* printf("on device mem %p\n",p); */

  /* /\* { *\/ */
  /* /\*   int j = 0; *\/ */
  /* /\*   while ( true ) { *\/ */
  /* /\*     ++j; *\/ */
  /* /\*   } *\/ */
  /* /\* } *\/ */
  
  /* const bool writable = true; */

  /* uint32_t * pagedir = pagedir_create(); */
  /* pagedir_activate(pagedir); */
  /* volatile uint32_t * upage = PHYS_BASE - 100*PGSIZE; */
  /* copy_of_install_page(pagedir,upage,on_device_mem,true); */
  /* // copy_of_install_page(pagedir,on_device_mem,upage,true); */

  /* int offset = 0x00008; */
  /* // device status is wrong + also crashes */
  /* printf("device status %u\n",upage[offset/4]); */

  /* /\* pagedir_clear_page_no_assert(pagedir, on_device_mem); *\/ */
    
  /* pagedir_activate(NULL); */
  
  /* /\* pagedir_destroy(pagedir); *\/ */

  /* { */
  /*   int j = 0; */
  /*   while ( true ) { */
  /*     ++j; */
  /*   } */
  /* } */
  
  return 1;
}
