#include "devices/e100.h"

#include "devices/pci.h"

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

  uint32_t phys_addr_uint = pcif->reg_base[0];
  uint32_t ofs = phys_addr_uint & 0xfffffff0 & PGMASK;

  uint32_t phys_addr_size = pcif->reg_size[0];
  
  uint32_t * vaddr = pci_alloc_mem((void *)phys_addr_uint, phys_addr_size / PGSIZE);

  vaddr = (void *)((uintptr_t)vaddr + ofs);

  // prints 0x80080783 but seriously what the fuck
  int offset = 0x00008;
  printf("device status 0x%x\n",vaddr[offset/4]);

  
  int j = 0;
  while ( true ) {
    ++j;
  }

  return 1;
}
