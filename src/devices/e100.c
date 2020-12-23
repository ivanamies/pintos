#include "devices/e100.h"

#include "devices/pci.h"
#include "devices/e100_hw.h"

#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#include "userprog/pagedir.h"

#include <string.h>

// this leaks
volatile uint32_t * e100_vaddr;
volatile tx_desc_t * tx_descs;
uint32_t tx_descs_tail;
uint32_t tx_descs_sz = 64; // in uint32_t indices

static void init_tx_descs(void) {
  tx_descs_tail = 0;
  const int num_pages_tx_descs = (tx_descs_sz * sizeof(tx_desc_t) / PGSIZE) + 1;
  // its fging not freed
  tx_descs = palloc_get_multiple(num_pages_tx_descs, PAL_ASSERT | PAL_ZERO);
  ASSERT(sizeof(tx_desc_t) == 0x10); // HAS TO BE 16
  ASSERT(tx_descs_sz == 0x40); // HAS TO BE 64
  ASSERT( ((uintptr_t)tx_descs & 0xF) == 0 );  
}

int pci_e100_attach(struct pci_func *pcif)
{
  pci_func_enable(pcif);
  printf("e100 device detected.\n");

  uint32_t phys_addr_uint = pcif->reg_base[0];
  uint32_t ofs = phys_addr_uint & 0xfffffff0 & PGMASK;

  uint32_t phys_addr_size = pcif->reg_size[0];
  
  e100_vaddr = pci_alloc_mem((void *)phys_addr_uint, phys_addr_size / PGSIZE);

  e100_vaddr = (void *)((uintptr_t)e100_vaddr + ofs);

  // prints 0x80080783 but seriously what the fuck
  // 0x80080783 indicates "a full duplex link is up at 1000 MB/s" and other things
  printf("device status 0x%x\n",e100_vaddr[E1000_STATUS/4]);

  init_tx_descs();

  // "Program the Transmit Descriptor Base Address (TDBAL/TDBAH) register(s) with the address of the region."
  // Software should insure this memory is aligned on a paragraph (16-byte) boundary. 
  // ignore TDBAH, which is for 64 bit allocs
  e100_vaddr[E1000_TDBAL/4] = (uint32_t)tx_descs;
  // Set the Transmit Descriptor Length (TDLEN) register to the size (in bytes) of the descriptor ring. This register must be 128-byte aligned.
  e100_vaddr[E1000_TDLEN/4] = tx_descs_sz * sizeof(tx_desc_t);
  //The Transmit Descriptor Head and Tail (TDH/TDT) registers are initialized (by hardware) to 0b
  // after a power-on or a software initiated Ethernet controller reset.
  // Software should write 0b to both these registers to ensure this.
  e100_vaddr[E1000_TDH/4] = 0x0;
  e100_vaddr[E1000_TDT/4] = 0x0;

  // Initialize the Transmit Control Register (TCTL) for desired operation to include the following:
  // - Set the Enable (TCTL.EN) bit to 1b for normal operation.
  // - Set the Pad Short Packets (TCTL.PSP) bit to 1b.
  // - Configure the Collision Threshold (TCTL.CT) to the desired value. Ethernet standard is 10h.
  //   This setting only has meaning in half duplex mode.
  // - Configure the Collision Distance (TCTL.COLD) to its expected value.
  //   For full duplex operation, this value should be set to 40h. 
  const uint32_t tctl = 0x1 << 1 | // TCTL.EN bit is 1b
    0x1 << 3 | // TCTL.PSP bit is 1
    0x10 << 4 | // TCTL.CT bits are 0x10. Shouldn't matter.
    0x40 << 12; // TCTL.COLD bits are 0x40.
  e100_vaddr[E1000_TCTL] = tctl;

  const uint32_t tipg = 10 << 0 | // decimal 10 in few bits for IPGT
    10 << 10 | // decimal 10 in 10th bits and up for IPGR1. shouldn't matter.
    10 << 20;   // decimal 10 in 10th bits and up for IPGR2. shouldn't matter.
  e100_vaddr[E1000_TIPG/4] = tipg;

  
  return 1;
}

void e100_transmit(void * data, uint16_t sz) {
  const size_t max_ethernet_packet_sz = 1518;
  ASSERT(sz <= max_ethernet_packet_sz);
  
  // pAcKet oPeRaTioNs
  //
  volatile tx_desc_t * tx_desc = &tx_descs[tx_descs_tail];
  if ( (tx_desc->status & 0x1) == 1 ) { // check descriptor is done in DD bit of STA field
    int j = 0;
    while ( (tx_desc->status & 0x1) == 1 ) { // spin until it is done. should sleep instead.
      ++j;
    }
  }
  // ... this is wrong. we can exit this function, packet won't transmit, user frees data,
  // then driver accesses free'd data.
  tx_desc->addr = (uintptr_t)data;
  tx_desc->length = sz;
  // set RS bit tx_desc CMD field
  // hardware will set DD bit tx_desc STA field
  tx_desc->cmd |= 1 << 3; 
  //
  
  e100_vaddr[E1000_TDT/4] = tx_descs_tail;
  ++tx_descs_tail;
  tx_descs_tail &= tx_descs_sz;
}
