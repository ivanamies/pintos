#include "devices/e100.h"

#include "devices/pci.h"
#include "devices/e100_hw.h"

#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#include "userprog/pagedir.h"

#include <string.h>

#define MAX_ETH_PACKET_SZ (1518)
// in uint32_t indices
#define TX_DESCS_SZ (64)
#define RX_DESCS_SZ (128)

typedef struct tx_ring {
  volatile tx_desc_t * tx_descs;
  // volatile tx_desc_t tx_descs[TX_DESCS_SZ];
  uint8_t packets[TX_DESCS_SZ][MAX_ETH_PACKET_SZ];
  uint32_t tx_descs_tail;
} tx_ring_t;

/* typedef struct rx_ring { */
/*   volatile rx_desc_t * rx_descs; */
/*   // ???? */
/*   uint8_t packets[TX_DESCS_SZ][MAX_ETH_PACKET_SZ]; */
/*   uint32_t rx_descs_tail; */
/* } rx_ring_t; */

tx_ring_t tx_ring;
// rx_ring_t rx_ring;

// this leaks
volatile uint32_t * e100_vaddr;

static void init_tx_descs(void) {
  ASSERT(sizeof(tx_desc_t) == 0x10); // HAS TO BE 16
  ASSERT(TX_DESCS_SZ == 0x40); // HAS TO BE 64

  /* void * mem1 = pci_alloc_mem2(1); */
  /* void * mem2 = pci_alloc_mem2(1); */
  /* printf("mem1 %p\n",mem1); */
  /* printf("mem2 %p\n",mem2); */
  /* tx_descs = mem2; */

  void * mem1 = palloc_get_page(PAL_ASSERT | PAL_ZERO);
  void * mem2 = palloc_get_page(PAL_ASSERT | PAL_ZERO);
  void * mem3 = palloc_get_page(PAL_ASSERT | PAL_ZERO);
  // doesn't work
  // this memory isn't mapped so you can't access it ??
  /* void * mem1 = pci_alloc_mem2(1); */
  /* void * mem2 = pci_alloc_mem2(1); */
  /* void * mem3 = pci_alloc_mem2(1); */
  printf("mem 1 2 3 %p %p %p\n",mem1,mem2,mem3);
    
  tx_ring.tx_descs_tail = 0;
  tx_ring.tx_descs = mem2;
  ASSERT( ((uintptr_t)tx_ring.tx_descs & 0xF) == 0 ); // is 16 byte aligned
  
  for ( int i = 0; i < TX_DESCS_SZ; ++i ) {
    // set bit 29 to 0b to specify legacy mode
    
    // also pretend this descriptor is done
    tx_ring.tx_descs[i].status |= 0x1;
    // ensure that packets are in kernel space
    ASSERT(is_kernel_vaddr(&tx_ring.packets[i]));
    
    tx_ring.tx_descs[i].addr = (uintptr_t)&tx_ring.packets[i];

  }

}

/* static void init_rx_descs(void) { */

/*   ASSERT(sizeof(rx_desc_t) == 0x10); // has to be 16 */
/*   ASSERT(RX_DESCS_SZ == 0x80); // has to be 128 */
/*   // ... why isn't this memory mapped? */
/*   void * mem1 = palloc_get_page(PAL_ASSERT | PAL_ZERO); */
/*   void * mem2 = palloc_get_page(PAL_ASSERT | PAL_ZERO); */
/*   void * mem3 = palloc_get_page(PAL_ASSERT | PAL_ZERO); */

/*   rx_ring.rx_descs_tail = 0; */
/*   rx_ring.rx_descs = mem2;   */
/*   ASSERT(((uintptr_t)rx_ring.rx_descs & 0xF) == 0); // is 16 byte aligned */
  
/*   /\* void *  *\/ */
/* } */

// what I checked
// - continguous PC memory
// - all the registers are right and inputs to registers are right
// - endianness
// - TDT tail is one past the last valid descriptor
// - TDT memory is 16 byte aligned
// - tx desc struct is 16
// - tx desc array size is 128 byte aligned
  

int pci_e100_attach(struct pci_func *pcif)
{
  pci_func_enable(pcif);
  printf("e100 device detected.\n");

  uint32_t phys_addr_uint = pcif->reg_base[0];
  uint32_t ofs = phys_addr_uint & 0xfffffff0 & PGMASK;

  uint32_t phys_addr_size = pcif->reg_size[0];

  // why/how does memory mapped io work again?
  e100_vaddr = pci_alloc_mem((void *)phys_addr_uint, phys_addr_size / PGSIZE);
  printf("tagiamies phys_addr_size %u\n",phys_addr_size);

  // wtf, but whatever
  e100_vaddr = (void *)((uintptr_t)e100_vaddr + ofs);
  
  // prints 0x80080783 but seriously what the fuck
  // 0x80080783 indicates "a full duplex link is up at 1000 MB/s" and other things
  printf("device status 0x%x\n",e100_vaddr[E1000_STATUS/4]);

  // general configuration
  // 1000 MB/s, full duplex
  
  init_tx_descs();

  /* const uint32_t device_control = 0b0 | */
  /*   0b1 << 0 | // full duplex mode, but this is ignored */
  /*   0b0 << 3 | // do not do link reset, do auto-negotiation */
  /*   0b1 << 5 | // auto speed detection enable */
  /*   0b1 << 6 | // set link up (?) */
  /*   0b0 << 7 | // do not invert loss of signal */
  /*   0b10 << 8 | // we do not use the SPEED bits, but set to 10b anyways */
  /*   0b0 << 11 | // do not force speed */
  /*   0b0 << 12 | // do not force duplex */
  /*   0b0 << 18 | // SDP0_DATA is an input */
  /*   0b0 << 19 | // SPD1_DATA is an input */
  /*   0b0 << 20 | // do not enable D3Cold Wakeup advertising */
  /*   0b0 << 21 | // PHY does not do power management */
  /*   0b0 << 22 | // SPD0 pin is an input */
  /*   0b0 << 23 | // SPD1 pin is an input */
  /*   0b0 << 26 | // do not reset the device */
  /*   0b0 << 27 | // let auto-negotiation deal with receive flow control */
  /*   0b0 << 28 | // let auto-negotiation deal with transmit flow control */
  /*   0b0 << 30 | // do not turn on VLAN */
  /*   0b0 << 31; // reset PHY. ... why does the manual say to set then clear this? */

  /* e100_vaddr[E1000_CTRL/4] = device_control; */
  /* // we do not use control flow, so disable it */
  /* e100_vaddr[E1000_FCAH/4]= 0x0; */
  /* e100_vaddr[E1000_FCAL/4]= 0x0; */
  /* e100_vaddr[E1000_FCT/4] = 0x0; */
  /* e100_vaddr[E1000_FCTTV/4]= 0x0; */

  // receive buffer configuration
  /* //////////////////// */
  /* // mac address 52:54:00:12:34:56:00:00 */
  /* // 52:54:00:12:34:56:00:00 - low to high -> 00d 00d 56d 34d   12d 00d 54d 52d */
  /* // -> 0x00003822  0x0C003634 */
  /* e100_vaddr[E1000_RAL/4] = 0x0C003634; */
  /* e100_vaddr[E1000_RAH/4] = 0x00003822; */

  /* // multicast table is all 0s */
  /* e100_vaddr[E1000_MTA/4] = 0x0; */
  /* // no interrupts for now */
  /* e100_vaddr[E1000_IMS/4] = 0x0; */
  /* // do not fill E1000_RDTR for now */
  
  /* e100_vaddr[E1000_RDBAL/4] = rx_ring.rx_descs; */
  /* e100_vaddr[E1000_RDBAH/4] = 0x0; */
  /* // rx descs size must be 128 aligned */
  /* ASSERT(RX_DESCS_SZ * sizeof(rx_desc_t) & (0x80-1) == 0x0); */
  /* e100_vaddr[E1000_RDLEN/4] = RX_DESCS_SZ * sizeof(rx_desc_t); */
  /* // head points to first valid descriptor */
  /* e100_vaddr[E1000_RDH/4] = 0; */
  /* // tail points to 1 past the last valid descriptor */
  /* e100_vaddr[E1000_RDH/4] = 0; */
  /* // set receive control register */
  /* uint32_t rctl = 0; */
  /* //////////////////// */
  
  // "Program the Transmit Descriptor Base Address (TDBAL/TDBAH) register(s) with the address of the region."
  // Software should insure this memory is aligned on a paragraph (16-byte) boundary. 
  e100_vaddr[E1000_TDBAL/4] = (uintptr_t)tx_ring.tx_descs;
  e100_vaddr[E1000_TDBAH/4] = 0x0;

  // Set the Transmit Descriptor Length (TDLEN) register to the size (in bytes) of the descriptor ring. This register must be 128-byte aligned.
  e100_vaddr[E1000_TDLEN/4] = TX_DESCS_SZ * sizeof(tx_desc_t);
  // ensure 128 byte aligned
  ASSERT(((TX_DESCS_SZ * sizeof(tx_desc_t)) & (0x80-1)) == 0);
  // The Transmit Descriptor Head and Tail (TDH/TDT) registers are initialized (by hardware) to 0b
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
  e100_vaddr[E1000_TCTL/4] = tctl;

  const uint32_t tipg = 10 << 0 | // decimal 10 in few bits for IPGT
    10 << 10 | // decimal 10 in 10th bits and up for IPGR1. shouldn't matter.
    10 << 20;   // decimal 10 in 10th bits and up for IPGR2. shouldn't matter.
  e100_vaddr[E1000_TIPG/4] = tipg;

  printf("begin to transmit...\n");
  uint16_t sz = 256;
  void * data = malloc(sz);
  for ( int i = 0; i < 200; ++i ) {
    uint32_t * place = data + i;
    place[i] = i;
  }
  e100_transmit(data,sz);
  printf("end transmit...\n");
  
  return 1;
}

void e100_transmit(void * data, uint16_t sz) {
  ASSERT(sz <= MAX_ETH_PACKET_SZ);
  
  volatile tx_desc_t * tx_desc = &tx_ring.tx_descs[tx_ring.tx_descs_tail];
  printf("tx_desc->status 0x%x\n",tx_desc->status);
  if ( (tx_desc->status & 0x1) == 0 ) { // check descriptor is done in DD bit of STA field
    int j = 0;
    while ( (tx_desc->status & 0x1) == 0 ) { // spin until it is done. should sleep instead.
      ++j;
    }
  }
  // clear STA field's DD bit
  tx_desc->status &= ~(1 << 0);

  // set the addr
  void * addr = (void *)&tx_ring.packets[tx_ring.tx_descs_tail];
  ASSERT((uintptr_t)tx_ring.packets[tx_ring.tx_descs_tail] == tx_desc->addr);
  memcpy(addr,data,sz);
  // set the length
  tx_desc->length = sz;
  // set the cso
  tx_desc->cso = 0x0;
  // set the cmd field
  // only send one packet, set EOP
  // ??????????????
  tx_desc->cmd = 0x0;
  /* tx_desc->cmd |= (1 << 0); */
  // set RS bit tx_desc CMD field
  // hardware will set DD bit tx_desc STA field
  tx_desc->cmd |= ( 1<< 3);
  // assert that CMD's RS bit is set to 1 so firmware will reset STA's DD bit
  ASSERT(((tx_desc->cmd >> 3)&0x1) == 1);

  //
  // status
  
  // css
  // set to 0 to indicate the first byte in the packet
  // not sure what to do with the other packets
  tx_desc->css = 0x0;
  
  // notify device to transmit and advance tx_descs_tail
  // tail points to 1 past last valid descriptor
  ++tx_ring.tx_descs_tail;
  tx_ring.tx_descs_tail &= (TX_DESCS_SZ-1); // like mod 64
  e100_vaddr[E1000_TDT/4] = tx_ring.tx_descs_tail;

  // check if descriptor has been sent
  int j = 0;
  while ( (tx_ring.tx_descs[tx_ring.tx_descs_tail-1].status & 0x1) == 0 ) {
    printf("waiting... %d\n",j);
    ++j;
  }

}
