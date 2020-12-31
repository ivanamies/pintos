#ifndef DEVICES_E100_H
#define DEVICES_E100_H

#include "devices/pci.h"

#define E100_VENDORID 0x8086
// ... but section 5.2 in the e100 manual says its device id is 0x100e?
// #define E100_QEMU_DEVICEID 0x1209
// #define E100_BOCHS_DEVICEID 0x100e
#define E100_QEMU_DEVICEID 0x100e

typedef struct tx_desc {
  uint64_t addr;
  uint16_t length;
  uint8_t cso;
  uint8_t cmd;
  uint8_t status; // last 4 bits are RSV
  uint8_t css;
  uint16_t special;
} tx_desc_t;

int pci_e100_attach(struct pci_func *pcif);
void e100_transmit(void * data, uint16_t sz);

#endif // DEVICES_E100_H
