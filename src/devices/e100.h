#ifndef DEVICES_E100_H
#define DEVICES_E100_H

#include "devices/pci.h"

#define E100_VENDORID 0x8086
// ... but section 5.2 in the e100 manual says its device id is 0x100e?
// #define E100_QEMU_DEVICEID 0x1209
// #define E100_BOCHS_DEVICEID 0x100e
#define E100_QEMU_DEVICEID 0x100e

int pci_e100_attach(struct pci_func *pcif);

#endif // DEVICES_E100_H
