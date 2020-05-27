#ifndef __LIB_KERNEL_CONSOLE_H
#define __LIB_KERNEL_CONSOLE_H

#include <stdio.h>

void putbuf (const char *, size_t);

void console_init (void);
void console_panic (void);
void console_print_stats (void);

#endif /* lib/kernel/console.h */
