#ifndef __LWIP_ARCH_SYS_ARCH
#define __LWIP_ARCH_SYS_ARCH

#include "threads/synch.h"
#include "threads/thread.h"

typedef struct semaphore sys_sem_t;

// Mailbox definitions
struct mbox
{
  int size;
  struct semaphore wait;
  struct list queue;
};
typedef struct mbox sys_mbox_t;

struct mbox_entry
{
  void* msg;
  struct list_elem elem;
};

typedef tid_t sys_thread_t;

// pintos provides no mutexes, so use lwIP's binary semaphores
#define LWIP_COMPAT_MUTEX 1

#define SYS_ARCH_PROTECT(x)      intr_disable ()
#define SYS_ARCH_UNPROTECT(x)    intr_enable ()
#define SYS_ARCH_DECL_PROTECT(x)

#endif
